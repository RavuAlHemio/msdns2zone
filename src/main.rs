mod args;
mod enc;
mod ldif;
mod record;
mod tiny_directory;


use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};

use crate::args::{Credentials, Mode};
use crate::enc::{ByteWriteAdapter, MsDecodable, SupportsEverythingEncoder, ZoneEncodable};
use crate::ldif::parse_ldif;
use crate::record::DnsRecord;
use crate::tiny_directory::directorify;


fn get_required_single_string_value(entry: &SearchEntry, key: &str) -> String {
    if entry.bin_attrs.contains_key(key) {
        panic!("{} on {} is a binary value?!", key, entry.dn);
    }
    let values = match entry.attrs.get(key) {
        Some(v) => v,
        None => panic!("{} is not set on {}", key, entry.dn),
    };
    let value = match values.get(0) {
        Some(v) => v,
        None => panic!("{} on {} has no values?!", key, entry.dn),
    };
    value.clone()
}


async fn get_default_naming_context(ldap: &mut Ldap) -> String {
    let mut naming_context = None;
    let (rootdse_entries, _) = ldap.search(
        "",
        Scope::Base,
        "(objectClass=*)",
        vec!["defaultNamingContext"],
    )
        .await.expect("failed to query RootDSE on LDAP server")
        .success().expect("querying RootDSE on LDAP server failed");
    for rootdse_raw_entry in rootdse_entries {
        let rootdse_entry = SearchEntry::construct(rootdse_raw_entry);
        let this_naming_context = get_required_single_string_value(
            &rootdse_entry, "defaultNamingContext",
        );
        naming_context = Some(this_naming_context);
    }
    naming_context
        .expect("rootDSE is missing defaultNamingContext")
}


async fn dump_zones(ldap: &mut Ldap, subdir_name: &str, dns_config_dn: &str) {
    // enumerate zones
    let zone_result = ldap.search(
        dns_config_dn,
        Scope::OneLevel,
        "(objectClass=dnsZone)",
        vec!["name"],
    ).await;
    let zone_response = match zone_result {
        Ok(zr) => zr,
        Err(e) => {
            eprintln!("skipping {:?}: failed to query zones: {}", dns_config_dn, e);
            return;
        },
    };
    let (zone_entries, _) = match zone_response.success() {
        Ok(zrs) => zrs,
        Err(e) => {
            eprintln!("skipping {:?}: zone query failed: {}", dns_config_dn, e);
            return;
        },
    };
    let mut zones = Vec::with_capacity(zone_entries.len());
    for zone_raw_entry in zone_entries {
        let zone_entry = SearchEntry::construct(zone_raw_entry);
        let zone_name = get_required_single_string_value(
            &zone_entry, "name",
        );
        zones.push((zone_name, zone_entry.dn));
    }

    for (zone_name, zone_dn) in zones {
        let mut zone_path = PathBuf::from(subdir_name);
        zone_path.push(format!("{}.dns", zone_name));
        dump_zone(ldap, &zone_path, &zone_dn).await;
    }
}


async fn dump_zone(ldap: &mut Ldap, file_name: &Path, zone_dn: &str) {
    // enumerate entries
    let entries_result = ldap.search(
        zone_dn,
        Scope::OneLevel,
        "(objectClass=dnsNode)",
        vec!["name", "dnsRecord"],
    ).await;
    let entries_response = match entries_result {
        Ok(er) => er,
        Err(e) => {
            eprintln!("skipping {:?}: failed to query entries: {}", zone_dn, e);
            return;
        },
    };
    let (entries_entries, _) = match entries_response.success() {
        Ok(ees) => ees,
        Err(e) => {
            eprintln!("skipping {:?}: entries query failed: {}", zone_dn, e);
            return;
        },
    };

    let file_name_parent = file_name.parent().unwrap();
    std::fs::create_dir_all(file_name_parent)
        .expect("failed to create directory for zone file");
    let mut file = File::create(file_name)
        .expect("failed to open zone file");

    for entry_raw_entry in entries_entries {
        let entry_entry = SearchEntry::construct(entry_raw_entry);
        let entry_name = get_required_single_string_value(
            &entry_entry, "name",
        );
        let Some(entry_records) = entry_entry.bin_attrs.get("dnsRecord")
            else { continue };
        for record in entry_records {
            let dns_record = DnsRecord::try_decode(record)
                .expect("failed to decode a DNS record");
            if dns_record.data.record_type().to_base_type() == 0x0000 {
                continue;
            }
            write!(file, "{} ", entry_name).unwrap();
            dns_record.try_encode(&SupportsEverythingEncoder, &mut ByteWriteAdapter(&mut file))
                .expect("failed to write out a DNS record");
            writeln!(file).unwrap();
        }
    }
}

async fn run() {
    let mode = Mode::parse();

    match mode {
        Mode::Query(opts) => {
            // connect to LDAP
            let (conn, mut ldap) = LdapConnAsync::new(&opts.ldap_uri)
                .await.expect("failed to connect to LDAP server");
            ldap3::drive!(conn);

            // obtain credentials
            let (bind_dn, password) = if let Some(bind_dn) = opts.bind_dn {
                let password = rpassword::prompt_password("LDAP password: ")
                    .expect("failed to read LDAP password");
                (bind_dn, password)
            } else if let Some(credentials_file) = opts.credentials_file {
                let credentials_string = std::fs::read_to_string(credentials_file)
                    .expect("failed to read credentials file");
                let credentials: Credentials = toml::from_str(&credentials_string)
                    .expect("failed to parse credentials file");
                (credentials.bind_dn, credentials.password)
            } else {
                unreachable!();
            };

            // bind
            ldap.simple_bind(&bind_dn, &password)
                .await.expect("failed to login (bind) on LDAP server");

            let naming_context = get_default_naming_context(&mut ldap).await;

            let subdirs_and_dns_objects = [
                ("system", format!("CN=MicrosoftDNS,CN=System,{}", naming_context)),
                ("forest", format!("CN=MicrosoftDNS,DC=ForestDnsZones,{}", naming_context)),
                ("domain", format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", naming_context)),
            ];
            for (subdir_name, dns_config_dn) in &subdirs_and_dns_objects {
                dump_zones(&mut ldap, subdir_name, dns_config_dn).await;
            }
        },
        Mode::Decode(opts) => {
            let ldif_string = std::fs::read_to_string(&opts.ldif_path)
                .expect("failed to load LDIF file");
            let entries = parse_ldif(&ldif_string);
            let directory = directorify(&entries);
            println!("{:#?}", directory);
            // still a work in progress :-)
        },
    }
}


#[tokio::main]
async fn main() {
    run().await
}
