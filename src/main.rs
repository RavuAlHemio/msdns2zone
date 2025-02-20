mod args;
mod directory;
mod enc;
mod ldap;
mod ldif;
mod record;
mod tiny_directory;


use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use clap::Parser;
use ldap::LdapConnection;
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use unicase::UniCase;

use crate::args::{Credentials, Mode};
use crate::directory::{Directory, DirectoryEntry};
use crate::enc::{ByteWriteAdapter, MsDecodable, SupportsEverythingEncoder, ZoneEncodable};
use crate::ldif::parse_ldif;
use crate::record::DnsRecord;
use crate::tiny_directory::{directorify, DirectoryWrapper};
use crate::tiny_directory::dn::{dn_to_rdns, MaybeUniCaseString};


macro_rules! define_attribute {
    ($name:ident, $value:expr) => {
        static $name: LazyLock<UniCase<String>> = LazyLock::new(|| UniCase::new(String::from(
            $value
        )));
    }
}

macro_rules! define_attribute_list {
    ($name:ident $(, $values:expr)+ $(,)?) => {
        static $name: LazyLock<Vec<UniCase<String>>> = LazyLock::new(|| vec![
            $(UniCase::new($values.to_owned()),)+
        ]);
    }
}

macro_rules! define_mucs {
    ($name:ident, $value:expr) => {
        static $name: LazyLock<MaybeUniCaseString> = LazyLock::new(|| MaybeUniCaseString::from(
            $value
        ));
    }
}

define_attribute!(ATTRIBUTE_CN, "cn");
define_attribute!(ATTRIBUTE_DC, "dc");
define_attribute!(ATTRIBUTE_DNS_RECORD, "dnsRecord");
define_attribute!(ATTRIBUTE_NAME, "name");
define_attribute_list!(ATTRIBUTES_NAME, "name");
define_attribute_list!(ATTRIBUTES_NAME_DNSRECORD, "name", "dnsRecord");
define_mucs!(MUCS_DOMAIN_DNS_ZONES, "DomainDnsZones");
define_mucs!(MUCS_FOREST_DNS_ZONES, "ForestDnsZones");
define_mucs!(MUCS_MICROSOFTDNS, "MicrosoftDNS");
define_mucs!(MUCS_SYSTEM, "System");


fn get_required_single_string_value(entry: &DirectoryEntry, key: &UniCase<String>) -> String {
    let values = match entry.attributes.get(key) {
        Some(v) => v,
        None => panic!("{} is not set on {}", key, entry.dn),
    };
    let value_bytes = match values.first() {
        Some(v) => v,
        None => panic!("{} on {} has no values?!", key, entry.dn),
    };
    let value = match String::from_utf8(value_bytes.clone()) {
        Ok(v) => v,
        Err(_) => panic!("{} on {} is binary?! {:?}", key, entry.dn, value_bytes),
    };
    value
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
        if rootdse_entry.bin_attrs.contains_key("defaultNamingContext") {
            panic!("defaultNamingContext on RootDSE is binary?!");
        }
        let dnc = rootdse_entry.attrs
            .get("defaultNamingContext").expect("defaultNamingContext not found")
            .get(0)
            .expect("defaultNamingContext has no values");
        naming_context = Some(dnc.clone());
    }
    naming_context
        .expect("rootDSE is missing defaultNamingContext")
}


async fn dump_zones<D: Directory>(directory: &mut D, subdir_name: &str, dns_config_dn: &str) {
    // enumerate zones
    let Some(zone_entries) = directory.find_children(
        dns_config_dn,
        "dnsZone",
        &ATTRIBUTES_NAME,
    ).await else { return };
    let mut zones = Vec::with_capacity(zone_entries.len());
    for zone_entry in zone_entries {
        let zone_name = get_required_single_string_value(
            &zone_entry,
            &ATTRIBUTE_NAME,
        );
        zones.push((zone_name, zone_entry.dn));
    }

    for (zone_name, zone_dn) in zones {
        let mut zone_path = PathBuf::from(subdir_name);
        zone_path.push(format!("{}.dns", zone_name));
        dump_zone(directory, &zone_path, &zone_dn).await;
    }
}


async fn dump_zone<D: Directory>(directory: &mut D, file_name: &Path, zone_dn: &str) {
    // enumerate entries
    let Some(entries_entries) = directory.find_children(
        zone_dn,
        "dnsNode",
        &ATTRIBUTES_NAME_DNSRECORD,
    ).await else { return };
    let file_name_parent = file_name.parent().unwrap();
    std::fs::create_dir_all(file_name_parent)
        .expect("failed to create directory for zone file");
    let mut file = File::create(file_name)
        .expect("failed to open zone file");

    for entry_entry in entries_entries {
        let entry_name = get_required_single_string_value(
            &entry_entry, &ATTRIBUTE_NAME,
        );
        let Some(entry_records) = entry_entry.attributes
            .get(&ATTRIBUTE_DNS_RECORD)
            else { continue };
        for record in entry_records {
            let dns_record = DnsRecord::try_decode(record)
                .expect("failed to decode a DNS record");
            if dns_record.data.record_type().to_base_type() == 0x0000 {
                // tombstone
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

            let mut ldap_connection = LdapConnection::new(ldap);

            for (subdir_name, dns_config_dn) in &subdirs_and_dns_objects {
                dump_zones(&mut ldap_connection, subdir_name, dns_config_dn).await;
            }
        },
        Mode::Decode(opts) => {
            let ldif_string = std::fs::read_to_string(&opts.ldif_path)
                .expect("failed to load LDIF file");
            let entries = parse_ldif(&ldif_string);
            let directory = directorify(&entries);

            let msdns_objects = directory.descendants_with_rdn(
                &ATTRIBUTE_CN,
                MUCS_MICROSOFTDNS.clone(),
            );
            for (dn, _) in msdns_objects {
                let Some(rdns) = dn_to_rdns(&dn)
                    else { continue };
                if rdns.len() < 2 {
                    continue;
                }

                let mut dw = DirectoryWrapper::from(&directory);
                if &rdns[1].key == &*ATTRIBUTE_CN && &rdns[1].value == &*MUCS_SYSTEM {
                    dump_zones(&mut dw, "system", &dn).await;
                } else if &rdns[1].key == &*ATTRIBUTE_DC && &rdns[1].value == &*MUCS_DOMAIN_DNS_ZONES {
                    dump_zones(&mut dw, "domain", &dn).await;
                } else if &rdns[1].key == &*ATTRIBUTE_DC && &rdns[1].value == &*MUCS_FOREST_DNS_ZONES {
                    dump_zones(&mut dw, "forest", &dn).await;
                } else {
                    eprintln!("warning: cannot identify tree location of {:?}; skipping", dn);
                }
            }
        },
    }
}


#[tokio::main]
async fn main() {
    run().await
}
