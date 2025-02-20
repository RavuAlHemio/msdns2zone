use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use ldap3::{Scope, SearchEntry};
use unicase::UniCase;

use crate::directory::{Directory, DirectoryEntry};


#[derive(Debug)]
pub struct LdapConnection {
    ldap: ldap3::Ldap,
}
impl LdapConnection {
    pub fn new(ldap: ldap3::Ldap) -> Self { Self { ldap } }
}
#[async_trait]
impl Directory for LdapConnection {
    async fn find_children(&mut self, base_dn: &str, object_class: &str, attribute_names: &[UniCase<String>]) -> Option<Vec<DirectoryEntry>> {
        let filter = format!("(objectClass={})", object_class);
        let ldap_attribute_names: Vec<&str> = attribute_names
            .into_iter()
            .map(|n| n.as_ref())
            .collect();
        let ldap_result = self.ldap.search(
            base_dn,
            Scope::OneLevel,
            &filter,
            ldap_attribute_names,
        ).await;
        let ldap_response = match ldap_result {
            Ok(lr) => lr,
            Err(e) => {
                eprintln!("skipping {:?}: failed to query children of class {:?}: {}", base_dn, object_class, e);
                return None;
            },
        };
        let (ldap_entries, _) = match ldap_response.success() {
            Ok(lrs) => lrs,
            Err(e) => {
                eprintln!("skipping {:?}: query for children of class {:?} failed: {}", base_dn, object_class, e);
                return None;
            },
        };
        let mut entries = Vec::with_capacity(ldap_entries.len());
        for ldap_entry in ldap_entries {
            let search_entry = SearchEntry::construct(ldap_entry);
            let mut attributes = BTreeMap::new();
            for (key, string_values) in search_entry.attrs {
                let all_values = attributes
                    .entry(UniCase::new(key))
                    .or_insert_with(|| BTreeSet::new());
                for string_value in string_values {
                    all_values.insert(string_value.into_bytes());
                }
            }
            for (key, bytes_values) in search_entry.bin_attrs {
                let all_values = attributes
                    .entry(UniCase::new(key))
                    .or_insert_with(|| BTreeSet::new());
                for bytes_value in bytes_values {
                    all_values.insert(bytes_value);
                }
            }
            let entry = DirectoryEntry {
                dn: UniCase::new(search_entry.dn),
                attributes,
            };
            entries.push(entry);
        }
        Some(entries)
    }
}
