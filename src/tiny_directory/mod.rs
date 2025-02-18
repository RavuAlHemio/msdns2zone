pub mod dn;


use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;

use crate::directory::{Directory, DirectoryEntry};
use crate::tiny_directory::dn::{dn_to_rdns, Rdn};


pub type AttributeBag = BTreeMap<String, BTreeSet<Vec<u8>>>;


#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Object {
    pub attributes: AttributeBag,
    pub children: BTreeMap<Rdn, Object>,
}


pub fn directorify(attribute_bags: &[AttributeBag]) -> Object {
    let mut root_object = Object::default();

    for attribute_bag in attribute_bags {
        let dn_value = match attribute_bag.get("dn") {
            None => {
                eprintln!("skipping attribute bag without \"dn\" attribute: {:?}", attribute_bag);
                continue;
            },
            Some(values) => {
                if values.len() != 1 {
                    eprintln!("attribute bag has {} values for \"dn\" attribute: {:?}", values.len(), values);
                    continue;
                }
                values.iter()
                    .nth(0).unwrap()
                    .clone()
            },
        };
        let dn_string = match String::from_utf8(dn_value) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("\"dn\" attribute value not decodable as UTF-8: {:?}", e.as_bytes());
                continue;
            },
        };
        let dn_rdns = match dn_to_rdns(&dn_string) {
            Some(rs) => rs,
            None => {
                eprintln!("failed to parse DN {:?}", dn_string);
                continue;
            },
        };

        // find or create DN
        let mut cur_object = &mut root_object;
        for rdn in dn_rdns.iter().rev() {
            cur_object = cur_object
                .children
                .entry(rdn.clone())
                .or_insert_with(|| Object::default());
        }

        // merge attributes
        for (key, values) in attribute_bag {
            if key == "dn" {
                continue;
            }

            let existing_values = cur_object
                .attributes
                .entry(key.clone())
                .or_insert_with(|| BTreeSet::new());
            for value in values {
                existing_values.insert(value.clone());
            }
        }
    }

    root_object
}


#[async_trait]
impl Directory for Object {
    async fn find_children<S: AsRef<str> + Sync>(&mut self, base_dn: &str, object_class: &str, attribute_names: &[S]) -> Option<Vec<DirectoryEntry>> {
        let base_dn_rdns = dn_to_rdns(base_dn)?;
        let object_class_lower = object_class.to_lowercase();

        // descend through the directory tree
        let mut current_node = self;
        for rdn in &base_dn_rdns {
            let requested_child = match current_node.children.get_mut(rdn) {
                Some(rc) => rc,
                None => {
                    if let Ok(rdn_value_text) = std::str::from_utf8(&rdn.value) {
                        eprintln!("requested child {}={} not found", rdn.key, rdn_value_text);
                    } else {
                        eprintln!("requested child {}={:?}", rdn.key, rdn.value);
                    }
                    return None;
                },
            };
            current_node = requested_child;
        }

        for (rdn, child) in &current_node.children {
            let Some(child_object_classes_bin) = child.attributes.get("objectClass")
                else { continue };
            let child_object_classes_str: Vec<&str> = child_object_classes_bin.iter()
                .filter_map(|cocb| std::str::from_utf8(cocb).ok())
                .collect();
            if !child_object_classes_str.iter().any(|cocs| cocs.to_lowercase() == object_class_lower) {
                // this child is not relevant for us
                continue;
            }

            let child_dn = format!("{},{}", rdn, base_dn);
            todo!();
        }

        todo!();
    }
}
