pub mod dn;


use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use unicase::UniCase;

use crate::directory::{Directory, DirectoryEntry};
use crate::tiny_directory::dn::{dn_to_rdns, MaybeUniCaseString, Rdn};


pub type AttributeBag = BTreeMap<UniCase<String>, BTreeSet<Vec<u8>>>;


#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Object {
    pub attributes: AttributeBag,
    pub children: BTreeMap<Rdn, Object>,
}
impl Object {
    pub fn descendants_with_rdn(&self, key: &UniCase<String>, value: MaybeUniCaseString) -> Vec<(String, &Object)> {
        let mut ret = Vec::new();
        let mut queue = Vec::new();
        queue.push((String::new(), self));

        while let Some((item_dn, item)) = queue.pop() {
            for (child_rdn, child) in &item.children {
                let child_dn = if item_dn.len() > 0 {
                    format!("{},{}", child_rdn, item_dn)
                } else {
                    format!("{}", child_rdn)
                };
                if &child_rdn.key == key && child_rdn.value == value {
                    ret.push((child_dn.clone(), child));
                }
                queue.push((child_dn, child));
            }
        }

        ret
    }
}


pub fn directorify(attribute_bags: &[AttributeBag]) -> Object {
    let mut root_object = Object::default();
    let unicase_dn = UniCase::new("dn".to_owned());

    for attribute_bag in attribute_bags {
        let dn_value = match attribute_bag.get(&unicase_dn) {
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
            if key == &unicase_dn {
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


pub struct DirectoryWrapper<'a> {
    pub object: &'a Object,
}
impl<'a> From<&'a Object> for DirectoryWrapper<'a> {
    fn from(value: &'a Object) -> Self { Self { object: value } }
}
#[async_trait]
impl<'a> Directory for DirectoryWrapper<'a> {
    async fn find_children(&mut self, base_dn: &str, object_class: &str, attribute_names: &[UniCase<String>]) -> Option<Vec<DirectoryEntry>> {
        let base_dn_rdns = dn_to_rdns(base_dn)?;
        let object_class_unicase = UniCase::new(object_class);
        let object_class_name_unicase = UniCase::new("objectClass".to_owned());

        // descend through the directory tree
        let mut current_node = self.object;
        for rdn in base_dn_rdns.iter().rev() {
            println!("looking for {:?} among {:?}", rdn, current_node.children.keys());
            let requested_child = match current_node.children.get(rdn) {
                Some(rc) => rc,
                None => {
                    if let Some(rdn_value_text) = rdn.value.try_as_str() {
                        eprintln!("requested child {}={} not found", rdn.key, rdn_value_text);
                    } else {
                        eprintln!("requested child {}={:?}", rdn.key, rdn.value);
                    }
                    return None;
                },
            };
            current_node = requested_child;
        }

        let mut results = Vec::new();
        for (rdn, child) in &current_node.children {
            let Some(child_object_classes_bin) = child.attributes.get(&object_class_name_unicase)
                else { continue };
            let child_object_classes_str: Vec<UniCase<String>> = child_object_classes_bin.iter()
                .filter_map(|cocb| std::str::from_utf8(cocb).ok())
                .map(|s| UniCase::new(s.to_owned()))
                .collect();
            if !child_object_classes_str.iter().any(|cocs| cocs == &object_class_unicase) {
                // this child is not relevant for us
                continue;
            }

            let mut attributes = child.attributes.clone();
            attributes.retain(|k, _v| attribute_names.contains(k));

            let child_dn = format!("{},{}", rdn, base_dn);
            let child_entry = DirectoryEntry {
                dn: UniCase::new(child_dn),
                attributes,
            };
            results.push(child_entry);
        }

        Some(results)
    }
}
