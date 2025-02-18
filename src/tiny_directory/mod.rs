pub mod dn;


use std::collections::{BTreeMap, BTreeSet};

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
