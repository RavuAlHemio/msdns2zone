use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectoryEntry {
    pub dn: String,
    pub attributes: BTreeMap<String, BTreeSet<Vec<u8>>>,
}


#[async_trait]
pub trait Directory {
    async fn find_children<S: AsRef<str> + Sync>(&mut self, base_dn: &str, object_class: &str, attribute_names: &[S]) -> Option<Vec<DirectoryEntry>>;
}
