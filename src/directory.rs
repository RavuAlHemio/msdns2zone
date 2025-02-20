use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use unicase::UniCase;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectoryEntry {
    pub dn: UniCase<String>,
    pub attributes: BTreeMap<UniCase<String>, BTreeSet<Vec<u8>>>,
}


#[async_trait]
pub trait Directory {
    async fn find_children(&mut self, base_dn: &str, object_class: &str, attribute_names: &[UniCase<String>]) -> Option<Vec<DirectoryEntry>>;
}
