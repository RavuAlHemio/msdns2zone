pub mod dn;


use std::collections::{BTreeMap, BTreeSet};

use crate::tiny_directory::dn::Rdn;


pub type AttributeBag = BTreeMap<String, BTreeSet<Vec<u8>>>;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Object {
    pub attributes: AttributeBag,
    pub children: BTreeMap<Rdn, Object>,
}
