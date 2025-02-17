use std::collections::{BTreeMap, BTreeSet};


pub type AttributeBag = BTreeMap<String, BTreeSet<Vec<u8>>>;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Rdn {
    pub key: String,
    pub value: Vec<u8>,
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Object {
    pub attributes: AttributeBag,
    pub children: BTreeMap<Rdn, Object>,
}

fn dn_to_rdns(dn: &str) -> Option<Vec<Rdn>> {
    // RFC4514
    if dn.len() == 0 {
        return Some(Vec::with_capacity(0));
    }

    // tokenize to abstract away escapes
    enum Token<'a> {
        UnescapedSlice(&'a str),
        EscapedByte(u8),
    }

    fn tokenize(dn: &str) -> Option<Vec<Token>> {
        //let tokens = Vec::new();

        let mut current_start = 0;
        while let Some(next_backslash) = dn[current_start..].find('\\').map(|i| i + current_start) {
            //let next_backslash
        }

        todo!();
    }

    todo!();
}
