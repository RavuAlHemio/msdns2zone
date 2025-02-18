use std::collections::{BTreeMap, BTreeSet};
use std::str::pattern::Pattern;


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
    #[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
    enum Token<'a> {
        UnescapedSlice(&'a str),
        EscapedByte(u8),
    }

    fn tokenize(dn: &str) -> Option<Vec<Token>> {
        let mut tokens = Vec::new();

        let mut current_start = 0;
        loop {
            let next_backslash = match find_from(dn, '\\', current_start) {
                Some(nb) => nb,
                None => {
                    let rest_slice = &dn[current_start..];
                    if rest_slice.len() > 0 {
                        tokens.push(Token::UnescapedSlice(rest_slice));
                    }
                    break;
                },
            };

            // eat the part until the backslash
            let eaten = &dn[current_start..next_backslash];
            tokens.push(Token::UnescapedSlice(eaten));

            // what follows the backslash?
            match dn[next_backslash+1..].chars().nth(0) {
                None => {
                    // backslash at the end is invalid
                    return None;
                },
                Some(c) => {
                    if [' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\'].binary_search(&c).is_some() {
                        tokens.push(Token::EscapedByte((c as u32).try_into().unwrap()));

                        // continue after that escaped character
                        current_start = next_backslash + 2;
                    } else if c.is_ascii_hexdigit() {
                        // okay, do we have another hex digit?
                        let c2 = match dn[next_backslash+2..].chars().nth(0) {
                            Some(c2) => c2,
                            None => {
                                // DN ends with a string like "\9" or "\F"
                                return None;
                            },
                        };
                        if !c2.is_ascii_hexdigit() {
                            // a string like "\A%"
                            return None;
                        }
                        debug_assert!(c.len_utf8() == 1 && c2.len_utf8() == 1);
                        let hex_slice = &dn[next_backslash+1..next_backslash+3];
                        let hex_value = u8::from_str_radix(hex_slice, 16).unwrap();
                        tokens.push(Token::EscapedByte(hex_value));

                        // continue after the second hex digit
                        current_start = next_backslash + 3;
                    }
                },
            }
        }

        Some(tokens)
    }

    let tokens = tokenize(dn)?;

    fn split_at_unescaped_commas(tokens: &[Token]) -> Vec<Vec<Token>> {
        let mut pieces = Vec::new();
        let mut current_piece = Vec::new();
        for token in tokens {
            match token {
                Token::EscapedByte(b) => {
                    current_piece.push(token.clone());
                },
                Token::UnescapedSlice(s) => {
                    if s.len() == 0 {
                        continue;
                    }

                    match s.find(',') {
                        None => {
                            current_piece.push(token.clone());
                        },
                        Some(comma_index) => {
                            let before = &s[..comma_index];
                            let after = &s[comma_index+1..];
                            if before.len() > 0 {
                                current_piece.push(Token::UnescapedSlice(before));
                            }
                            let push_me = std::mem::replace(&mut current_piece, Vec::new());
                            pieces.push(push_me);
                            if after.len() > 0 {
                                current_piece.push(Token::UnescapedSlice(after));
                            }
                        },
                    }
                },
            }
        }
        if current_piece.len() > 0 {
            pieces.push(current_piece);
        }
        pieces
    }

    let pieces = split_at_unescaped_commas(&tokens);

    todo!();
}

fn find_from<P: Pattern>(haystack: &'h str, needle: P, offset: usize) -> Option<usize> {
    haystack[offset..]
        .find(needle)
        .map(|i| i + offset)
}
