use std::fmt;

use unicase::UniCase;


const ESCAPABLE_CHARACTERS_SORTED: [char; 10] = [' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\'];
const ALWAYS_ESCAPE_BYTES_SORTED: [u8; 7] = [b'"', b'+', b',', b';', b'<', b'>', b'\\'];


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Rdn {
    pub key: UniCase<String>,
    pub value: Vec<u8>,
}
impl Rdn {
    pub fn new(key: String, value: Vec<u8>) -> Self {
        Self {
            key: UniCase::new(key),
            value,
        }
    }
}
impl fmt::Display for Rdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=", self.key)?;
        for (i, &b) in self.value.iter().enumerate() {
            let self_escape =
                ALWAYS_ESCAPE_BYTES_SORTED.binary_search(&b).is_ok()
                || (i == 0 && (b == b' ' || b == b'#'))
                || (i == self.value.len() - 1 && b == b' ')
            ;
            if self_escape {
                write!(f, "\\{}", char::from_u32(b as u32).unwrap())?;
            } else if b >= 0x20 && b <= 0x7E {
                write!(f, "{}", char::from_u32(b as u32).unwrap())?;
            } else {
                write!(f, "\\{:02X}", b)?;
            }
        }
        Ok(())
    }
}

pub fn dn_to_rdns(dn: &str) -> Option<Vec<Rdn>> {
    // RFC4514

    if dn.len() == 0 {
        return Some(Vec::with_capacity(0));
    }

    let tokens = tokenize(dn)?;
    let pieces = split_at_unescaped_commas(&tokens);

    let mut rdns = Vec::with_capacity(pieces.len());
    for piece in &pieces {
        let (key_tokens, value_tokens) = split_at_first_unescaped_equals(&piece)?;
        let key_bytes = tokens_to_bytes(&key_tokens);
        let rear_bytes = tokens_to_bytes(&value_tokens);

        let key_string = String::from_utf8(key_bytes).ok()?;
        rdns.push(Rdn::new(key_string, rear_bytes));
    }

    Some(rdns)
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
enum Token<'a> {
    UnescapedSlice(&'a str),
    EscapedByte(u8),
}

/// Tokenizes the given DN string.
///
/// Used to abstract away escapes.
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
                if ESCAPABLE_CHARACTERS_SORTED.binary_search(&c).is_ok() {
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
                } else {
                    // some other character -- not allowed
                    return None;
                }
            },
        }
    }

    Some(tokens)
}


fn find_from(haystack: &str, needle: char, offset: usize) -> Option<usize> {
    haystack[offset..]
        .find(needle)
        .map(|i| i + offset)
}

fn split_at_unescaped_commas<'a>(tokens: &[Token<'a>]) -> Vec<Vec<Token<'a>>> {
    let mut pieces = Vec::new();
    let mut current_piece = Vec::new();
    for token in tokens {
        match token {
            Token::EscapedByte(_) => {
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

fn split_at_first_unescaped_equals<'a>(tokens: &[Token<'a>]) -> Option<(Vec<Token<'a>>, Vec<Token<'a>>)> {
    let mut front_pieces = Vec::new();
    for (i, token) in tokens.into_iter().enumerate() {
        match token {
            Token::EscapedByte(_) => {
                front_pieces.push(token.clone());
            },
            Token::UnescapedSlice(s) => {
                if s.len() == 0 {
                    continue;
                }

                match s.find('=') {
                    None => {
                        front_pieces.push(token.clone());
                    },
                    Some(equals_index) => {
                        let before = &s[..equals_index];
                        let after = &s[equals_index+1..];

                        if before.len() > 0 {
                            front_pieces.push(Token::UnescapedSlice(before));
                        }

                        // handle the rest
                        let mut rear_pieces = Vec::new();
                        if after.len() > 0 {
                            rear_pieces.push(Token::UnescapedSlice(after));
                        }
                        for rest_piece in tokens.into_iter().skip(i + 1) {
                            rear_pieces.push(rest_piece.clone());
                        }

                        return Some((front_pieces, rear_pieces));
                    },
                }
            },
        }
    }

    // no unescaped equals found
    None
}

fn tokens_to_bytes(tokens: &[Token]) -> Vec<u8> {
    let mut ret = Vec::new();
    for token in tokens {
        match token {
            Token::EscapedByte(b) => ret.push(*b),
            Token::UnescapedSlice(slice) => ret.extend_from_slice(slice.as_bytes()),
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use unicase::UniCase;
    use super::dn_to_rdns;

    fn uc(s: &str) -> UniCase<&str> {
        UniCase::new(s)
    }

    #[test]
    fn test_dn_to_rdns() {
        let rdns = dn_to_rdns("").unwrap();
        assert_eq!(rdns.len(), 0);

        let rdns = dn_to_rdns("C=QQ").unwrap();
        assert_eq!(rdns.len(), 1);
        assert_eq!(rdns[0].key, uc("C"));
        assert_eq!(rdns[0].value, b"QQ");

        let rdns = dn_to_rdns("O=Dewey LLC,C=QQ").unwrap();
        assert_eq!(rdns.len(), 2);
        assert_eq!(rdns[0].key, uc("O"));
        assert_eq!(rdns[0].value, b"Dewey LLC");
        assert_eq!(rdns[1].key, uc("C"));
        assert_eq!(rdns[1].value, b"QQ");

        let rdns = dn_to_rdns("O=Dewey\\, Cheatham and Howe LLC,C=QQ").unwrap();
        assert_eq!(rdns.len(), 2);
        assert_eq!(rdns[0].key, uc("O"));
        assert_eq!(rdns[0].value, b"Dewey, Cheatham and Howe LLC");
        assert_eq!(rdns[1].key, uc("C"));
        assert_eq!(rdns[1].value, b"QQ");

        let rdns = dn_to_rdns("givenName=Ond\\C5\\99ej,SN=Ho\\C5\\A1ek,C=QQ").unwrap();
        assert_eq!(rdns.len(), 3);
        assert_eq!(rdns[0].key, uc("givenName"));
        assert_eq!(rdns[0].value, "Ond\u{0159}ej".as_bytes());
        assert_eq!(rdns[1].key, uc("SN"));
        assert_eq!(rdns[1].value, "Ho\u{0161}ek".as_bytes());
        assert_eq!(rdns[2].key, uc("C"));
        assert_eq!(rdns[2].value, b"QQ");

        let rdns = dn_to_rdns("one=two=three").unwrap();
        assert_eq!(rdns.len(), 1);
        assert_eq!(rdns[0].key, uc("one"));
        assert_eq!(rdns[0].value, b"two=three");

        let rdns = dn_to_rdns("one=,two=").unwrap();
        assert_eq!(rdns.len(), 2);
        assert_eq!(rdns[0].key, uc("one"));
        assert_eq!(rdns[0].value, b"");
        assert_eq!(rdns[1].key, uc("two"));
        assert_eq!(rdns[1].value, b"");

        let rdns = dn_to_rdns("one=\\\"").unwrap();
        assert_eq!(rdns.len(), 1);
        assert_eq!(rdns[0].key, uc("one"));
        assert_eq!(rdns[0].value, b"\"");

        assert_eq!(dn_to_rdns("one=\\"), None);
        assert_eq!(dn_to_rdns("one=\\Z"), None);
        assert_eq!(dn_to_rdns("one=\\A"), None);
        assert_eq!(dn_to_rdns("one=\\AZ"), None);
    }
}
