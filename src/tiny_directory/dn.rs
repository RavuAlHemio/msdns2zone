#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Rdn {
    pub key: String,
    pub value: Vec<u8>,
}
impl Rdn {
    pub fn new(key: String, value: Vec<u8>) -> Self {
        Self {
            key,
            value,
        }
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
    for piece in pieces {
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
                if [' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\'].binary_search(&c).is_ok() {
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

fn split_at_first_unescaped_equals<'a>(tokens: &[Token<'a>]) -> Option<(Vec<Token<'a>>, Vec<Token<'a>>)> {
    let mut front_pieces = Vec::new();
    for (i, token) in tokens.into_iter().enumerate() {
        match token {
            Token::EscapedByte(b) => {
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
                        for rest_piece in tokens.into_iter().skip(i) {
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
    use super::dn_to_rdns;

    #[test]
    fn test_dn_to_rdns() {
        let rdns = dn_to_rdns("").unwrap();
        assert_eq!(rdns.len(), 0);

        let rdns = dn_to_rdns("C=QQ").unwrap();
        assert_eq!(rdns.len(), 1);
        assert_eq!(rdns[0].key, "C");
        assert_eq!(rdns[0].value, b"QQ");
    }
}
