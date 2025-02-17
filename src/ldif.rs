use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;

use crate::tiny_directory::AttributeBag;


fn normalize_newlines<'a>(ldif: &'a str) -> Cow<'a, str> {
    if ldif.contains("\r\n") {
        Cow::Owned(ldif.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(ldif)
    }
}

fn join_continuations<'a>(ldif: &'a str) -> Cow<'a, str> {
    if ldif.contains("\n ") {
        Cow::Owned(ldif.replace("\n ", ""))
    } else {
        Cow::Borrowed(ldif)
    }
}

fn strip_comments<'a>(ldif: &'a str) -> Cow<'a, str> {
    if ldif.starts_with('#') || ldif.contains("\n#") {
        let mut uncommented = String::with_capacity(ldif.len());
        let mut first_line = true;
        for ln in ldif.split('\n') {
            if ln.starts_with('#') {
                // skip
            }

            if first_line {
                first_line = false;
            } else {
                uncommented.push('\n');
            }
            uncommented.push_str(ln);
        }
        Cow::Owned(uncommented)
    } else {
        Cow::Borrowed(ldif)
    }
}

fn compress_newlines<'a>(ldif: &'a str) -> Cow<'a, str> {
    if ldif.contains("\n\n\n") {
        let mut compressed = ldif.replace("\n\n\n", "\n\n");
        while compressed.contains("\n\n\n") {
            compressed = compressed.replace("\n\n\n", "\n\n");
        }
        Cow::Owned(compressed)
    } else {
        Cow::Borrowed(ldif)
    }
}

fn cut_str_to_max(s: &str, mut max_bytes: usize) -> &str {
    while !s.is_char_boundary(max_bytes) {
        max_bytes -= 1;
    }
    &s[0..max_bytes]
}


fn parse_ldif(ldif: &str) -> Vec<AttributeBag> {
    // normalize LDIF
    let normalized = normalize_newlines(ldif);
    let joined = join_continuations(&*normalized);
    let stripped = strip_comments(&*joined);
    let compressed = compress_newlines(&*stripped);

    // each record is now separated by "\n\n"
    let mut records: Vec<AttributeBag> = Vec::new();
    for record in compressed.split("\n\n") {
        let mut key_to_values = AttributeBag::new();

        // and each attribute in the record by "\n"
        for attribute in record.split("\n") {
            // split at the attribute name
            let Some((key, rest)) = attribute.split_once(':') else {
                eprintln!("skipping LDIF line missing colon: {:?}", record);
                continue;
            };

            // how many colons?
            let value = if rest == ":" {
                // empty value
                Vec::with_capacity(0)
            } else if let Some(mut base64_str) = rest.strip_prefix(":: ") {
                // base64
                // strip off additional spaces
                base64_str = base64_str.trim_matches(' ');

                // decode
                let decoded = match base64::engine::general_purpose::STANDARD.decode(base64_str) {
                    Ok(bs) => bs,
                    Err(_) => {
                        if base64_str.len() > 64 {
                            eprintln!("invalid base64 value {:?}[...]", cut_str_to_max(base64_str, 64));
                        } else {
                            eprintln!("invalid base64 value {:?}", base64_str);
                        }
                        continue;
                    },
                };
                decoded
            } else if let Some(mut plain_str) = rest.strip_prefix(": ") {
                // plain
                // strip off additional spaces
                plain_str = plain_str.trim_matches(' ');

                plain_str.as_bytes().to_vec()
            } else {
                eprintln!("skipping LDIF line with unexpected delimiter: {:?}", record);
                continue;
            };

            key_to_values
                .entry(key.to_owned())
                .or_insert_with(|| BTreeSet::new())
                .insert(value);
        }

        if !key_to_values.contains_key("dn") {
            eprintln!("skipping LDIF record missing required \"dn\" pseudo-attribute: {:?}", key_to_values);
        }

        records.push(key_to_values);
    }

    records
}
