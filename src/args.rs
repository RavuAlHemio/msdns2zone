use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
pub enum Mode {
    /// Query an LDAP server for Microsoft DNS entries.
    Query(QueryOpts),

    /// Decode an LDIF export from an LDAP server with Microsoft DNS entries.
    Decode(DecodeOpts),
}

#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
pub struct QueryOpts {
    #[arg(short = 'H', long)]
    pub ldap_uri: String,

    #[arg(short = 'D', long, group = "auth", required = true)]
    pub bind_dn: Option<String>,

    #[arg(short = 'c', long, group = "auth", required = true)]
    pub credentials_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Credentials {
    pub bind_dn: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
pub struct DecodeOpts {
    #[arg(short = 'l', long)]
    pub ldif_path: PathBuf,
}
