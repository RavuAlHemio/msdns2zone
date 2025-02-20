use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
pub enum Mode {
    #[command(about = "Query an LDAP server for Microsoft DNS entries")]
    Query(QueryOpts),

    #[command(about = "Decode an LDIF export from an LDAP server with Microsoft DNS entries")]
    Decode(DecodeOpts),
}

#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
pub struct QueryOpts {
    /// The URI to the LDAP server
    #[arg(
        short = 'H', long,
        help = "The URI of the LDAP server",
        long_help = concat!(
            "The URI of the LDAP server. Conforms to a format such as \"ldap://ldap.example.com\",\n",
            "\"ldaps://ldap.example.com\" (for LDAP over TLS) or \"ldap://ldap.example.com:3269\"\n",
            "(to use an alternative port).",
        ),
    )]
    pub ldap_uri: String,

    #[arg(
        short = 'D', long, group = "auth", required = true,
        help = "DN to use to bind (log in) to the LDAP server",
        long_help = concat!(
            "DN (distinguished name) to use to bind (log in) to the LDAP server.\n",
            "\n",
            "A bind DN generally looks like \"CN=Administrator,CN=Users,DC=example,DC=com\", but\n",
            "an LDAP server may also accept a different syntax. For example, Active Directory\n",
            "also accepts the Windows NT format \"EXAMPLE\\Administrator\".\n",
            "\n",
            "When this option is used, the password is read from the terminal. It cannot be used\n",
            "simultaneously with -c/--credentials-file.",
        ),
    )]
    pub bind_dn: Option<String>,

    #[arg(
        short = 'c', long, group = "auth", required = true,
        help = "Path to a TOML file containing credentials for binding (logging in) to the LDAP server",
        long_help = concat!(
            "Path to a TOML file containing credentials for binding (logging in) to the LDAP server.\n",
            "\n",
            "The file has the following format:\n",
            "\n",
            "bind_dn = \"CN=Administrator,CN=Users,DC=example,DC=com\"\n",
            "password = \"hunter2\"\n",
            "\n",
            "This option cannot be used simultaneously with -D/--bind-dn.",
        ),
    )]
    pub credentials_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Credentials {
    pub bind_dn: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, Hash, Ord, Parser, PartialEq, PartialOrd)]
pub struct DecodeOpts {
    #[arg(
        short = 'l', long,
        help = "Path to an LDIF file containing DNS data",
        long_help = concat!(
            "Path to an LDIF file containing DNS data.\n",
            "\n",
            "The LDIF format is specified in RFC 2849. It is generated by tools such as ldapsearch\n",
            "from the OpenLDAP suite. The Microsoft DNS entries are loaded from the LDIF file and\n",
            "output in zone format (RFC 1035 Section 5).",
        ),
    )]
    pub ldif_path: PathBuf,
}
