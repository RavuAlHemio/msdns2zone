# msdns2zone

Extracts DNS records from an Active Directory domain and writes them into zone files as specified in
[RFC1035 § 5](https://datatracker.ietf.org/doc/html/rfc1035#section-5).

The data can be extracted by either of the following:

* `query` mode: querying a domain controller via LDAP

* `decode` mode: parsing a dump of the relevant sections in LDIF format (as output e.g. by
  OpenLDAP's [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch))

The tool creates three subdirectories (named `system`, `forest` and `domain`), corresponding to the
standard three DNS partitions in Active Directory: `CN=System,{domain}`,
`DC=ForestDnsZones,{domain}` and `DC=DomainDnsZones,{domain}`, and fills them with zone files, each
representing one of the zones in the given partition.

This tool was originally written to extract DNS records from Samba, since Samba does not export a
`NETLOGON.DNS`-style zone file for including domain controller data in a pre-existing DNS
environment. It is puzzling that the open-source reimplementation is less open to sharing
information with external systems than the closed-source original implementation. (Loading a plugin
into BIND9 to obtain zone data from a Samba server seems like overkill.)

## LDAP credentials

The client always performs a simple LDAP bind. There are two ways to provide credentials in `query`
mode:

* Provide the bind DN on the command line (`-D`/`--bind-dn`). The password is then queried via
  standard input.

* Provide the bind DN and password through a credentials file, specifying its path on the command
  line (`-c`/`--credentials-file`). The credentials file has the following format:

```toml
bind_dn = "DOMAIN\\user"
password = "hunter2"
```

Using SSL to connect to the server is strongly recommended.

## Pre-generating an LDIF file

When using `ldapsearch` to generate LDIF files, the following combination of options seems useful:

```bash
ldapsearch \
    -H 'ldaps://dc.example.com/' \
    -x \
    -W \
    -D 'EXAMPLE\Administrator' \
    -b "CN=MicrosoftDNS,CN=System,DC=example,DC=com" \
    -s sub \
    "(objectClass=*)" \
    "*" "+" \
    > example-system.txt
```

The results of all three partitions can be queried as follows:

```bash
ad_dns_search()
{
    partition="$1"
    outfile="$2"

    ldapsearch \
        -H 'ldaps://dc.example.com/' \
        -x \
        -W \
        -D 'EXAMPLE\Administrator' \
        -b "$partition" \
        -s sub \
        "(objectClass=*)" \
        "*" "+" \
        > "$outfile"
}
ad_dns_search "CN=MicrosoftDNS,CN=System,DC=example,DC=com" "example-system.txt"
ad_dns_search "CN=MicrosoftDNS,DC=ForestDnsZones,DC=example,DC=com" "example-forest.txt"
ad_dns_search "CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com" "example-domain.txt"
cat "example-system.txt" "example-forest.txt" "example-domain.txt" > "example-all.txt"
```
