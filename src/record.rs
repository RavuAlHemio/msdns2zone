use std::borrow::Cow;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DnsRecord {
    // data_length: u16,
    // type: u16,
    // version: u8 == 0x05
    rank: u8,
    // flags: u16 == 0x0000
    serial: u32,
    ttl: Duration,
    // reserved: u32 == 0
    timestamp: u32, // hours since 1601-01-01 00:00:00 UTC
    data: RecordData,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum RecordType {
    // Zero = 0, consider as other
    Ipv4Address = 1,
    NameServer = 2,
    MailDestination = 3,
    MailForwarder = 4,
    CanonicalName = 5,
    StartOfAuthority = 6,
    Mailbox = 7,
    MailGroup = 8,
    MailRename = 9,
    // Null = 10, consider as other
    WellKnownService = 11,
    Pointer = 12,
    HostInformation = 13,
    MailboxInformation = 14,
    MailExchanger = 15,
    Text = 16,
    ResponsiblePerson = 17,
    AfsDatabase = 18,
    X25Psdn = 19,
    Isdn = 20,
    RouteThrough = 21,
    // 22 and 23 not officially supported
    Signature = 24,
    Key = 25,
    // 26 and 27 not officially supported
    Ipv6Address = 28,
    // 29 (Location/LOC) is listed but its structure is unknown
    NextDomain = 30,
    // 31 and 32 not officially supported
    ServerSelection = 33,
    AtmAddress = 34,
    NamingAuthorityPointer = 35,
    // 36, 37 and 38 not officially supported
    DomainRedirectName = 39,
    // 40, 41 and 42 not officially supported
    DelegationSigner = 43,
    // 44 and 45 not officially supported
    ResourceRecordSignature = 46,
    AuthenticatedDenial = 47,
    PublicKey = 48,
    DhcpClientIdentifier = 49,
    AuthenticatedDenial3 = 50,
    AuthenticatedDenial3Parameters = 51,
    DaneTlsa = 52,
    Other(u16),
}
impl RecordType {
    fn to_name(&self) -> Cow<'static, str> {
        fn cb(s: &'static str) -> Cow<'static, str> { Cow::Borrowed(s) }

        match self {
            Self::Ipv4Address => cb("A"),
            Self::NameServer => cb("NS"),
            Self::MailDestination => cb("ND"),
            Self::MailForwarder => cb("MF"),
            Self::CanonicalName => cb("CNAME"),
            Self::StartOfAuthority => cb("SOA"),
            Self::Mailbox => cb("MB"),
            Self::MailGroup => cb("MG"),
            Self::MailRename => cb("MR"),
            Self::WellKnownService => cb("WKS"),
            Self::Pointer => cb("PTR"),
            Self::HostInformation => cb("HINFO"),
            Self::MailboxInformation => cb("MINFO"),
            Self::MailExchanger => cb("MX"),
            Self::Text => cb("TXT"),
            Self::ResponsiblePerson => cb("RP"),
            Self::AfsDatabase => cb("AFSDB"),
            Self::X25Psdn => cb("X25"),
            Self::Isdn => cb("ISDN"),
            Self::RouteThrough => cb("RT"),
            Self::Signature => cb("SIG"),
            Self::Key => cb("KEY"),
            Self::Ipv6Address => cb("AAAA"),
            Self::NextDomain => cb("NXT"),
            Self::ServerSelection => cb("SRV"),
            Self::AtmAddress => cb("ATMA"),
            Self::NamingAuthorityPointer => cb("NAPTR"),
            Self::DomainRedirectName => cb("DNAME"),
            Self::DelegationSigner => cb("DS"),
            Self::ResourceRecordSignature => cb("RRSIG"),
            Self::AuthenticatedDenial => cb("NSEC"),
            Self::PublicKey => cb("DNSKEY"),
            Self::DhcpClientIdentifier => cb("DHCID"),
            Self::AuthenticatedDenial3 => cb("NSEC3"),
            Self::AuthenticatedDenial3Parameters => cb("NSEC3PARAM"),
            Self::DaneTlsa => cb("TLSA"),
            Self::Other(kind) => {
                // magical RFC3597 format
                Cow::Owned(format!("TYPE{}", kind))
            },
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RecordData {
    Ipv4Address(Ipv4AddressData),
    NameServer(NodeNameData),
    MailDestination(NodeNameData),
    MailForwarder(NodeNameData),
    CanonicalName(NodeNameData),
    StartOfAuthority(StartOfAuthorityData),
    Mailbox(NodeNameData),
    MailGroup(NodeNameData),
    MailRename(NodeNameData),
    WellKnownService(WellKnownServiceData),
    Pointer(NodeNameData),
    HostInformation(StringData),
    MailboxInformation(MailboxPairData),
    MailExchanger(NameAndPreferenceData),
    Text(StringData),
    ResponsiblePerson(MailboxPairData),
    AfsDatabase(NameAndPreferenceData),
    X25Psdn(StringData),
    Isdn(StringData),
    RouteThrough(NameAndPreferenceData),
    Signature(SignatureData),
    Key(KeyData),
    Ipv6Address(Ipv6AddressData),
    NextDomain(NextDomainData),
    ServerSelection(ServerSelectionData),
    AtmAddress(AtmAddressData),
    NamingAuthorityPointer(NamingAuthorityPointerData),
    DomainRedirectName(NodeNameData),
    DelegationSigner(DelegationSignerData),
    ResourceRecordSignature(ResourceRecordSignatureData),
    AuthenticatedDenial(AuthenticatedDenialData),
    PublicKey(PublicKeyData),
    DhcpClientIdentifier(DhcpClientIdentifierData),
    AuthenticatedDenial3(AuthenticatedDenial3Data),
    AuthenticatedDenial3Parameters(AuthenticatedDenial3ParametersData),
    DaneTlsa(DaneTlsaData),
    Other { kind: u16, data: Vec<u8> },
}
impl RecordData {
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::Ipv4Address(_) => RecordType::Ipv4Address,
            Self::NameServer(_) => RecordType::NameServer,
            Self::MailDestination(_) => RecordType::MailDestination,
            Self::MailForwarder(_) => RecordType::MailForwarder,
            Self::CanonicalName(_) => RecordType::CanonicalName,
            Self::StartOfAuthority(_) => RecordType::StartOfAuthority,
            Self::Mailbox(_) => RecordType::Mailbox,
            Self::MailGroup(_) => RecordType::MailGroup,
            Self::MailRename(_) => RecordType::MailRename,
            Self::WellKnownService(_) => RecordType::WellKnownService,
            Self::Pointer(_) => RecordType::Pointer,
            Self::HostInformation(_) => RecordType::HostInformation,
            Self::MailboxInformation(_) => RecordType::MailboxInformation,
            Self::MailExchanger(_) => RecordType::MailExchanger,
            Self::Text(_) => RecordType::Text,
            Self::ResponsiblePerson(_) => RecordType::ResponsiblePerson,
            Self::AfsDatabase(_) => RecordType::AfsDatabase,
            Self::X25Psdn(_) => RecordType::X25Psdn,
            Self::Isdn(_) => RecordType::Isdn,
            Self::RouteThrough(_) => RecordType::RouteThrough,
            Self::Signature(_) => RecordType::Signature,
            Self::Key(_) => RecordType::Key,
            Self::Ipv6Address(_) => RecordType::Ipv6Address,
            Self::NextDomain(_) => RecordType::NextDomain,
            Self::ServerSelection(_) => RecordType::ServerSelection,
            Self::AtmAddress(_) => RecordType::AtmAddress,
            Self::NamingAuthorityPointer(_) => RecordType::NamingAuthorityPointer,
            Self::DomainRedirectName(_) => RecordType::DomainRedirectName,
            Self::DelegationSigner(_) => RecordType::DelegationSigner,
            Self::ResourceRecordSignature(_) => RecordType::ResourceRecordSignature,
            Self::AuthenticatedDenial(_) => RecordType::AuthenticatedDenial,
            Self::PublicKey(_) => RecordType::PublicKey,
            Self::DhcpClientIdentifier(_) => RecordType::DhcpClientIdentifier,
            Self::AuthenticatedDenial3(_) => RecordType::AuthenticatedDenial3,
            Self::AuthenticatedDenial3Parameters(_) => RecordType::AuthenticatedDenial3Parameters,
            Self::DaneTlsa(_) => RecordType::DaneTlsa,
            Self::Other { kind, .. } => RecordType::Other(*kind),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WriteError {
    Fmt(fmt::Error),
    Unencodable,
}
impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Fmt(e) => write!(f, "formatting error: {}", e),
            Self::Unencodable => write!(f, "value cannot be encoded"),
        }
    }
}
impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fmt(e) => Some(e),
            Self::Unencodable => None,
        }
    }
}
impl From<fmt::Error> for WriteError {
    fn from(value: fmt::Error) -> Self { Self::Fmt(value) }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AtmAddressData {
    pub format: u8,
    pub data: Vec<u8>,
}
impl AtmAddressData {
    pub fn try_write<W: fmt::Write>(&self, mut writer: W) -> Result<(), WriteError> {
        match self.format {
            0 => {
                // AESA; hex dump
                for b in &self.data {
                    write!(writer, "{:02x}", b)?;
                }
                Ok(())
            },
            1 => {
                // E.164; phone number with a + prefix
                // check if the data is valid
                for &b in &self.data {
                    if b < b'0' || b > b'9' {
                        return Err(WriteError::Unencodable);
                    }
                }
                write!(writer, "+")?;
                for &b in &self.data {
                    let c = char::from_u32(b.into()).unwrap();
                    write!(writer, "{}", c)?;
                }
                Ok(())
            },
            _ => Err(WriteError::Unencodable),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatedDenial3Data {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    // salt length: u8,
    // hash length: u8,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub bitmap: Vec<u8>, // RFC5155 § 3.2.1 encoding: (block: u8, length: u8, bitmap: [u8; length])+
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatedDenial3ParametersData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatedDenialData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DaneTlsaData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DelegationSignerData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DhcpClientIdentifierData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4AddressData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv6AddressData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MailboxPairData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NameAndPreferenceData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamingAuthorityPointerData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NextDomainData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeNameData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicKeyData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceRecordSignatureData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServerSelectionData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StartOfAuthorityData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StringData {
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WellKnownServiceData {
}
