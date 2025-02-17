use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use base64::engine::Engine;
use from_to_repr::from_to_other;

use crate::enc::{self, WireEncodable};


fn u16_msb(value: u16) -> u8 { ((value >> 8) & 0xFF) as u8 }
fn u16_lsb(value: u16) -> u8 { ((value >> 0) & 0xFF) as u8 }

fn u32_msb(value: u32) -> u8 { ((value >> 24) & 0xFF) as u8 }
fn u32_2sb(value: u32) -> u8 { ((value >> 16) & 0xFF) as u8 }
fn u32_3sb(value: u32) -> u8 { ((value >>  8) & 0xFF) as u8 }
fn u32_lsb(value: u32) -> u8 { ((value >>  0) & 0xFF) as u8 }


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DnsRecord {
    // data_length: u16,
    // type: u16,
    // version: u8 == 0x05
    pub rank: u8,
    // flags: u16 == 0x0000
    pub serial: u32,
    pub ttl: Duration,
    pub timestamp: u32, // hours since 1601-01-01 00:00:00 UTC
    pub reserved: u32,
    pub data: RecordData,
}
impl enc::MsDecodable for DnsRecord {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 24 {
            return Err(enc::Error::WrongLength);
        }
        let data_length: usize = u16::from_le_bytes(slice[0..2].try_into().unwrap()).into();
        if slice.len() != 24 + data_length {
            return Err(enc::Error::WrongLength);
        }
        let kind_u16 = u16::from_le_bytes(slice[2..4].try_into().unwrap());
        let version = slice[4];
        if version != 0x05 {
            return Err(enc::Error::InvalidData);
        }
        let rank = slice[5];
        let flags = u16::from_le_bytes(slice[6..8].try_into().unwrap());
        if flags != 0x0000 {
            return Err(enc::Error::InvalidData);
        }
        let serial = u32::from_le_bytes(slice[8..12].try_into().unwrap());
        let ttl_seconds = u32::from_be_bytes(slice[12..16].try_into().unwrap());
        let timestamp = u32::from_le_bytes(slice[16..20].try_into().unwrap());
        let reserved = u32::from_le_bytes(slice[20..24].try_into().unwrap());

        let ttl = Duration::from_secs(ttl_seconds.into());

        let data_slice = &slice[24..];
        let kind = RecordType::from_base_type(kind_u16);

        let data = match kind {
            RecordType::Ipv4Address => {
                let data = Ipv4AddressData::try_decode(data_slice)?;
                RecordData::Ipv4Address(data)
            },
            RecordType::NameServer|RecordType::MailDestination|RecordType::MailForwarder
                    |RecordType::CanonicalName|RecordType::Mailbox|RecordType::MailGroup
                    |RecordType::MailRename|RecordType::Pointer|RecordType::DomainRedirectName => {
                let data = NodeNameData::try_decode(data_slice)?;
                match kind {
                    RecordType::NameServer => RecordData::NameServer(data),
                    RecordType::MailDestination => RecordData::MailDestination(data),
                    RecordType::MailForwarder => RecordData::MailForwarder(data),
                    RecordType::CanonicalName => RecordData::CanonicalName(data),
                    RecordType::Mailbox => RecordData::Mailbox(data),
                    RecordType::MailGroup => RecordData::MailGroup(data),
                    RecordType::MailRename => RecordData::MailRename(data),
                    RecordType::Pointer => RecordData::Pointer(data),
                    RecordType::DomainRedirectName => RecordData::DomainRedirectName(data),
                    _ => unreachable!(),
                }
            },
            RecordType::StartOfAuthority => {
                let data = StartOfAuthorityData::try_decode(data_slice)?;
                RecordData::StartOfAuthority(data)
            },
            RecordType::WellKnownService => {
                let data = WellKnownServiceData::try_decode(data_slice)?;
                RecordData::WellKnownService(data)
            },
            RecordType::HostInformation|RecordType::Text|RecordType::X25Psdn|RecordType::Isdn => {
                let data = StringData::try_decode(data_slice)?;
                match kind {
                    RecordType::HostInformation => RecordData::HostInformation(data),
                    RecordType::Text => RecordData::Text(data),
                    RecordType::X25Psdn => RecordData::X25Psdn(data),
                    RecordType::Isdn => RecordData::Isdn(data),
                    _ => unreachable!(),
                }
            },
            RecordType::MailboxInformation|RecordType::ResponsiblePerson => {
                let data = MailboxPairData::try_decode(data_slice)?;
                match kind {
                    RecordType::MailboxInformation => RecordData::MailboxInformation(data),
                    RecordType::ResponsiblePerson => RecordData::ResponsiblePerson(data),
                    _ => unreachable!(),
                }
            },
            RecordType::MailExchanger|RecordType::AfsDatabase|RecordType::RouteThrough => {
                let data = NameAndPreferenceData::try_decode(data_slice)?;
                match kind {
                    RecordType::MailExchanger => RecordData::MailExchanger(data),
                    RecordType::AfsDatabase => RecordData::AfsDatabase(data),
                    RecordType::RouteThrough => RecordData::RouteThrough(data),
                    _ => unreachable!(),
                }
            },
            RecordType::Signature|RecordType::ResourceRecordSignature => {
                let data = SignatureData::try_decode(data_slice)?;
                match kind {
                    RecordType::Signature => RecordData::Signature(data),
                    RecordType::ResourceRecordSignature => RecordData::ResourceRecordSignature(data),
                    _ => unreachable!(),
                }
            },
            RecordType::Key|RecordType::PublicKey => {
                let data = PublicKeyData::try_decode(data_slice)?;
                match kind {
                    RecordType::Key => RecordData::Key(data),
                    RecordType::PublicKey => RecordData::PublicKey(data),
                    _ => unreachable!(),
                }
            },
            RecordType::Ipv6Address => {
                let data = Ipv6AddressData::try_decode(data_slice)?;
                RecordData::Ipv6Address(data)
            },
            RecordType::NextDomain => {
                let data = NextDomainData::try_decode(data_slice)?;
                RecordData::NextDomain(data)
            },
            RecordType::ServerSelection => {
                let data = ServerSelectionData::try_decode(data_slice)?;
                RecordData::ServerSelection(data)
            },
            RecordType::AtmAddress => {
                let data = AtmAddressData::try_decode(data_slice)?;
                RecordData::AtmAddress(data)
            },
            RecordType::NamingAuthorityPointer => {
                let data = NamingAuthorityPointerData::try_decode(data_slice)?;
                RecordData::NamingAuthorityPointer(data)
            },
            RecordType::DelegationSigner => {
                let data = DelegationSignerData::try_decode(data_slice)?;
                RecordData::DelegationSigner(data)
            },
            RecordType::AuthenticatedDenial => {
                let data = AuthenticatedDenialData::try_decode(data_slice)?;
                RecordData::AuthenticatedDenial(data)
            },
            RecordType::DhcpClientIdentifier => {
                let data = DhcpClientIdentifierData::try_decode(data_slice)?;
                RecordData::DhcpClientIdentifier(data)
            },
            RecordType::AuthenticatedDenial3 => {
                let data = AuthenticatedDenial3Data::try_decode(data_slice)?;
                RecordData::AuthenticatedDenial3(data)
            },
            RecordType::AuthenticatedDenial3Parameters => {
                let data = AuthenticatedDenial3ParametersData::try_decode(data_slice)?;
                RecordData::AuthenticatedDenial3Parameters(data)
            },
            RecordType::DaneTlsa => {
                let data = DaneTlsaData::try_decode(data_slice)?;
                RecordData::DaneTlsa(data)
            },
            RecordType::Other(kind) => RecordData::Other { kind, data: data_slice.to_vec() },
        };

        Ok(Self {
            rank,
            serial,
            ttl,
            timestamp,
            reserved,
            data,
        })
    }
}
impl enc::ZoneEncodable for DnsRecord {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} IN ", self.ttl.as_secs())?;
        if encoder.knows_record_type(self.data.record_type().to_base_type()) {
            let mut data_string = String::new();
            enc::ZoneEncodable::try_encode(&self.data, encoder, &mut data_string)?;
            write!(writer, "{}", data_string)?;
        } else {
            let mut buf = Vec::new();
            enc::WireEncodable::try_encode(&self.data, &mut buf)?;
            write!(writer, "TYPE{} \\# {}", self.data.record_type().to_base_type(), buf.len())?;
            if buf.len() > 0 {
                write!(writer, " ")?;
                for b in buf {
                    write!(writer, "{:02x}", b)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
#[from_to_other(base_type = u16, derive_compare = "as_int")]
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

    fn is_known(&self) -> bool {
        match self {
            Self::Other(_) => false,
            _ => true,
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
    Key(PublicKeyData),
    Ipv6Address(Ipv6AddressData),
    NextDomain(NextDomainData),
    ServerSelection(ServerSelectionData),
    AtmAddress(AtmAddressData),
    NamingAuthorityPointer(NamingAuthorityPointerData),
    DomainRedirectName(NodeNameData),
    DelegationSigner(DelegationSignerData),
    ResourceRecordSignature(SignatureData),
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
impl enc::ZoneEncodable for RecordData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        if encoder.knows_record_type(self.record_type().to_base_type()) {
            write!(writer, "{} ", self.record_type().to_name())?;
            match self {
                Self::Ipv4Address(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::NameServer(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::MailDestination(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::MailForwarder(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::CanonicalName(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::StartOfAuthority(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Mailbox(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::MailGroup(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::MailRename(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::WellKnownService(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Pointer(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::HostInformation(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::MailboxInformation(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::MailExchanger(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Text(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::ResponsiblePerson(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::AfsDatabase(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::X25Psdn(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Isdn(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::RouteThrough(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Signature(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Key(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Ipv6Address(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::NextDomain(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::ServerSelection(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::AtmAddress(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::NamingAuthorityPointer(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::DomainRedirectName(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::DelegationSigner(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::ResourceRecordSignature(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::AuthenticatedDenial(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::PublicKey(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::DhcpClientIdentifier(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::AuthenticatedDenial3(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::AuthenticatedDenial3Parameters(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::DaneTlsa(data) => enc::ZoneEncodable::try_encode(data, encoder, writer)?,
                Self::Other { data, .. } => {
                    write!(writer, "\\# {}", data.len())?;
                    if data.len() > 0 {
                        write!(writer, " ")?;
                        for b in data {
                            write!(writer, "{:02x}", b)?;
                        }
                    }
                },
            }
        } else {
            let mut wire_bytes = Vec::new();

            let mut cur = io::Cursor::new(&mut wire_bytes);
            WireEncodable::try_encode(self, &mut cur)?;

            write!(writer, "TYPE{} \\# {}", self.record_type().to_base_type(), wire_bytes.len())?;
            if wire_bytes.len() > 0 {
                write!(writer, " ")?;
                for b in wire_bytes {
                    write!(writer, "{:02x}", b)?;
                }
            }
        }
        Ok(())
    }
}
impl WireEncodable for RecordData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        match self {
            Self::Ipv4Address(data) => data.try_encode(writer)?,
            Self::NameServer(data) => data.try_encode(writer)?,
            Self::MailDestination(data) => data.try_encode(writer)?,
            Self::MailForwarder(data) => data.try_encode(writer)?,
            Self::CanonicalName(data) => data.try_encode(writer)?,
            Self::StartOfAuthority(data) => data.try_encode(writer)?,
            Self::Mailbox(data) => data.try_encode(writer)?,
            Self::MailGroup(data) => data.try_encode(writer)?,
            Self::MailRename(data) => data.try_encode(writer)?,
            Self::WellKnownService(data) => data.try_encode(writer)?,
            Self::Pointer(data) => data.try_encode(writer)?,
            Self::HostInformation(data) => data.try_encode(writer)?,
            Self::MailboxInformation(data) => data.try_encode(writer)?,
            Self::MailExchanger(data) => data.try_encode(writer)?,
            Self::Text(data) => data.try_encode(writer)?,
            Self::ResponsiblePerson(data) => data.try_encode(writer)?,
            Self::AfsDatabase(data) => data.try_encode(writer)?,
            Self::X25Psdn(data) => data.try_encode(writer)?,
            Self::Isdn(data) => data.try_encode(writer)?,
            Self::RouteThrough(data) => data.try_encode(writer)?,
            Self::Signature(data) => data.try_encode(writer)?,
            Self::Key(data) => data.try_encode(writer)?,
            Self::Ipv6Address(data) => data.try_encode(writer)?,
            Self::NextDomain(data) => data.try_encode(writer)?,
            Self::ServerSelection(data) => data.try_encode(writer)?,
            Self::AtmAddress(data) => data.try_encode(writer)?,
            Self::NamingAuthorityPointer(data) => data.try_encode(writer)?,
            Self::DomainRedirectName(data) => data.try_encode(writer)?,
            Self::DelegationSigner(data) => data.try_encode(writer)?,
            Self::ResourceRecordSignature(data) => data.try_encode(writer)?,
            Self::AuthenticatedDenial(data) => data.try_encode(writer)?,
            Self::PublicKey(data) => data.try_encode(writer)?,
            Self::DhcpClientIdentifier(data) => data.try_encode(writer)?,
            Self::AuthenticatedDenial3(data) => data.try_encode(writer)?,
            Self::AuthenticatedDenial3Parameters(data) => data.try_encode(writer)?,
            Self::DaneTlsa(data) => data.try_encode(writer)?,
            Self::Other { data, .. } => writer.write_all(data)?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AtmAddressData {
    pub format: u8,
    pub data: Vec<u8>,
}
impl enc::MsDecodable for AtmAddressData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 2 {
            return Err(enc::Error::WrongLength);
        }
        let format = slice[0];
        let data = slice[1..].to_vec();
        Ok(Self {
            format,
            data,
        })
    }
}
impl enc::ZoneEncodable for AtmAddressData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
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
                        return Err(enc::Error::Unencodable);
                    }
                }
                write!(writer, "+")?;
                for &b in &self.data {
                    let c = char::from_u32(b.into()).unwrap();
                    write!(writer, "{}", c)?;
                }
                Ok(())
            },
            2 => {
                // Windows DNS erroneously encodes AESA with type byte 2 instead of 0;
                // dump this in the arbitrary-bytes format
                write!(writer, "\\# {} {:02x}", 1 + self.data.len(), self.format)?;
                for b in &self.data {
                    write!(writer, "{:02x}", b)?;
                }
                Ok(())
            },
            _ => Err(enc::Error::Unencodable),
        }
    }
}
impl enc::WireEncodable for AtmAddressData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_array = [self.format];
        writer.write_all(&fixed_array)?;
        writer.write_all(&self.data)?;
        Ok(())
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
    pub block_to_bitmap: BTreeMap<u8, Vec<u8>>, // DNSSEC bitmap encoding
}
impl enc::MsDecodable for AuthenticatedDenial3Data {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 6 {
            return Err(enc::Error::WrongLength);
        }
        let algorithm = slice[0];
        let flags = slice[1];
        let iterations = u16::from_le_bytes(slice[2..4].try_into().unwrap());
        let salt_length: usize = slice[4].into();
        let hash_length: usize = slice[5].into();

        if salt_length + hash_length > slice.len() - 6 {
            return Err(enc::Error::WrongLength);
        }

        let mut index = 6;

        let salt = slice[index..index+salt_length].to_vec();
        index += salt_length;

        let hash = slice[index..index+hash_length].to_vec();
        index += hash_length;

        let block_to_bitmap = parse_dnssec_type_bitmap(slice, &mut index)?;

        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt,
            hash,
            block_to_bitmap,
        })
    }
}
impl enc::ZoneEncodable for AuthenticatedDenial3Data {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        // RFC5155 § 3.3
        write!(writer, "{} {} {} ", self.algorithm, self.flags, self.iterations)?;

        if self.salt.len() > 0 {
            for &b in &self.salt {
                write!(writer, "{:02x}", b)?;
            }
        } else {
            write!(writer, "-")?;
        }

        let base32_rfc5155 = base32::Alphabet::Rfc4648Hex { padding: false };
        let encoded_hash = base32::encode(base32_rfc5155, &self.hash);
        write!(writer, " {}", encoded_hash)?;

        write_zone_dnssec_type_bitmap(&self.block_to_bitmap, encoder, writer)?;

        Ok(())
    }
}
impl enc::WireEncodable for AuthenticatedDenial3Data {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let salt_len_u8: u8 = self.salt.len()
            .try_into().map_err(|_| enc::Error::Unencodable)?;
        let hash_len_u8: u8 = self.hash.len()
            .try_into().map_err(|_| enc::Error::Unencodable)?;

        let fixed_array = [
            self.algorithm, self.flags, u16_msb(self.iterations), u16_lsb(self.iterations),
            salt_len_u8,
        ];
        writer.write_all(&fixed_array)?;
        writer.write_all(&self.salt)?;
        let hash_array = [hash_len_u8];
        writer.write_all(&hash_array)?;
        writer.write_all(&self.hash)?;
        write_wire_dnssec_type_bitmap(&self.block_to_bitmap, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatedDenial3ParametersData {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    // salt length: u8,
    pub salt: Vec<u8>,
}
impl enc::MsDecodable for AuthenticatedDenial3ParametersData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 6 {
            return Err(enc::Error::WrongLength);
        }
        let algorithm = slice[0];
        let flags = slice[1];
        let iterations = u16::from_le_bytes(slice[2..4].try_into().unwrap());
        let salt_length: usize = slice[4].into();

        if salt_length > slice.len() - 5 {
            return Err(enc::Error::WrongLength);
        }

        let mut index = 5;

        let salt = slice[index..index+salt_length].to_vec();
        index += salt_length;

        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt,
        })
    }
}
impl enc::ZoneEncodable for AuthenticatedDenial3ParametersData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        // RFC5155 § 4.3
        write!(writer, "{} {} {} ", self.algorithm, self.flags, self.iterations)?;

        if self.salt.len() > 0 {
            for &b in &self.salt {
                write!(writer, "{:02x}", b)?;
            }
        } else {
            write!(writer, "-")?;
        }

        Ok(())
    }
}
impl enc::WireEncodable for AuthenticatedDenial3ParametersData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let salt_len_u8: u8 = self.salt.len()
            .try_into().map_err(|_| enc::Error::Unencodable)?;

        let fixed_array = [
            self.algorithm, self.flags, u16_msb(self.iterations), u16_lsb(self.iterations),
            salt_len_u8,
        ];
        writer.write_all(&fixed_array)?;
        writer.write_all(&self.salt)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatedDenialData {
    pub name_signer: String, // name
    pub block_to_bitmap: BTreeMap<u8, Vec<u8>>, // DNSSEC bitmap encoding
}
impl enc::MsDecodable for AuthenticatedDenialData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        let mut index = 0;
        let name_signer = parse_ms_dns_name(slice, &mut index)?;
        let block_to_bitmap = parse_dnssec_type_bitmap(slice, &mut index)?;

        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            name_signer,
            block_to_bitmap,
        })
    }
}
impl enc::ZoneEncodable for AuthenticatedDenialData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        // RFC4034 § 4.2
        write!(writer, "{}", self.name_signer)?;
        write_zone_dnssec_type_bitmap(&self.block_to_bitmap, encoder, writer)?;
        Ok(())
    }
}
impl enc::WireEncodable for AuthenticatedDenialData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        write_wire_dns_name(&self.name_signer, writer)?;
        write_wire_dnssec_type_bitmap(&self.block_to_bitmap, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DaneTlsaData {
    pub certificate_usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub certificate_association_data: Vec<u8>,
}
impl enc::MsDecodable for DaneTlsaData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 4 {
            return Err(enc::Error::WrongLength);
        }

        let certificate_usage = slice[0];
        let selector = slice[1];
        let matching_type = slice[2];
        let certificate_association_data = slice[3..].to_vec();

        Ok(Self {
            certificate_usage,
            selector,
            matching_type,
            certificate_association_data,
        })
    }
}
impl enc::ZoneEncodable for DaneTlsaData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        // RFC6698 § 2.2
        write!(writer, "{} {} {} ", self.certificate_usage, self.selector, self.matching_type)?;
        for &b in &self.certificate_association_data {
            write!(writer, "{:02x}", b)?;
        }
        Ok(())
    }
}
impl enc::WireEncodable for DaneTlsaData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_data = [self.certificate_usage, self.selector, self.matching_type];
        writer.write_all(&fixed_data)?;
        writer.write_all(&self.certificate_association_data)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DelegationSignerData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}
impl enc::MsDecodable for DelegationSignerData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 5 {
            return Err(enc::Error::WrongLength);
        }
        let key_tag = u16::from_be_bytes(slice[0..2].try_into().unwrap());
        let algorithm = slice[2];
        let digest_type = slice[3];
        let digest = slice[4..].to_vec();
        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}
impl enc::ZoneEncodable for DelegationSignerData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        // RFC4034 § 5.3
        write!(writer, "{} {} {} ", self.key_tag, self.algorithm, self.digest_type)?;
        for &b in &self.digest {
            write!(writer, "{:02x}", b)?;
        }
        Ok(())
    }
}
impl enc::WireEncodable for DelegationSignerData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_data = [
            u16_msb(self.key_tag), u16_lsb(self.key_tag),
            self.algorithm, self.digest_type,
        ];
        writer.write_all(&fixed_data)?;
        writer.write_all(&self.digest)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DhcpClientIdentifierData {
    pub dhcp_identifier: Vec<u8>,
}
impl enc::MsDecodable for DhcpClientIdentifierData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        let dhcp_identifier = slice.to_vec();
        Ok(Self {
            dhcp_identifier,
        })
    }
}
impl enc::ZoneEncodable for DhcpClientIdentifierData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        // RFC4701 § 3.2
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.dhcp_identifier);
        write!(writer, "{}", encoded)?;
        Ok(())
    }
}
impl enc::WireEncodable for DhcpClientIdentifierData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        writer.write_all(&self.dhcp_identifier)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4AddressData {
    pub address: Ipv4Addr,
}
impl enc::MsDecodable for Ipv4AddressData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() != 4 {
            return Err(enc::Error::WrongLength);
        }
        let address = Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]);
        Ok(Self {
            address,
        })
    }
}
impl enc::ZoneEncodable for Ipv4AddressData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{}", self.address)?;
        Ok(())
    }
}
impl enc::WireEncodable for Ipv4AddressData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let addr_bytes = self.address.octets();
        writer.write_all(&addr_bytes)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv6AddressData {
    pub address: Ipv6Addr,
}
impl enc::MsDecodable for Ipv6AddressData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() != 16 {
            return Err(enc::Error::WrongLength);
        }
        let address_bits = u128::from_be_bytes(slice.try_into().unwrap());
        let address = Ipv6Addr::from_bits(address_bits);
        Ok(Self {
            address,
        })
    }
}
impl enc::ZoneEncodable for Ipv6AddressData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{}", self.address)?;
        Ok(())
    }
}
impl enc::WireEncodable for Ipv6AddressData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let addr_bytes = self.address.octets();
        writer.write_all(&addr_bytes)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MailboxPairData {
    pub one_mailbox: String, // name
    pub other_mailbox: String, // name
}
impl enc::MsDecodable for MailboxPairData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        let mut index = 0;
        let one_mailbox = parse_ms_dns_name(slice, &mut index)?;
        let other_mailbox = parse_ms_dns_name(slice, &mut index)?;
        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            one_mailbox,
            other_mailbox,
        })
    }
}
impl enc::ZoneEncodable for MailboxPairData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} {}", self.one_mailbox, self.other_mailbox)?;
        Ok(())
    }
}
impl enc::WireEncodable for MailboxPairData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        write_wire_dns_name(&self.one_mailbox, writer)?;
        write_wire_dns_name(&self.other_mailbox, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NameAndPreferenceData {
    pub preference: u16,
    pub name: String, // name
}
impl enc::MsDecodable for NameAndPreferenceData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 2 {
            return Err(enc::Error::WrongLength);
        }
        let preference = u16::from_be_bytes(slice[0..2].try_into().unwrap());
        let mut index = 2;
        let name = parse_ms_dns_name(slice, &mut index)?;
        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            preference,
            name,
        })
    }
}
impl enc::ZoneEncodable for NameAndPreferenceData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} {}", self.preference, self.name)?;
        Ok(())
    }
}
impl enc::WireEncodable for NameAndPreferenceData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_bytes = [
            u16_msb(self.preference), u16_lsb(self.preference),
        ];
        writer.write_all(&fixed_bytes)?;
        write_wire_dns_name(&self.name, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamingAuthorityPointerData {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub services: String,
    pub regexp: String,
    pub replacement: String, // name
}
impl enc::MsDecodable for NamingAuthorityPointerData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 4 {
            return Err(enc::Error::WrongLength);
        }
        let order = u16::from_be_bytes(slice[0..2].try_into().unwrap());
        let preference = u16::from_be_bytes(slice[2..4].try_into().unwrap());
        let mut index = 4;
        let flags = parse_string(slice, &mut index)?;
        let services = parse_string(slice, &mut index)?;
        let regexp = parse_string(slice, &mut index)?;
        let replacement = parse_ms_dns_name(slice, &mut index)?;
        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        })
    }
}
impl enc::ZoneEncodable for NamingAuthorityPointerData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} {} ", self.order, self.preference)?;
        write_zone_quoted_string(&self.flags, writer)?;
        write!(writer, " ")?;
        write_zone_quoted_string(&self.services, writer)?;
        write!(writer, " ")?;
        write_zone_quoted_string(&self.regexp, writer)?;
        write!(writer, " {}", self.replacement)?;
        Ok(())
    }
}
impl enc::WireEncodable for NamingAuthorityPointerData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_bytes = [
            u16_msb(self.order), u16_lsb(self.order),
            u16_msb(self.preference), u16_lsb(self.preference),
        ];
        writer.write_all(&fixed_bytes)?;
        write_wire_string(&self.flags, writer)?;
        write_wire_string(&self.services, writer)?;
        write_wire_string(&self.regexp, writer)?;
        write_wire_dns_name(&self.replacement, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NextDomainData {
// theoretically (RPC format):
    // bitmap_word_count: u16
    // bitmap: [u16; bitmap_word_count]
// name: String, // name
    //
    // in practice (MS DNS structure):
    pub bitmap: [u8; 16],
    pub name: String, // name
}
impl enc::MsDecodable for NextDomainData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 16 {
            return Err(enc::Error::WrongLength);
        }
        
        let mut bitmap = [0u8; 16];
        bitmap.copy_from_slice(&slice[0..16]);

        let mut index = 16;
        let name = parse_ms_dns_name(slice, &mut index)?;

        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            bitmap,
            name,
        })
    }
}
impl enc::ZoneEncodable for NextDomainData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{}", self.name)?;
        write_zone_linear_type_bitmap(0, &self.bitmap, encoder, writer)?;
        Ok(())
    }
}
impl enc::WireEncodable for NextDomainData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        write_wire_dns_name(&self.name, writer)?;
        writer.write_all(&self.bitmap)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeNameData {
    pub name: String,
}
impl enc::MsDecodable for NodeNameData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        let mut index = 0;
        let name = parse_ms_dns_name(slice, &mut index)?;
        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            name,
        })
    }
}
impl enc::ZoneEncodable for NodeNameData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{}", self.name)?;
        Ok(())
    }
}
impl enc::WireEncodable for NodeNameData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        write_wire_dns_name(&self.name, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicKeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub key: Vec<u8>,
}
impl enc::MsDecodable for PublicKeyData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 4 {
            return Err(enc::Error::WrongLength);
        }

        let flags = u16::from_be_bytes(slice[0..2].try_into().unwrap());
        let protocol = slice[2];
        let algorithm = slice[3];
        let key = slice[4..].to_vec();

        Ok(Self {
            flags,
            protocol,
            algorithm,
            key,
        })
    }
}
impl enc::ZoneEncodable for PublicKeyData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} {} {}", self.flags, self.protocol, self.algorithm)?;
        if self.key.len() > 0 {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&self.key);
            write!(writer, " {}", encoded)?;
        }
        Ok(())
    }
}
impl enc::WireEncodable for PublicKeyData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_array = [
            u16_msb(self.flags), u16_lsb(self.flags),
            self.protocol, self.algorithm,
        ];
        writer.write_all(&fixed_array)?;
        writer.write_all(&self.key)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServerSelectionData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String, // name
}
impl enc::MsDecodable for ServerSelectionData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 6 {
            return Err(enc::Error::WrongLength);
        }

        let priority = u16::from_be_bytes(slice[0..2].try_into().unwrap());
        let weight = u16::from_be_bytes(slice[2..4].try_into().unwrap());
        let port = u16::from_be_bytes(slice[4..6].try_into().unwrap());

        let mut index = 6;
        let target = parse_ms_dns_name(slice, &mut index)?;

        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }
}
impl enc::ZoneEncodable for ServerSelectionData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} {} {} {}", self.priority, self.weight, self.port, self.target)?;
        Ok(())
    }
}
impl enc::WireEncodable for ServerSelectionData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_array = [
            u16_msb(self.priority), u16_lsb(self.priority),
            u16_msb(self.weight), u16_lsb(self.weight),
            u16_msb(self.port), u16_lsb(self.port),
        ];
        writer.write_all(&fixed_array)?;
        write_wire_dns_name(&self.target, writer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureData {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration: u32,
    pub signature_inception: u32,
    pub key_tag: u16,
    pub name_signer: String, // name
    pub signature_info: Vec<u8>,
}
impl enc::MsDecodable for SignatureData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 18 {
            return Err(enc::Error::WrongLength);
        }

        let type_covered = u16::from_be_bytes(slice[0..2].try_into().unwrap());
        let algorithm = slice[2];
        let labels = slice[3];
        let original_ttl = u32::from_be_bytes(slice[4..8].try_into().unwrap());
        let signature_expiration = u32::from_be_bytes(slice[8..12].try_into().unwrap());
        let signature_inception = u32::from_be_bytes(slice[12..16].try_into().unwrap());
        let key_tag = u16::from_be_bytes(slice[16..18].try_into().unwrap());

        let mut index = 18;
        let name_signer = parse_ms_dns_name(slice, &mut index)?;
        let signature_info = slice[index..].to_vec();

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            name_signer,
            signature_info,
        })
    }
}
impl enc::ZoneEncodable for SignatureData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        let type_covered = RecordType::from_base_type(self.type_covered);
        if type_covered.is_known() && encoder.knows_record_type(self.type_covered) {
            write!(writer, "{}", type_covered.to_name())?;
        } else {
            write!(writer, "TYPE{}", self.type_covered)?;
        }

        write!(
            writer,
            " {} {} {} {} {} {} {}",
            self.algorithm,
            self.labels,
            self.original_ttl,
            self.signature_expiration,
            self.signature_inception,
            self.key_tag,
            self.name_signer,
        )?;
        if self.signature_info.len() > 0 {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&self.signature_info);
            write!(writer, " {}", encoded)?;
        }
        Ok(())
    }
}
impl enc::WireEncodable for SignatureData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let fixed_array = [
            u16_msb(self.type_covered), u16_lsb(self.type_covered),
            self.algorithm, self.labels,
            u32_msb(self.original_ttl), u32_2sb(self.original_ttl),
            u32_3sb(self.original_ttl), u32_lsb(self.original_ttl),
            u32_msb(self.signature_expiration), u32_2sb(self.signature_expiration),
            u32_3sb(self.signature_expiration), u32_lsb(self.signature_expiration),
            u32_msb(self.signature_inception), u32_2sb(self.signature_inception),
            u32_3sb(self.signature_inception), u32_lsb(self.signature_inception),
            u16_msb(self.key_tag), u16_lsb(self.key_tag),
        ];
        writer.write_all(&fixed_array)?;
        write_wire_dns_name(&self.name_signer, writer)?;
        writer.write_all(&self.signature_info)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StartOfAuthorityData {
    pub serial_number: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
    pub primary_server: String, // name
    pub zone_admin_email: String, // name
}
impl enc::MsDecodable for StartOfAuthorityData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 20 {
            return Err(enc::Error::WrongLength);
        }

        let serial_number = u32::from_be_bytes(slice[0..4].try_into().unwrap());
        let refresh = u32::from_be_bytes(slice[4..8].try_into().unwrap());
        let retry = u32::from_be_bytes(slice[8..12].try_into().unwrap());
        let expire = u32::from_be_bytes(slice[12..16].try_into().unwrap());
        let minimum_ttl = u32::from_be_bytes(slice[16..20].try_into().unwrap());

        let mut index = 20;
        let primary_server = parse_ms_dns_name(slice, &mut index)?;
        let zone_admin_email = parse_ms_dns_name(slice, &mut index)?;

        if index < slice.len() {
            return Err(enc::Error::WrongLength);
        }

        Ok(Self {
            serial_number,
            refresh,
            retry,
            expire,
            minimum_ttl,
            primary_server,
            zone_admin_email,
        })
    }
}
impl enc::ZoneEncodable for StartOfAuthorityData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(
            writer,
            "{} {} {} {} {} {} {}",
            self.primary_server,
            self.zone_admin_email,
            self.serial_number,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum_ttl,
        )?;
        Ok(())
    }
}
impl enc::WireEncodable for StartOfAuthorityData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        write_wire_dns_name(&self.primary_server, writer)?;
        write_wire_dns_name(&self.zone_admin_email, writer)?;
        let fixed_array = [
            u32_msb(self.serial_number), u32_2sb(self.serial_number),
            u32_3sb(self.serial_number), u32_lsb(self.serial_number),
            u32_msb(self.refresh), u32_2sb(self.refresh),
            u32_3sb(self.refresh), u32_lsb(self.refresh),
            u32_msb(self.retry), u32_2sb(self.retry),
            u32_3sb(self.retry), u32_lsb(self.retry),
            u32_msb(self.expire), u32_2sb(self.expire),
            u32_3sb(self.expire), u32_lsb(self.expire),
            u32_msb(self.minimum_ttl), u32_2sb(self.minimum_ttl),
            u32_3sb(self.minimum_ttl), u32_lsb(self.minimum_ttl),
        ];
        writer.write_all(&fixed_array)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StringData {
    pub strings: Vec<String>,
}
impl enc::MsDecodable for StringData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        let mut index = 0;
        let mut strings = Vec::new();
        while index < slice.len() {
            let string = parse_string(slice, &mut index)?;
            strings.push(string);
        }

        Ok(Self {
            strings,
        })
    }
}
impl enc::ZoneEncodable for StringData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        let mut first_string = true;
        for string in &self.strings {
            if first_string {
                first_string = false;
            } else {
                write!(writer, " ")?;
            }
            write_zone_quoted_string(string, writer)?;
        }
        Ok(())
    }
}
impl enc::WireEncodable for StringData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        for string in &self.strings {
            write_wire_string(string, writer)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WellKnownServiceData {
    pub address: Ipv4Addr,
    pub protocol: u8,
    pub bitmap: Vec<u8>,
}
impl enc::MsDecodable for WellKnownServiceData {
    fn try_decode(slice: &[u8]) -> Result<Self, enc::Error> {
        if slice.len() < 5 {
            return Err(enc::Error::WrongLength);
        }
        let address = Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]);
        let protocol = slice[4];

        let mut bitmap = slice[5..].to_vec();

        // bytes are in the correct order but the bits within them aren't
        for b in &mut bitmap {
            *b = b.reverse_bits();
        }

        Ok(Self {
            address,
            protocol,
            bitmap,
        })
    }
}
impl enc::ZoneEncodable for WellKnownServiceData {
    fn try_encode<D: enc::Encoder, W: fmt::Write>(&self, _encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
        write!(writer, "{} {}", self.address, self.protocol)?;
        for (byte_index, &byte) in self.bitmap.iter().enumerate() {
            let byte_base = byte_index * 8;
            for bit_index in 0..8 {
                if byte & (1 << bit_index) != 0 {
                    let port_number = byte_base + bit_index;
                    write!(writer, " {}", port_number)?;
                }
            }
        }
        Ok(())
    }
}
impl enc::WireEncodable for WellKnownServiceData {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), enc::Error> {
        let address = self.address.octets();
        let fixed_array = [
            address[0], address[1], address[2], address[3],
            self.protocol,
        ];
        writer.write_all(&fixed_array)?;
        writer.write_all(&self.bitmap)?;
        Ok(())
    }
}

/// Parses a DNSSEC record type bitmap.
///
/// This bitmap encoding is specified in RFC4034 § 4.1.2 and RFC5155 § 3.2.1.
fn parse_dnssec_type_bitmap(slice: &[u8], index: &mut usize) -> Result<BTreeMap<u8, Vec<u8>>, enc::Error> {
    let mut block_to_bitmap = BTreeMap::new();
    while *index < slice.len() {
        // pick out block and length
        if *index + 2 > slice.len() {
            return Err(enc::Error::WrongLength);
        }
        let block = slice[*index];
        let length: usize = slice[*index + 1].into();
        *index += 2;

        // block contains the upper byte of all records within it;
        // length contains the number of bytes for this block in the bitmap;
        // each byte in the bitmap represents 8 record types;
        // since each block has record types 0-255, length is <= 32;
        // since it is pointless to list empty blocks, length is >= 1
        if length < 1 || length > 32 {
            return Err(enc::Error::InvalidData);
        }

        // bits are encoded as follows:
        // first byte: LSB represents 0, MSB represents 7
        // second byte: LSB represents 8, MSB represents 15
        // etc.
        if *index + length > slice.len() {
            return Err(enc::Error::WrongLength);
        }
        let bitmap = slice[*index..*index+length].to_vec();
        *index += length;

        block_to_bitmap.insert(block, bitmap);
    }
    Ok(block_to_bitmap)
}

/// Writes out a DNSSEC record type bitmap in zone file format.
///
/// This bitmap encoding is specified in RFC4034 § 4.1.2 and RFC5155 § 3.2.1.
fn write_zone_dnssec_type_bitmap<D: enc::Encoder, W: fmt::Write>(block_to_bitmap: &BTreeMap<u8, Vec<u8>>, encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
    for (&block, bitmap) in block_to_bitmap {
        let kind_base = u16::from(block) << 8;
        write_zone_linear_type_bitmap(kind_base, bitmap, encoder, writer)?;
    }

    Ok(())
}

/// Writes out a linear type bitmap in zone file format.
///
/// This bitmap encoding is specified in RFC2535 § 5.2.
fn write_zone_linear_type_bitmap<D: enc::Encoder, W: fmt::Write>(kind_base: u16, bitmap: &[u8], encoder: &D, writer: &mut W) -> Result<(), enc::Error> {
    for (byte_index, &byte) in bitmap.iter().enumerate() {
        let byte_index_bits = byte_index * 8;
        for bit_index in 0..7 {
            if byte & (1 << bit_index) == 0 {
                continue;
            }

            // bit is set
            let complete_kind = kind_base + u16::try_from(byte_index_bits).unwrap() + bit_index;

            // do we know this type?
            let rec_type = RecordType::from_base_type(complete_kind);
            if rec_type.is_known() && encoder.knows_record_type(complete_kind) {
                // write out the name
                write!(writer, " {}", rec_type.to_name())?;
            } else {
                // RFC3597 to the rescue
                write!(writer, " TYPE{}", complete_kind)?;
            }
        }
    }

    Ok(())
}

fn parse_string(slice: &[u8], index: &mut usize) -> Result<String, enc::Error> {
    // byte of length, then string
    if *index + 1 > slice.len() {
        return Err(enc::Error::WrongLength);
    }

    let length: usize = slice[*index].into();
    *index += 1;

    if *index + length > slice.len() {
        return Err(enc::Error::WrongLength);
    }

    let bytes = slice[*index..*index+length].to_vec();
    *index += length;

    let string = String::from_utf8(bytes)
        .map_err(|_| enc::Error::InvalidData)?;
    Ok(string)
}

fn parse_ms_dns_name(slice: &[u8], index: &mut usize) -> Result<String, enc::Error> {
    // [MS-DNSP] § 3.1.6.3: any DNS_RPC_NAME is converted to DNS_COUNT_NAME
    // length: u8
    // label_count: u8
    // labels: [Label; label_count]
    // struct Label { length: u8, data: [u8; length] }

    if *index + 2 > slice.len() {
        return Err(enc::Error::WrongLength);
    }

    let total_length: usize = slice[*index].into();
    let label_count: usize = slice[*index+1].into();
    *index += 2;

    if *index + total_length > slice.len() {
        return Err(enc::Error::WrongLength);
    }

    let mut fqdn = String::new();
    for _ in 0..label_count {
        if *index + 1 > slice.len() {
            return Err(enc::Error::WrongLength);
        }

        let label_length: usize = slice[*index].into();
        *index += 1;

        if *index + label_length > slice.len() {
            return Err(enc::Error::WrongLength);
        }

        let label_slice = &slice[*index..*index+label_length];
        *index += label_length;
        let label_str = std::str::from_utf8(label_slice)
            .map_err(|_| enc::Error::InvalidData)?;
        let label_string = label_str
            .replace("\\", "\\\\")
            .replace(".", "\\.");
        fqdn.push_str(&label_string);
        fqdn.push('.');
    }

    // skip the trailing zero byte
    if *index + 1 > slice.len() {
        return Err(enc::Error::WrongLength);
    }
    *index += 1;

    Ok(fqdn)
}

fn write_zone_quoted_string<W: fmt::Write>(string: &str, writer: &mut W) -> Result<(), enc::Error> {
    write!(writer, "\"")?;
    for c in string.chars() {
        match c {
            '\\' => write!(writer, "\\\\")?,
            '"' => write!(writer, "\\\"")?,
            other => write!(writer, "{}", other)?,
        }
    }
    write!(writer, "\"")?;
    Ok(())
}

fn write_wire_dns_name<W: io::Write>(name: &str, writer: &mut W) -> Result<(), enc::Error> {
    if name.contains("..") {
        return Err(enc::Error::Unencodable);
    }
    for piece in name.split('.') {
        let piece_len: u8 = piece.len().try_into()
            .map_err(|_| enc::Error::Unencodable)?;
        let piece_array = [piece_len];
        writer.write_all(&piece_array)?;
        writer.write_all(piece.as_bytes())?;
    }
    Ok(())
}

fn write_wire_dnssec_type_bitmap<W: io::Write>(block_to_bitmap: &BTreeMap<u8, Vec<u8>>, writer: &mut W) -> Result<(), enc::Error> {
    for (&block, bitmap) in block_to_bitmap {
        let bitmap_len: u8 = bitmap.len()
            .try_into().map_err(|_| enc::Error::Unencodable)?;
        let block_array = [block, bitmap_len];
        writer.write_all(&block_array)?;
        writer.write_all(bitmap)?;
    }
    Ok(())
}

fn write_wire_string<W: io::Write>(string: &str, writer: &mut W) -> Result<(), enc::Error> {
    let string_len: u8 = string.len()
        .try_into().map_err(|_| enc::Error::Unencodable)?;
    let length_array = [string_len];
    writer.write_all(&length_array)?;
    writer.write_all(string.as_bytes())?;
    Ok(())
}
