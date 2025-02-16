use std::fmt;
use std::io;


#[derive(Debug)]
pub enum Error {
    Fmt(fmt::Error),
    Io(io::Error),
    Unencodable,
    WrongLength,
    InvalidData,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Fmt(e) => write!(f, "formatting error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Unencodable => write!(f, "value cannot be encoded"),
            Self::WrongLength => write!(f, "value has incorrect length"),
            Self::InvalidData => write!(f, "invalid data"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fmt(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Unencodable => None,
            Self::WrongLength => None,
            Self::InvalidData => None,
        }
    }
}
impl From<fmt::Error> for Error {
    fn from(value: fmt::Error) -> Self { Self::Fmt(value) }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

pub trait Encoder {
    fn knows_record_type(&self, record_type: u16) -> bool;
}

pub struct SupportsEverythingEncoder;
impl Encoder for SupportsEverythingEncoder {
    fn knows_record_type(&self, _record_type: u16) -> bool { true }
}

pub trait ZoneEncodable {
    fn try_encode<E: Encoder, W: fmt::Write>(&self, encoder: &E, writer: &mut W) -> Result<(), Error>;
}

pub trait WireEncodable {
    fn try_encode<W: io::Write>(&self, writer: &mut W) -> Result<(), Error>;
}

pub trait MsDecodable {
    fn try_decode(slice: &[u8]) -> Result<Self, Error>
        where Self : Sized;
}

pub struct ByteWriteAdapter<'a, W: io::Write>(pub &'a mut W);
impl<'a, W: io::Write> fmt::Write for ByteWriteAdapter<'a, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_all(s.as_bytes())
            .map_err(|_| fmt::Error)
    }
}
