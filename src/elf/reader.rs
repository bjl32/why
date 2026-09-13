//! Bounds-checked byte decoding with explicit endianness.
//!
//! Every read in this module is checked against the buffer length, so a
//! truncated or hostile file produces an error instead of a panic.

use std::fmt;

/// Byte order of the file being parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    #[inline]
    fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        }
    }
}

/// A read that fell outside the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfBounds {
    pub offset: usize,
    pub size: usize,
    pub len: usize,
}

impl fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "read of {} byte(s) at offset {} exceeds the {} byte buffer",
            self.size, self.offset, self.len
        )
    }
}

impl std::error::Error for OutOfBounds {}

/// A cursor over a byte slice that decodes integers with a fixed endianness.
#[derive(Debug, Clone, Copy)]
pub struct Bytes<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Self { data, endian }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.data
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a sub-slice, or an error if it does not fit in the buffer.
    pub fn slice(&self, offset: usize, size: usize) -> Result<&'a [u8], OutOfBounds> {
        let end = offset.checked_add(size).ok_or(OutOfBounds {
            offset,
            size,
            len: self.data.len(),
        })?;
        self.data.get(offset..end).ok_or(OutOfBounds {
            offset,
            size,
            len: self.data.len(),
        })
    }

    pub fn u8(&self, offset: usize) -> Result<u8, OutOfBounds> {
        Ok(self.slice(offset, 1)?[0])
    }

    pub fn u16(&self, offset: usize) -> Result<u16, OutOfBounds> {
        let s = self.slice(offset, 2)?;
        Ok(self.endian.u16([s[0], s[1]]))
    }

    pub fn u32(&self, offset: usize) -> Result<u32, OutOfBounds> {
        let s = self.slice(offset, 4)?;
        Ok(self.endian.u32([s[0], s[1], s[2], s[3]]))
    }

    pub fn u64(&self, offset: usize) -> Result<u64, OutOfBounds> {
        let s = self.slice(offset, 8)?;
        Ok(self
            .endian
            .u64([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }

    /// Reads a NUL-terminated string starting at `offset`.
    ///
    /// Invalid UTF-8 is replaced rather than rejected: symbol names from the
    /// wild are occasionally not valid UTF-8, and a mangled name is still
    /// useful for a diagnostic report.
    pub fn cstr(&self, offset: usize) -> Option<String> {
        let rest = self.data.get(offset..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }
}
