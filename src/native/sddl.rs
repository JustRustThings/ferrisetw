use std::convert::TryFrom;
use std::str::Utf8Error;

/// SDDL native error
#[derive(Debug)]
pub enum SddlNativeError {
    /// Represents an error parsing the SID into a String
    ///
    /// No longer produced: SIDs are now formatted directly, without decoding a C string.
    SidParseError(Utf8Error),
    /// The buffer does not hold a well-formed SID
    InvalidSid(&'static str),
    /// Represents an standard IO Error
    ///
    /// No longer produced: formatting a SID does not call into Windows any more.
    IoError(std::io::Error),
}

impl From<Utf8Error> for SddlNativeError {
    fn from(err: Utf8Error) -> Self {
        SddlNativeError::SidParseError(err)
    }
}

impl std::fmt::Display for SddlNativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SidParseError(e) => write!(f, "sid parse error {}", e),
            Self::InvalidSid(reason) => write!(f, "invalid sid: {}", reason),
            Self::IoError(e) => write!(f, "i/o error {}", e),
        }
    }
}

pub(crate) type SddlResult<T> = Result<T, SddlNativeError>;

/// Size of the fixed part of a `SID`: revision, sub-authority count, and identifier authority
const SID_HEADER_SIZE: usize = 8;

/// `SID_MAX_SUB_AUTHORITIES`, from `winnt.h`
const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// `SID_REVISION`, from `winnt.h`: the only revision `IsValidSid` accepts
const SID_REVISION: u8 = 1;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Size of the SID at the start of `bytes`, read from its own header
///
/// A SID declares how many sub-authorities it has in its second byte, so its size is known without
/// asking Windows. The checks are the ones `IsValidSid` makes; a header that fails them is reported
/// so that callers can fail the way they always have.
pub(crate) fn sid_size(bytes: &[u8]) -> Result<usize, &'static str> {
    let header = bytes.get(..2).ok_or("shorter than a SID header")?;
    if header[0] != SID_REVISION {
        return Err("unsupported revision");
    }
    let sub_authority_count = usize::from(header[1]);
    if sub_authority_count > SID_MAX_SUB_AUTHORITIES {
        return Err("too many sub-authorities");
    }
    Ok(SID_HEADER_SIZE + 4 * sub_authority_count)
}

/// The longest text a SID can have: `S-`, a revision of up to three digits, an identifier
/// authority written as `-0x` and twelve hexadecimal digits, and `SID_MAX_SUB_AUTHORITIES`
/// sub-authorities of up to ten digits each
const SID_STRING_MAX_LEN: usize =
    "S-".len() + 3 + "-0x".len() + 12 + SID_MAX_SUB_AUTHORITIES * (1 + 10);

/// A SID's text, held inline
///
/// A SID cannot be written in more than [`SID_STRING_MAX_LEN`] bytes, so formatting one needs no
/// allocation at all: [`SidStr::as_str`] borrows the text out of the value itself, and a caller
/// that wants it somewhere else -- in an interned or reference-counted string, say -- can copy it
/// there directly, with no `String` in between.
#[derive(Clone)]
pub struct SidStr {
    text: [u8; SID_STRING_MAX_LEN],
    len: usize,
}

impl SidStr {
    fn new() -> Self {
        SidStr {
            text: [0; SID_STRING_MAX_LEN],
            len: 0,
        }
    }

    /// The text written so far
    pub fn as_str(&self) -> &str {
        // Everything `push_*` writes is ASCII, so the fallback is unreachable; it is there so
        // that a bug here could never panic a trace callback
        std::str::from_utf8(&self.text[..self.len]).unwrap_or("<invalid sid>")
    }

    fn push(&mut self, byte: u8) {
        if let Some(slot) = self.text.get_mut(self.len) {
            *slot = byte;
            self.len += 1;
        }
    }

    fn push_str(&mut self, text: &str) {
        for byte in text.bytes() {
            self.push(byte);
        }
    }

    /// Append `value` in decimal
    ///
    /// This is `write!(out, "{}", value)` without `core::fmt`, which is worth avoiding on a path
    /// that runs for every SID-typed property of every event: the formatting machinery costs more
    /// than everything else here put together.
    fn push_decimal(&mut self, value: u32) {
        let mut digits = [0u8; 10];
        let mut len = 0;
        let mut rest = value;
        loop {
            digits[len] = b'0' + (rest % 10) as u8;
            rest /= 10;
            len += 1;
            if rest == 0 {
                break;
            }
        }

        while len > 0 {
            len -= 1;
            self.push(digits[len]);
        }
    }

    /// Append `value` in hexadecimal, without leading zeros
    fn push_hex(&mut self, value: u64) {
        // One digit per four bits; `checked_ilog2` is `None` for zero, which is written as one digit
        let digits = (value.checked_ilog2().unwrap_or(0) / 4 + 1) as usize;
        for digit in (0..digits).rev() {
            let nibble = (value >> (4 * digit)) & 0xf;
            self.push(HEX_DIGITS[nibble as usize]);
        }
    }
}

impl std::ops::Deref for SidStr {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for SidStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for SidStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for SidStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Format a SID the way [`ConvertSidToStringSidA`] would, without calling into Windows
///
/// A SID is `{revision: u8, sub_authority_count: u8, identifier_authority: [u8; 6],
/// sub_authorities: [u32]}`, and its string form is mechanical: `S-<revision>-<authority>` then
/// one `-<sub-authority>` per sub-authority. Doing it here costs a single `String` allocation,
/// where `ConvertSidToStringSidA` also `LocalAlloc`s its output buffer (which we then have to
/// `LocalFree`) on the Win32 process heap, and costs a syscall for every SID of every event.
///
/// [`ConvertSidToStringSidA`]: https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsida
pub fn convert_sid_to_string(sid: &[u8]) -> SddlResult<String> {
    // `ConvertSidToStringSidA` validates the SID before formatting it, and callers may well be
    // relying on malformed input being rejected rather than formatted: `sid_size` makes the same
    // checks `IsValidSid` does
    let size = sid_size(sid).map_err(SddlNativeError::InvalidSid)?;
    let sid = sid.get(..size).ok_or(SddlNativeError::InvalidSid(
        "shorter than the sub-authority count it declares",
    ))?;

    Ok(format_sid(sid).as_str().to_owned())
}

/// Format a SID whose header has already been checked, and whose length is exactly the one that
/// header declares
pub(crate) fn format_sid(sid: &[u8]) -> SidStr {
    let (header, sub_authorities) = sid.split_at(SID_HEADER_SIZE);

    // The identifier authority is a six-byte big-endian number. Windows prints it in decimal when
    // it fits in four bytes -- which is the case for every authority in use -- and in hexadecimal,
    // without leading zeros, otherwise.
    let authority = u64::from_be_bytes([
        0, 0, header[2], header[3], header[4], header[5], header[6], header[7],
    ]);

    let mut out = SidStr::new();
    out.push_str("S-");
    out.push_decimal(u32::from(header[0]));

    match u32::try_from(authority) {
        Ok(value) => {
            out.push(b'-');
            out.push_decimal(value);
        }
        Err(_) => {
            out.push_str("-0x");
            out.push_hex(authority);
        }
    }

    // The sub-authorities are `u32`s, in the memory order of the record
    for sub_authority in sub_authorities.chunks_exact(4) {
        out.push(b'-');
        out.push_decimal(u32::from_ne_bytes([
            sub_authority[0],
            sub_authority[1],
            sub_authority[2],
            sub_authority[3],
        ]));
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_convert_sid_to_string() {
        // BUILTIN\Administrators
        let sid = [1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0];
        assert_eq!(convert_sid_to_string(&sid).unwrap(), "S-1-5-32-544");
    }

    #[test]
    fn test_convert_well_known_sids() {
        // NT AUTHORITY\SYSTEM: the shortest and by far the most common form
        let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(convert_sid_to_string(&system).unwrap(), "S-1-5-18");

        // The null SID, whose identifier authority is zero
        let null = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(convert_sid_to_string(&null).unwrap(), "S-1-0-0");

        // A high mandatory level label
        let high = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x30, 0, 0];
        assert_eq!(convert_sid_to_string(&high).unwrap(), "S-1-16-12288");

        // A domain user, i.e. the longest shape seen in practice
        let user = [
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xE8, 0x03, 0, 0, 0xD0, 0x07, 0, 0, 0xB8, 0x0B, 0,
            0, 0xE9, 0x03, 0, 0,
        ];
        assert_eq!(
            convert_sid_to_string(&user).unwrap(),
            "S-1-5-21-1000-2000-3000-1001"
        );
    }

    #[test]
    fn test_convert_sid_with_large_identifier_authority() {
        // An authority that does not fit in four bytes is printed in hexadecimal, and Windows
        // does not pad it (checked against `ConvertSidToStringSidA` on Windows 10 22H2)
        let sid = [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(convert_sid_to_string(&sid).unwrap(), "S-1-0x100000000-1");
        let sid = [1, 1, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 1, 0, 0, 0];
        assert_eq!(convert_sid_to_string(&sid).unwrap(), "S-1-0xabcdef012345-1");
    }

    #[test]
    fn the_longest_possible_sid_fits_inline() {
        // Every field at its maximum: an authority too large for decimal, and the most
        // sub-authorities `IsValidSid` accepts, each the longest a `u32` can be
        let mut sid = vec![
            SID_REVISION,
            SID_MAX_SUB_AUTHORITIES as u8,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ];
        sid.resize(SID_HEADER_SIZE + 4 * SID_MAX_SUB_AUTHORITIES, 0xFF);

        let text = format_sid(&sid);
        assert!(text.as_str().starts_with("S-1-0xffffffffffff-4294967295-"));
        assert_eq!(text.as_str().len(), 183);
        assert!(text.as_str().len() <= SID_STRING_MAX_LEN);
    }

    #[test]
    fn test_sid_size() {
        assert_eq!(sid_size(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]), Ok(12));
        // Only the header is needed to know the size
        assert_eq!(sid_size(&[1, 5]), Ok(28));
        assert_eq!(sid_size(&[1, 15]), Ok(68));
        assert!(sid_size(&[1]).is_err());
        assert!(sid_size(&[2, 1]).is_err());
        assert!(sid_size(&[1, 16]).is_err());
    }

    #[test]
    fn test_reject_malformed_sids() {
        // Too short to even hold a header
        assert!(convert_sid_to_string(&[1, 1, 0, 0, 0, 0, 0]).is_err());

        // Declares a sub-authority that the buffer does not contain
        assert!(convert_sid_to_string(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0]).is_err());

        // Declares more sub-authorities than a SID can hold
        assert!(convert_sid_to_string(&[1, 16, 0, 0, 0, 0, 0, 5]).is_err());

        // Not a revision Windows accepts: `ConvertSidToStringSidA` rejects this too, rather than
        // formatting it as "S-2-5-18"
        assert!(convert_sid_to_string(&[2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).is_err());
    }
}
