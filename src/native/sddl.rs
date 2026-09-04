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

/// The number of decimal digits `value` will be written as
fn decimal_len(value: u32) -> usize {
    // `checked_ilog10` is `None` for zero, which is written as one digit
    (value.checked_ilog10().unwrap_or(0) + 1) as usize
}

/// The number of hexadecimal digits `value` will be written as, without leading zeros
fn hex_len(value: u64) -> usize {
    // One digit per four bits; `checked_ilog2` is `None` for zero, which is written as one digit
    (value.checked_ilog2().unwrap_or(0) / 4 + 1) as usize
}

/// Append `value` in hexadecimal, without leading zeros
fn push_hex(out: &mut String, value: u64) {
    for digit in (0..hex_len(value)).rev() {
        let nibble = (value >> (4 * digit)) & 0xf;
        out.push(HEX_DIGITS[nibble as usize] as char);
    }
}

/// Append `value` in decimal
///
/// This is `write!(out, "{}", value)` without `core::fmt`, which is worth avoiding on a path that
/// runs for every SID-typed property of every event: the formatting machinery costs more than
/// everything else here put together.
fn push_decimal(out: &mut String, value: u32) {
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
        out.push(digits[len] as char);
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
/// The length is worked out before anything is written, so that `String` is allocated once and at
/// exactly the right size. Most SIDs on a given host are short well-known ones such as
/// `S-1-5-18`, so reserving an upper bound instead would multiply the bytes this churns.
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
    let (header, sub_authorities) = sid.split_at(SID_HEADER_SIZE);
    let revision = u32::from(header[0]);

    // The identifier authority is a six-byte big-endian number. Windows prints it in decimal when
    // it fits in four bytes -- which is the case for every authority in use -- and in hexadecimal,
    // without leading zeros, otherwise.
    let authority = u64::from_be_bytes([
        0, 0, header[2], header[3], header[4], header[5], header[6], header[7],
    ]);
    let decimal_authority = u32::try_from(authority).ok();

    // The sub-authorities are `u32`s, in the memory order of the record
    let sub_authorities = sub_authorities.chunks_exact(4).map(|sub_authority| {
        u32::from_ne_bytes([
            sub_authority[0],
            sub_authority[1],
            sub_authority[2],
            sub_authority[3],
        ])
    });

    let mut size = "S-".len() + decimal_len(revision);
    size += match decimal_authority {
        Some(value) => 1 + decimal_len(value),
        None => "-0x".len() + hex_len(authority),
    };
    for value in sub_authorities.clone() {
        size += 1 + decimal_len(value);
    }

    let mut out = String::with_capacity(size);
    out.push_str("S-");
    push_decimal(&mut out, revision);

    match decimal_authority {
        Some(value) => {
            out.push('-');
            push_decimal(&mut out, value);
        }
        None => {
            out.push_str("-0x");
            push_hex(&mut out, authority);
        }
    }

    for value in sub_authorities {
        out.push('-');
        push_decimal(&mut out, value);
    }

    debug_assert_eq!(out.len(), size, "the reserved size must be exact");
    Ok(out)
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
