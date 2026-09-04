//! ETW Types Parser
//!
//! This module act as a helper to parse the Buffer from an ETW Event

use crate::native::etw_types::event_record::EventRecord;
use crate::native::sddl;
use crate::native::tdh;
use crate::native::tdh_types::{
    Property, PropertyCount, PropertyInfo, PropertyLength, TdhInType, TdhOutType,
};
use crate::native::time::{FileTime, SystemTime};
use crate::property::PropertySlice;
use crate::schema::Schema;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::core::GUID;

/// Parser module errors
#[derive(Debug)]
pub enum ParserError {
    /// No property has this name
    NotFound,
    /// An invalid type
    InvalidType,
    /// Error parsing
    ParseError,
    /// Length mismatch when parsing a type
    LengthMismatch,
    PropertyError(String),
    /// An error while transforming an Utf-8 buffer into String
    Utf8Error(std::str::Utf8Error),
    /// An error trying to get an slice as an array
    SliceError(std::array::TryFromSliceError),
    /// Represents an internal [SddlNativeError](crate::native::SddlNativeError)
    SddlNativeError(crate::native::SddlNativeError),
    /// Represents an internal [TdhNativeError](crate::native::TdhNativeError)
    TdhNativeError(crate::native::TdhNativeError),
}

impl From<crate::native::TdhNativeError> for ParserError {
    fn from(err: crate::native::TdhNativeError) -> Self {
        ParserError::TdhNativeError(err)
    }
}

impl From<crate::native::SddlNativeError> for ParserError {
    fn from(err: crate::native::SddlNativeError) -> Self {
        ParserError::SddlNativeError(err)
    }
}

impl From<std::str::Utf8Error> for ParserError {
    fn from(err: std::str::Utf8Error) -> Self {
        ParserError::Utf8Error(err)
    }
}

impl From<std::array::TryFromSliceError> for ParserError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        ParserError::SliceError(err)
    }
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::InvalidType => write!(f, "invalid type"),
            Self::ParseError => write!(f, "parse error"),
            Self::LengthMismatch => write!(f, "length mismatch"),
            Self::PropertyError(s) => write!(f, "property error {}", s),
            Self::Utf8Error(e) => write!(f, "utf-8 error {}", e),
            Self::SliceError(e) => write!(f, "slice error {}", e),
            Self::SddlNativeError(e) => write!(f, "sddl native error {}", e),
            Self::TdhNativeError(e) => write!(f, "tdh native error {}", e),
        }
    }
}

type ParserResult<T> = Result<T, ParserError>;

/// How many property slices a [`CachedSlices`] holds without touching the heap
///
/// Most events have a handful of properties, but the ones we care most about do not: on Windows
/// 10 22H2, Microsoft-Windows-Threat-Intelligence events have 18 properties at the median and 42
/// at most, and Windows Defender and Kernel-General events also reach 42. This covers all of them,
/// and all but 5 of the 51,230 manifest event schemas registered on that system, for 1.5 KiB of
/// stack per parser. (`smallvec` only supports a few sizes above 32; 64 is the next one.)
const INLINE_PROPERTIES: usize = 64;

/// Cache of the properties we've extracted already
///
/// This is useful because computing their offset can be costly
struct CachedSlices<'schema, 'record> {
    /// The properties extracted so far, in schema order
    ///
    /// `slices[i]` is the slice of the event's `i`th property. Keeping them in order (rather than
    /// in a map keyed by name) means this doubles as the count of properties parsed so far, and
    /// lets a property that refers to a sibling by index find it (see `indexed_property_value`).
    ///
    /// The inline capacity keeps this cache -- which is rebuilt for every single event -- off the
    /// heap; see [`INLINE_PROPERTIES`] for how it was chosen.
    slices: SmallVec<[PropertySlice<'schema, 'record>; INLINE_PROPERTIES]>,
    /// The user buffer index we've cached up to
    last_cached_offset: usize,
}

impl<'schema, 'record> CachedSlices<'schema, 'record> {
    /// Look for an already extracted property by name
    ///
    /// This is a linear scan, but events have few properties, and it saves hashing (and owning) a
    /// name for every one of them.
    fn get(&self, name: &str) -> Option<PropertySlice<'schema, 'record>> {
        self.slices
            .iter()
            .find(|slice| slice.property.name == name)
            .copied()
    }
}

/// Read the value of the `index`th property of this event out of the cache, as a count of things
///
/// Returns `None` if that property has not been extracted yet (which happens when it comes _after_
/// the one being sized), or if it does not hold an integer we can read.
fn indexed_property_value(cached: &CachedSlices<'_, '_>, index: u16) -> Option<usize> {
    let slice = cached.slices.get(usize::from(index))?;

    let in_type = match slice.property.info {
        PropertyInfo::Value { in_type, .. } => in_type,
        // An array does not hold a single length or count
        PropertyInfo::Array { .. } => return None,
    };

    let value: i64 = match (in_type, slice.buffer) {
        (TdhInType::InTypeInt8, &[a]) => i8::from_ne_bytes([a]).into(),
        (TdhInType::InTypeUInt8, &[a]) => a.into(),
        (TdhInType::InTypeInt16, &[a, b]) => i16::from_ne_bytes([a, b]).into(),
        (TdhInType::InTypeUInt16, &[a, b]) => u16::from_ne_bytes([a, b]).into(),
        (TdhInType::InTypeInt32, &[a, b, c, d]) => i32::from_ne_bytes([a, b, c, d]).into(),
        (TdhInType::InTypeUInt32, &[a, b, c, d]) => u32::from_ne_bytes([a, b, c, d]).into(),
        // Not an integer, or not as wide as its type claims: we cannot read a count out of it
        _ => return None,
    };

    // A negative length is nonsense: let the caller fall back to TDH rather than make one up
    usize::try_from(value).ok()
}

/// Resolve a property length that the manifest expressed as a reference to a sibling property
///
/// Some manifests declare the length of a field by naming another field of the same event, e.g.
/// the WinInet provider has `<data name="Verb" inType="win:AnsiString" length="_VerbLength"/>`.
/// The referenced field precedes the one being sized, so it has already been extracted into
/// `cached`, and reading it from there saves a `TdhGetPropertySize` call for every such property
/// of every event. (Its value belongs to the record, not to the schema, so there is nothing to
/// memoise across events -- only this lookup to avoid.)
///
/// Returns `None` unless the length is unambiguously a number of bytes, because
/// `EVENT_PROPERTY_INFO::length` counts *characters* for string types: for those, TDH is the one
/// that knows how to turn the sibling's value into a size.
fn indexed_property_length(
    in_type: TdhInType,
    cached: &CachedSlices<'_, '_>,
    index: u16,
) -> Option<usize> {
    match in_type {
        // A byte count
        TdhInType::InTypeBinary => (),
        // One byte per character, so the same thing
        TdhInType::InTypeAnsiString => (),
        _ => return None,
    }

    indexed_property_value(cached, index)
}

/// Size of the counted string at the start of `buffer`: a 16-bit byte count, then that many bytes
///
/// The count is little-endian for the plain counted types and big-endian for the "reversed" ones.
fn counted_size(buffer: &[u8], big_endian: bool) -> Option<usize> {
    let prefix = [*buffer.first()?, *buffer.get(1)?];
    let count = if big_endian {
        u16::from_be_bytes(prefix)
    } else {
        u16::from_le_bytes(prefix)
    };
    Some(2 + usize::from(count))
}

/// Cross-check of the parser's property sizes against TDH (diagnostic builds only)
///
/// With the `shadow_tdh` feature, every size [`Parser`] works out for itself is also asked of
/// `TdhGetPropertySize`, and disagreements are counted and described. This is how the shortcuts in
/// `compute_property_size` were validated against real events; it is far too slow for anything else.
#[cfg(feature = "shadow_tdh")]
pub mod shadow_tdh {
    use super::ParserResult;
    use crate::native::etw_types::event_record::EventRecord;
    use crate::native::tdh;
    use crate::native::tdh_types::{Property, PropertyInfo, TdhInType};
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::sync::Mutex;
    use std::time::Instant;

    static CHECKED: AtomicU64 = AtomicU64::new(0);
    static MISMATCHES: AtomicU64 = AtomicU64::new(0);
    static NEW_RULE_TYPES: AtomicU64 = AtomicU64::new(0);
    static TDH_FALLBACKS: AtomicU64 = AtomicU64::new(0);
    static TDH_NS: AtomicU64 = AtomicU64::new(0);
    static DETAILS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// What the cross-check has seen since the last [`reset`]
    #[derive(Debug, Clone)]
    pub struct Stats {
        /// Property sizes compared
        pub checked: u64,
        /// ... of which disagreed with TDH
        pub mismatches: u64,
        /// ... of which were of a type the parser only recently learnt to size itself
        /// (SIDs and counted strings)
        pub new_rule_types: u64,
        /// Sizes the parser could not work out and asked TDH for (not counting the cross-check)
        pub tdh_fallbacks: u64,
        /// Time spent in `TdhGetPropertySize` for the cross-check
        pub tdh_ns: u64,
        /// The first few disagreements, described
        pub details: Vec<String>,
    }

    pub fn stats() -> Stats {
        Stats {
            checked: CHECKED.load(Relaxed),
            mismatches: MISMATCHES.load(Relaxed),
            new_rule_types: NEW_RULE_TYPES.load(Relaxed),
            tdh_fallbacks: TDH_FALLBACKS.load(Relaxed),
            tdh_ns: TDH_NS.load(Relaxed),
            details: DETAILS.lock().map(|d| d.clone()).unwrap_or_default(),
        }
    }

    pub fn reset() {
        for counter in [
            &CHECKED,
            &MISMATCHES,
            &NEW_RULE_TYPES,
            &TDH_FALLBACKS,
            &TDH_NS,
        ] {
            counter.store(0, Relaxed);
        }
        if let Ok(mut details) = DETAILS.lock() {
            details.clear();
        }
    }

    pub(super) fn note_fallback() {
        TDH_FALLBACKS.fetch_add(1, Relaxed);
    }

    pub(super) fn check(record: &EventRecord, property: &Property, ours: &ParserResult<usize>) {
        let started = Instant::now();
        let theirs = tdh::property_size(record, &property.name_utf16);
        TDH_NS.fetch_add(started.elapsed().as_nanos() as u64, Relaxed);
        CHECKED.fetch_add(1, Relaxed);

        let in_type = match property.info {
            PropertyInfo::Value { in_type, .. } | PropertyInfo::Array { in_type, .. } => in_type,
        };
        if matches!(
            in_type,
            TdhInType::InTypeSid
                | TdhInType::InTypeWbemSid
                | TdhInType::InTypeCountedString
                | TdhInType::InTypeCountedAnsiString
                | TdhInType::InTypeReversedCountedString
                | TdhInType::InTypeReversedCountedAnsiString
        ) {
            NEW_RULE_TYPES.fetch_add(1, Relaxed);
        }

        let agree = match (ours, &theirs) {
            (Ok(ours), Ok(theirs)) => *ours == *theirs as usize,
            (Err(_), Err(_)) => true,
            _ => false,
        };
        if !agree {
            MISMATCHES.fetch_add(1, Relaxed);
            if let Ok(mut details) = DETAILS.lock() {
                if details.len() < 16 {
                    details.push(format!(
                        "provider {:?} event {} v{} property {:?} ({:?}): ours={:?} tdh={:?}",
                        record.provider_id(),
                        record.event_id(),
                        record.version(),
                        property.name,
                        in_type,
                        ours.as_ref().map_err(|e| e.to_string()),
                        theirs.map_err(|e| e.to_string()),
                    ));
                }
            }
        }
    }
}

/// Represents a Parser
///
/// This structure provides a way to parse an ETW event (= extract its properties).
/// Because properties may have variable length (e.g. strings), a `Parser` is only suited to a single [`EventRecord`]
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::Parser;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///
///     // There are several ways to define the type requested for `try_parse`
///     // It is possible to use type inference...
///     let property1: Option<String> = parser.try_parse("PropertyName").ok();
///
///     // ...or to use the turbofish operator
///     match parser.try_parse::<u32>("OtherPropertyName") {
///         Ok(_) => println!("OtherPropertyName is a valid u32"),
///         Err(_) => println!("OtherPropertyName is invalid"),
///     }
/// };
/// ```
// `Parser` is intentionally `!Sync` via `RefCell`. ETW's `ProcessTrace` delivers events
// sequentially on a single thread, so a `Parser` is always created and consumed within a single
// callback invocation and is never shared across threads.
#[allow(dead_code)]
pub struct Parser<'schema, 'record> {
    properties: &'schema [Property],
    record: &'record EventRecord,
    cache: RefCell<CachedSlices<'schema, 'record>>,
}

impl<'schema, 'record> Parser<'schema, 'record> {
    /// Use the `create` function to create an instance of a Parser
    ///
    /// # Arguments
    /// * `schema` - The [Schema] from the ETW Event we want to parse
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// # use ferrisetw::parser::Parser;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let parser = Parser::create(record, &schema);
    /// };
    /// ```
    // Inlined so that the caller builds the parser in place: it is 1.5 KiB because of the inline
    // property cache, and moving it out of a non-inlined call would cost a memcpy larger than the
    // allocation that cache saves (measured: 68 ns vs 15 ns per event).
    #[inline]
    pub fn create(event_record: &'record EventRecord, schema: &'schema Schema) -> Self {
        let properties = schema.properties();
        Parser {
            record: event_record,
            properties,
            cache: RefCell::new(CachedSlices {
                // The event has at most this many properties, so the cache never has to grow.
                // Below the inline capacity this does not allocate at all.
                slices: SmallVec::with_capacity(properties.len()),
                last_cached_offset: 0,
            }),
        }
    }

    /// Ask TDH for the size of a property we were not able to size ourselves
    ///
    /// This costs a syscall, so it is only a last resort.
    fn tdh_property_size(&self, property: &Property) -> ParserResult<usize> {
        #[cfg(feature = "shadow_tdh")]
        shadow_tdh::note_fallback();
        Ok(tdh::property_size(self.record, &property.name_utf16)? as usize)
    }

    /// Size, in bytes, of `property` in this record
    fn find_property_size(
        &self,
        property: &Property,
        remaining_user_buffer: &[u8],
        cached: &CachedSlices<'schema, 'record>,
    ) -> ParserResult<usize> {
        let size = self.compute_property_size(property, remaining_user_buffer, cached);
        #[cfg(feature = "shadow_tdh")]
        shadow_tdh::check(self.record, property, &size);
        size
    }

    #[allow(clippy::len_zero)]
    fn compute_property_size(
        &self,
        property: &Property,
        remaining_user_buffer: &[u8],
        cached: &CachedSlices<'schema, 'record>,
    ) -> ParserResult<usize> {
        match property.info {
            PropertyInfo::Value {
                in_type, length, ..
            } => {
                // There are several cases
                //  * regular case, where property.len() directly makes sense
                //  * but EVENT_PROPERTY_INFO.length is an union, and (in its lengthPropertyIndex form) can refeer to another field
                //    e.g.: the WinInet provider manifest has fields such as `<data name="Verb" inType="win:AnsiString" length="_VerbLength"/>`
                //    In this case, we read that other field out of the cache, and only defer to
                //    TDH when we cannot (see `indexed_property_length`).

                // For pointer input type we can immediately infer the size based on the header flags.
                if in_type == TdhInType::InTypePointer {
                    return Ok(self.record.pointer_size());
                }

                let prop_len = match length {
                    PropertyLength::Length(l) => l,
                    PropertyLength::Index(index) => {
                        return match indexed_property_length(in_type, cached, index) {
                            Some(l) => Ok(l),
                            // We cannot work out the length ourselves, defer to TDH
                            None => self.tdh_property_size(property),
                        };
                    }
                };

                if prop_len > 0 {
                    return Ok(prop_len as usize);
                }

                // Length is not set. We'll have to ask TDH for the right length.
                // However, before doing so, there are some cases where we could determine ourselves.
                // The following _very_ common property types can be short-circuited to prevent the expensive call.
                // (that's taken from krabsetw)

                match in_type {
                    TdhInType::InTypeAnsiString => {
                        let mut l = 0;
                        for char in remaining_user_buffer {
                            if char == &0 {
                                l += 1; // include the final null byte
                                break;
                            }
                            l += 1;
                        }
                        return Ok(l);
                    }
                    TdhInType::InTypeUnicodeString => {
                        let mut l = 0;
                        for bytes in remaining_user_buffer.chunks_exact(2) {
                            if bytes[0] == 0 && bytes[1] == 0 {
                                l += 2;
                                break;
                            }
                            l += 2;
                        }
                        return Ok(l);
                    }
                    // A SID says in its own header how many sub-authorities it has. A header
                    // that is not well-formed falls through to TDH, which fails as it always has.
                    TdhInType::InTypeSid => {
                        if let Ok(size) = sddl::sid_size(remaining_user_buffer) {
                            return Ok(size);
                        }
                    }
                    // A TOKEN_USER -- two pointer-sized fields, in the event's pointer size --
                    // precedes the SID. This is how the kernel logger's Process events carry it.
                    TdhInType::InTypeWbemSid => {
                        let skip = 2 * self.record.pointer_size();
                        if let Some(Ok(size)) =
                            remaining_user_buffer.get(skip..).map(sddl::sid_size)
                        {
                            return Ok(skip + size);
                        }
                    }
                    // A 16-bit byte count, then the string
                    TdhInType::InTypeCountedString | TdhInType::InTypeCountedAnsiString => {
                        if let Some(size) = counted_size(remaining_user_buffer, false) {
                            return Ok(size);
                        }
                    }
                    TdhInType::InTypeReversedCountedString
                    | TdhInType::InTypeReversedCountedAnsiString => {
                        if let Some(size) = counted_size(remaining_user_buffer, true) {
                            return Ok(size);
                        }
                    }
                    _ => (),
                }

                self.tdh_property_size(property)
            }
            PropertyInfo::Array {
                in_type,
                length,
                count,
                ..
            } => {
                // For pointer input type we can immediately infer the size based on the header flags.
                let prop_len = if in_type == TdhInType::InTypePointer {
                    self.record.pointer_size()
                } else {
                    match length {
                        PropertyLength::Length(l) => l as usize,
                        // This is the length of a single element: it still has to be multiplied by
                        // the number of elements below
                        PropertyLength::Index(index) => {
                            match indexed_property_length(in_type, cached, index) {
                                Some(l) => l,
                                None => return self.tdh_property_size(property),
                            }
                        }
                    }
                };

                let prop_count = match count {
                    PropertyCount::Count(c) => c as usize,
                    PropertyCount::Index(index) => match indexed_property_value(cached, index) {
                        Some(c) => c,
                        None => return self.tdh_property_size(property),
                    },
                };

                if prop_len > 0 {
                    // Both of these may come from the record rather than from the schema, so they
                    // are not to be trusted: saturate instead of overflowing, and let the bounds
                    // check on the user buffer reject the result.
                    return Ok(prop_len.saturating_mul(prop_count));
                }

                self.tdh_property_size(property)
            }
        }
    }

    fn find_property(&self, name: &str) -> ParserResult<PropertySlice<'schema, 'record>> {
        let mut cache = self.cache.borrow_mut();

        let last_cached_property = cache.slices.len();

        // Callers usually walk an event's properties in schema order, so the one being asked for
        // is very often the one right after the last extracted -- which cannot be in the cache.
        // Recognising that costs a single comparison, where searching the cache first costs one
        // per property already extracted, i.e. quadratically many over the whole event.
        //
        // Note that it cannot be returned right away: its slice of the record is not known until
        // it has been sized. The loop below does exactly that, starting with this very property,
        // and returns it as soon as it is extracted.
        let wanted_is_next = self
            .properties
            .get(last_cached_property)
            .is_some_and(|property| property.name == name);

        if !wanted_is_next {
            // We may have extracted this property already
            if let Some(p) = cache.get(name) {
                return Ok(p);
            }
        }

        let properties_not_parsed_yet = match self.properties.get(last_cached_property..) {
            Some(s) => s,
            // If we've parsed every property already, that means no property matches this name
            None => return Err(ParserError::NotFound),
        };

        for property in properties_not_parsed_yet {
            let remaining_user_buffer =
                match self.record.user_buffer().get(cache.last_cached_offset..) {
                    None => {
                        return Err(ParserError::PropertyError(
                            "Invalid buffer bounds".to_owned(),
                        ))
                    }
                    Some(s) => s,
                };

            let prop_size = self.find_property_size(property, remaining_user_buffer, &cache)?;
            let property_buffer = match remaining_user_buffer.get(..prop_size) {
                None => {
                    return Err(ParserError::PropertyError(
                        "Property length out of buffer bounds".to_owned(),
                    ))
                }
                Some(s) => s,
            };

            let prop_slice = PropertySlice {
                property,
                buffer: property_buffer,
            };
            cache.slices.push(prop_slice);
            cache.last_cached_offset += prop_size;

            if property.name == name {
                return Ok(prop_slice);
            }
        }

        Err(ParserError::NotFound)
    }

    /// Return a property from the event, or an error in case the parsing failed.
    ///
    /// You must explicitly define `T`, the type you want to parse the property into.<br/>
    /// In case this type is not compatible with the ETW type, [`ParserError::InvalidType`] is returned.
    pub fn try_parse<T>(&self, name: &str) -> ParserResult<T>
    where
        Parser<'schema, 'record>: private::TryParse<T>,
    {
        use crate::parser::private::TryParse;
        self.try_parse_impl(name)
    }
}

mod private {
    use super::*;

    /// Trait to try and parse a type
    ///
    /// This trait has to be implemented in order to be able to parse a type we want to retrieve from
    /// within an Event.
    ///
    /// An implementation for most of the Primitive Types is created by using a Macro, any other needed type
    /// requires this trait to be implemented
    pub trait TryParse<T> {
        /// Implement the `try_parse` function to provide a way to Parse `T` from an ETW event or
        /// return an Error in case the type `T` can't be parsed
        ///
        /// # Arguments
        /// * `name` - Name of the property to be found in the Schema
        fn try_parse_impl(&self, name: &str) -> Result<T, ParserError>;
    }
}

macro_rules! impl_try_parse_primitive {
    ($T:ident) => {
        impl private::TryParse<$T> for Parser<'_, '_> {
            fn try_parse_impl(&self, name: &str) -> ParserResult<$T> {
                let prop_slice = self.find_property(name)?;

                match prop_slice.property.info {
                    PropertyInfo::Value { .. } => {
                        // TODO: Check In and Out type and do a better type checking
                        if std::mem::size_of::<$T>() != prop_slice.buffer.len() {
                            return Err(ParserError::LengthMismatch);
                        }
                        Ok($T::from_ne_bytes(prop_slice.buffer.try_into()?))
                    }
                    _ => Err(ParserError::InvalidType),
                }
            }
        }
    };
}

macro_rules! impl_try_parse_primitive_array {
    ($T:ident) => {
        impl<'schema, 'record> private::TryParse<&'record [$T]> for Parser<'schema, 'record> {
            fn try_parse_impl(&self, name: &str) -> ParserResult<&'record [$T]> {
                let prop_slice = self.find_property(name)?;

                match prop_slice.property.info {
                    PropertyInfo::Array { .. } => {
                        // TODO: Check In and Out type and do a better type checking

                        // This property type has not been tested yet as I don't have a
                        // provider that uses it. It's possible that the buffer is not
                        // aligned correctly, which would cause this to fail.
                        let size = std::mem::size_of::<$T>();
                        let align = std::mem::align_of::<$T>();

                        if prop_slice.buffer.len() % size != 0 {
                            return Err(ParserError::LengthMismatch);
                        }

                        let count = prop_slice.buffer.len() / size;

                        if prop_slice.buffer.as_ptr() as usize % align != 0 {
                            return Err(ParserError::PropertyError(
                                "buffer alignment mismatch".into(),
                            ));
                        }

                        if size.checked_mul(count).is_none() || (size * count) > isize::MAX as usize
                        {
                            return Err(ParserError::PropertyError("size overflow".into()));
                        }

                        let slice = unsafe {
                            std::slice::from_raw_parts(
                                prop_slice.buffer.as_ptr() as *const $T,
                                count,
                            )
                        };

                        Ok(slice)
                    }
                    _ => Err(ParserError::InvalidType),
                }
            }
        }
    };
}

impl_try_parse_primitive!(u8);
impl_try_parse_primitive!(i8);
impl_try_parse_primitive!(u16);
impl_try_parse_primitive!(i16);
impl_try_parse_primitive!(u32);
impl_try_parse_primitive!(i32);
impl_try_parse_primitive!(u64);
impl_try_parse_primitive!(i64);
impl_try_parse_primitive!(f32);
impl_try_parse_primitive!(f64);

impl_try_parse_primitive_array!(u16);
impl_try_parse_primitive_array!(i16);
impl_try_parse_primitive_array!(u32);
impl_try_parse_primitive_array!(i32);
impl_try_parse_primitive_array!(u64);
impl_try_parse_primitive_array!(i64);

/// Decode a nul-terminated UTF-16 property into a `String`
///
/// The record's buffer is not aligned for `u16`, so the code units are read out of it pair by pair
/// rather than through a slice cast -- there is no need for an aligned copy, the decoder takes any
/// iterator. The `String` is reserved at one byte per code unit: that is exact for ASCII, which is
/// what property strings (paths, names, keys) almost always are, so the common case is a single
/// allocation of the right size. Non-ASCII text needs up to 1.5x that and grows once.
fn utf16_property_to_string(bytes: &[u8]) -> ParserResult<String> {
    if bytes.len() % 2 != 0 {
        return Err(ParserError::PropertyError(
            "odd length in bytes for a wide string".into(),
        ));
    }

    // Drop the nul terminator if there is one: strings whose length the manifest declares do not
    // carry one, so it cannot be assumed. Only one is dropped, as has always been the case here.
    let bytes = match bytes {
        [head @ .., 0, 0] => head,
        _ => bytes,
    };

    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]));

    let mut out = String::with_capacity(bytes.len() / 2);
    out.extend(widestring::decode_utf16_lossy(units));
    Ok(out)
}

/// The `String` impl of the `TryParse` trait should be used to retrieve the following [TdhInTypes]:
///
/// * InTypeUnicodeString
/// * InTypeAnsiString
/// * InTypeCountedString
/// * InTypeGuid
///
/// On success a `String` with the with the data from the `name` property will be returned
///
/// # Arguments
/// * `name` - Name of the property to be found in the Schema
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::Parser;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///     let image_name: String = parser.try_parse("ImageName").unwrap();
/// };
/// ```
///
/// [TdhInTypes]: TdhInType
impl private::TryParse<String> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<String> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => match in_type {
                TdhInType::InTypeUnicodeString => utf16_property_to_string(prop_slice.buffer),
                TdhInType::InTypeAnsiString => {
                    let string = std::str::from_utf8(prop_slice.buffer)?;
                    Ok(string.trim_matches(char::default()).to_string())
                }
                TdhInType::InTypeSid => Ok(sddl::convert_sid_to_string(prop_slice.buffer)?),
                TdhInType::InTypeWbemSid => {
                    // Skip the TOKEN_USER in front of the SID
                    let sid = prop_slice
                        .buffer
                        .get(2 * self.record.pointer_size()..)
                        .ok_or(ParserError::LengthMismatch)?;
                    Ok(sddl::convert_sid_to_string(sid)?)
                }
                // Skip the 16-bit count in front of the string
                TdhInType::InTypeCountedString | TdhInType::InTypeReversedCountedString => {
                    let string = prop_slice
                        .buffer
                        .get(2..)
                        .ok_or(ParserError::LengthMismatch)?;
                    utf16_property_to_string(string)
                }
                TdhInType::InTypeCountedAnsiString | TdhInType::InTypeReversedCountedAnsiString => {
                    let string = prop_slice
                        .buffer
                        .get(2..)
                        .ok_or(ParserError::LengthMismatch)?;
                    Ok(std::str::from_utf8(string)?
                        .trim_matches(char::default())
                        .to_string())
                }
                _ => Err(ParserError::InvalidType),
            },
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<GUID> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> Result<GUID, ParserError> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeGuid {
                    return Err(ParserError::InvalidType);
                }

                if prop_slice.buffer.len() != 16 {
                    return Err(ParserError::LengthMismatch);
                }

                Ok(GUID {
                    data1: u32::from_ne_bytes(prop_slice.buffer[0..4].try_into()?),
                    data2: u16::from_ne_bytes(prop_slice.buffer[4..6].try_into()?),
                    data3: u16::from_be_bytes(prop_slice.buffer[6..8].try_into()?),
                    data4: prop_slice.buffer[8..].try_into()?,
                })
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<IpAddr> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<IpAddr> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { out_type, .. } => {
                if out_type != TdhOutType::OutTypeIpv4 && out_type != TdhOutType::OutTypeIpv6 {
                    return Err(ParserError::InvalidType);
                }

                // Hardcoded values for now
                let res = match prop_slice.buffer.len() {
                    16 => {
                        let tmp: [u8; 16] = prop_slice.buffer.try_into()?;
                        IpAddr::V6(Ipv6Addr::from(tmp))
                    }
                    4 => {
                        let tmp: [u8; 4] = prop_slice.buffer.try_into()?;
                        IpAddr::V4(Ipv4Addr::from(tmp))
                    }
                    _ => return Err(ParserError::LengthMismatch),
                };

                Ok(res)
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<bool> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<bool> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeBoolean {
                    return Err(ParserError::InvalidType);
                }

                match prop_slice.buffer.len() {
                    1 => Ok(prop_slice.buffer[0] != 0),
                    4 => Ok(u32::from_ne_bytes(prop_slice.buffer.try_into()?) != 0),
                    8 => Ok(u64::from_ne_bytes(prop_slice.buffer.try_into()?) != 0),
                    _ => Err(ParserError::LengthMismatch),
                }
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<FileTime> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<FileTime> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeFileTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(FileTime::from_slice(prop_slice.buffer.try_into()?))
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<SystemTime> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<SystemTime> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeSystemTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(SystemTime::from_slice(prop_slice.buffer.try_into()?))
            }
            _ => Err(ParserError::InvalidType),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Pointer(usize);

impl std::ops::Deref for Pointer {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Pointer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::LowerHex for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::LowerHex::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl std::fmt::UpperHex for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::UpperHex::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl std::fmt::Display for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::Display::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl private::TryParse<Pointer> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<Pointer> {
        let prop_slice = self.find_property(name)?;

        let mut res = Pointer::default();
        if prop_slice.buffer.len() == std::mem::size_of::<u32>() {
            res.0 = private::TryParse::<u32>::try_parse_impl(self, name)? as usize;
        } else {
            res.0 = private::TryParse::<u64>::try_parse_impl(self, name)? as usize;
        }

        Ok(res)
    }
}

impl private::TryParse<Vec<u8>> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> Result<Vec<u8>, ParserError> {
        let prop_slice = self.find_property(name)?;
        Ok(prop_slice.buffer.to_vec())
    }
}

// TODO: Implement SocketAddress
// TODO: Study if we can use primitive types for HexInt64, HexInt32 and Pointer

#[cfg(test)]
mod test {
    use super::{counted_size, utf16_property_to_string};

    #[test]
    fn counted_string_size_is_prefix_plus_count() {
        let utf16_abc = [6, 0, b'a', 0, b'b', 0, b'c', 0];
        assert_eq!(counted_size(&utf16_abc, false), Some(8));
        let utf16_abc_big_endian_count = [0, 6, b'a', 0, b'b', 0, b'c', 0];
        assert_eq!(counted_size(&utf16_abc_big_endian_count, true), Some(8));
        // The size is taken from the prefix alone; the caller bounds-checks the body
        assert_eq!(counted_size(&[0xFF, 0xFF], false), Some(2 + 0xFFFF));
        assert_eq!(counted_size(&[6], false), None);
        assert_eq!(counted_size(&[], false), None);
    }

    fn utf16(s: &str, terminated: bool) -> Vec<u8> {
        let mut bytes: Vec<u8> = s
            .encode_utf16()
            .flat_map(|unit| unit.to_ne_bytes())
            .collect();
        if terminated {
            bytes.extend_from_slice(&[0, 0]);
        }
        bytes
    }

    #[test]
    fn decodes_ascii_with_and_without_terminator() {
        let path = "C:\\Windows\\System32\\ntdll.dll";
        assert_eq!(utf16_property_to_string(&utf16(path, true)).unwrap(), path);
        assert_eq!(
            utf16_property_to_string(&utf16("ImageName", false)).unwrap(),
            "ImageName"
        );
    }

    #[test]
    fn ascii_is_a_single_exact_allocation() {
        let decoded = utf16_property_to_string(&utf16("HKLM\\SOFTWARE\\Microsoft", true)).unwrap();
        assert_eq!(decoded.capacity(), decoded.len());
    }

    #[test]
    fn decodes_non_ascii() {
        for text in ["héllo wörld", "日本語", "🦀 crab"] {
            assert_eq!(utf16_property_to_string(&utf16(text, true)).unwrap(), text);
        }
    }

    #[test]
    fn unpaired_surrogate_is_replaced() {
        let mut bytes = utf16("ab", false);
        bytes.extend_from_slice(&0xD800u16.to_ne_bytes());
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(utf16_property_to_string(&bytes).unwrap(), "ab\u{FFFD}");
    }

    #[test]
    fn empty_and_terminator_only() {
        assert_eq!(utf16_property_to_string(&[]).unwrap(), "");
        assert_eq!(utf16_property_to_string(&[0, 0]).unwrap(), "");
    }

    #[test]
    fn only_one_terminator_is_stripped() {
        // Fixed-length fields are padded with nuls, which have always been kept: pin that
        let mut bytes = utf16("ab", true);
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(utf16_property_to_string(&bytes).unwrap(), "ab\0");
    }

    #[test]
    fn odd_length_is_an_error() {
        assert!(utf16_property_to_string(&[0x61, 0, 0x62]).is_err());
    }
}
