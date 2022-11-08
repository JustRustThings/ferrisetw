//! Abstraction layer for Native functions and types
//!
//! This module interacts with the Windows native functions and should abstract all `unsafe` calls
pub mod etw_types;
pub(crate) mod evntrace;
pub(crate) mod pla;
pub(crate) mod sddl;
pub(crate) mod tdh;
pub(crate) mod tdh_types;
pub(crate) mod version_helper;

// These are used in our custom error types, and must be part of the public API
pub use evntrace::EvntraceNativeError;
pub use pla::PlaError;
pub use sddl::SddlNativeError;
pub use tdh::TdhNativeError;

// These are returned by some of our public APIs
pub use etw_types::DecodingSource;
pub use evntrace::ControlHandle;
pub use evntrace::TraceHandle;
