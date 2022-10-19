//! ETW Tracing/Session abstraction
//!
//! Provides both a Kernel and User trace that allows to start an ETW session
use std::sync::atomic::{AtomicUsize, Ordering};

use super::traits::*;
use crate::native::etw_types::EventRecord;
use crate::native::{evntrace, version_helper};
use crate::provider::Provider;
use crate::{provider, utils};
use crate::schema_locator::SchemaLocator;
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw;

const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const SYSTEM_TRACE_CONTROL_GUID: &str = "9e814aad-3204-11d2-9a82-006008a86939";
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x02000000;

/// Trace module errors
#[derive(Debug)]
pub enum TraceError {
    /// Wrapper over an internal [EvntraceNativeError]
    ///
    /// [EvntraceNativeError]: crate::native::evntrace::EvntraceNativeError
    EtwNativeError(evntrace::EvntraceNativeError),
    /// Wrapper over an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<TraceError> for TraceError {}

impl From<std::io::Error> for TraceError {
    fn from(err: std::io::Error) -> Self {
        TraceError::IoError(err)
    }
}

impl From<evntrace::EvntraceNativeError> for TraceError {
    fn from(err: evntrace::EvntraceNativeError) -> Self {
        TraceError::EtwNativeError(err)
    }
}

type TraceResult<T> = Result<T, TraceError>;

/// Trace Properties struct
///
/// Keeps the ETW session configuration settings
///
/// [More info](https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings#configuring-the-etw-session)
#[derive(Debug, Copy, Clone, Default)]
pub struct TraceProperties {
    /// Represents the ETW Session in KB
    pub buffer_size: u32,
    /// Represents the ETW Session minimum number of buffers to use
    pub min_buffer: u32,
    /// Represents the ETW Session maximum number of buffers in the buffer pool
    pub max_buffer: u32,
    /// Represents the ETW Session flush interval in seconds
    pub flush_timer: u32,
    /// Represents the ETW Session [Logging Mode](https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
    pub log_file_mode: u32,
}

/// Data used (and mutated) by callbacks when the trace is running
#[derive(Debug, Default)]
pub struct CallbackData {
    /// Represents the current events handled
    events_handled: AtomicUsize,
    /// List of Providers associated with the Trace
    providers: Vec<provider::Provider>,
    schema_locator: SchemaLocator,
}

impl CallbackData {
    fn new() -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            providers: Vec::new(),
            schema_locator: SchemaLocator::new(),
        }
    }

    /// How many events have been handled so far
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    /// Reset the event counter
    pub fn reset_events_handled(&self) {
        self.events_handled.store(0, Ordering::Relaxed)
    }

    pub fn provider_flags<T: TraceTrait>(&self) -> Etw::EVENT_TRACE_FLAG {
        Etw::EVENT_TRACE_FLAG(T::enable_flags(&self.providers))
    }

    pub(crate) fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);

        // We need a mutable reference to be able to modify the data it refers, which is actually
        // done within the Callback (The schema locator is modified)
        for prov in &self.providers {
            // We can unwrap safely, provider builder wouldn't accept a provider without guid
            // so we must have Some(Guid)
            if prov.guid() == record.provider_id() {
                prov.on_event(record, &self.schema_locator);
            }
        }
    }
}

/// Base trait for a Trace
///
/// This trait define the general methods required to control an ETW Session
pub trait TraceBaseTrait {
    /// Start processing a Trace session
    ///
    /// # Note
    /// This function will spawn the new thread which starts listening for events.
    ///
    /// See [ProcessTrace](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace#remarks)
    fn process(self) -> TraceResult<Self>
    where
        Self: Sized;

}

/// Specific trait for a Trace
///
/// This trait defines the specific methods that differentiate from a Kernel to a User Trace
pub trait TraceTrait: TraceBaseTrait {
    fn augmented_file_mode() -> u32 {
        0
    }
    fn enable_flags(_providers: &[Provider]) -> u32 {
        0
    }
    fn trace_guid() -> GUID {
        GUID::new().unwrap_or(GUID::zeroed())
    }
}

// Hyper Macro to create an impl of the BaseTrace for the Kernel and User Trace
macro_rules! impl_base_trace {
    (for $($t: ty),+) => {
        $(impl TraceBaseTrait for $t {
            fn process(self) -> TraceResult<Self> {
                self.etw.reset_event_counter();
                self.etw.process()?;

                Ok(self)
            }

            // query_stats
            // set_default_event_callback
            // buffers_processed
        })*
    }
}

impl_base_trace!(for UserTrace, KernelTrace);
impl TraceTrait for UserTrace {}

// TODO: Implement enable_provider function for providers that require call to TraceSetInformation with extended PERFINFO_GROUPMASK
impl TraceTrait for KernelTrace {
    fn augmented_file_mode() -> u32 {
        if version_helper::is_win8_or_greater() {
            EVENT_TRACE_SYSTEM_LOGGER_MODE
        } else {
            0
        }
    }

    fn enable_flags(providers: &[Provider]) -> u32 {
        providers.iter().fold(0, |acc, x| acc | x.kernel_flags())
    }

    fn trace_guid() -> GUID {
        if version_helper::is_win8_or_greater() {
            GUID::new().unwrap_or(GUID::zeroed())
        } else {
            GUID::from(SYSTEM_TRACE_CONTROL_GUID)
        }
    }
}




/// A user trace session
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
pub struct UserTrace {
    etw: evntrace::NativeEtw,
}

/// A kernel trace session
///
/// To stop the session, you can drop this instance
///
#[derive(Debug)]
pub struct KernelTrace {
    etw: evntrace::NativeEtw,
}

pub struct UserTraceBuilder {
    name: String,
    properties: TraceProperties,
    callback_data: CallbackData,
}
pub struct KernelTraceBuilder {
    name: String,
    properties: TraceProperties,
    callback_data: CallbackData,
}

impl UserTrace {
    /// Create a UserTrace builder
    pub fn new() -> UserTraceBuilder {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        UserTraceBuilder {
            name,
            callback_data: CallbackData::new(),
            properties: TraceProperties::default(),
        }
    }
}

impl KernelTrace {
    /// Create a KernelTrace builder
    pub fn new() -> KernelTraceBuilder {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        KernelTraceBuilder {
            name,
            callback_data: CallbackData::new(),
            properties: TraceProperties::default(),
        }
    }
}

impl UserTraceBuilder {
    pub fn named(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    pub fn set_trace_properties(mut self, props: TraceProperties) -> Self {
        self.properties = props;
        self
    }

    /// # Note
    /// Windows API seems to support removing providers, or changing its properties when the session is processing events (see https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)
    /// Currently, this crate only supports defining Providers and their settings when building the trace, because it is easier to ensure memory-safety this way.
    /// It probably would be possible to support changing Providers when the trace is processing, but this is left as a TODO.
    pub fn enable(mut self, provider: Provider) -> Self {
        self.callback_data.providers.push(provider);
        self
    }

    /// Build the `UserTrace` and start the trace session
    ///
    /// Windows APIs would call this `Open` the trace.
    /// You'll still have to call [`UserTrace::process`] to start receiving events
    pub fn start(self) -> TraceResult<UserTrace> {
        let callback_data = Box::new(self.callback_data);
        let mut etw = evntrace::NativeEtw::start::<UserTrace>(
            &self.name,
            &self.properties,
            &callback_data)?;

        for prov in &callback_data.providers {
            etw.enable_provider(prov)?;
            // Note: in case this fails for a provider, we ignore the following providers
        }

        etw.open(&self.name, callback_data)?;

        Ok(UserTrace {
            etw,
        })
    }
}

impl KernelTraceBuilder {
    /// On Windows Versions older than Win8 this method won't change the trace name. In those versions the trace name need to be set to "NT Kernel Logger", that's handled by the module
    pub fn named(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    pub fn set_trace_properties(mut self, props: TraceProperties) -> Self {
        self.properties = props;
        self
    }

    //
    //
    // TODO: write some doc
    //
    /// # Note
    /// Windows API seems to support removing providers, or changing its properties when the session is processing events (see https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)
    /// Currently, this crate only supports defining Providers and their settings when building the trace, because it is easier to ensure memory-safety this way.
    /// It probably would be possible to support changing Providers when the trace is processing, but this is left as a TODO.
    pub fn enable(mut self, provider: Provider) -> Self {
        self.callback_data.providers.push(provider);
        self
    }

    /// Build the `KernelTrace`
    ///
    /// Windows APIs would call this `Open` the trace.
    /// You'll still have to call [`KernelTrace::process`] to start receiving events
    //
    //
    //
    // name if build? start?
    pub fn start(self) -> TraceResult<KernelTrace> {
        let callback_data = Box::new(self.callback_data);
        let mut etw = evntrace::NativeEtw::start::<KernelTrace>(
            &self.name,
            &self.properties,
            &callback_data)?;

        let session_name = if version_helper::is_win8_or_greater() {
            &self.name
        } else {
            KERNEL_LOGGER_NAME
        };

        // TODO: Implement enable_provider function for providers that require call to TraceSetInformation with extended PERFINFO_GROUPMASK

        etw.open(session_name, callback_data)?;

        Ok(KernelTrace {
            etw,
        })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_enable_multiple_providers() {
        let prov = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716").build();
        let prov1 = Provider::by_guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A").build();

        let trace = UserTrace::new().enable(prov).enable(prov1);

        assert_eq!(trace.callback_data.providers.len(), 2);
    }
}
