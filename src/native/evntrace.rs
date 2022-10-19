//! Native API - Event Tracing evntrace header
//!
//! The `evntrace` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the crate level provide a safe API to interact
//! with the crate
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use windows::Win32::System::Diagnostics::Etw::EVENT_CONTROL_CODE_ENABLE_PROVIDER;
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_STOP;
use windows::core::GUID;
use windows::core::PCWSTR;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::Diagnostics::Etw::TRACE_QUERY_INFO_CLASS;
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::Foundation::ERROR_CTX_CLOSE_PENDING;
use windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;


use super::etw_types::*;
use crate::provider::Provider;
use crate::provider::event_filter::EventFilterDescriptor;
use crate::trace::{CallbackData, TraceProperties, TraceTrait};
use crate::traits::*;

/// Evntrace native module errors
#[derive(Debug)]
pub enum EvntraceNativeError {
    /// Represents an Invalid Handle Error
    InvalidHandle,
    /// Represents an ERROR_ALREADY_EXISTS
    AlreadyExist,
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<EvntraceNativeError> for EvntraceNativeError {}

impl From<std::io::Error> for EvntraceNativeError {
    fn from(err: std::io::Error) -> Self {
        EvntraceNativeError::IoError(err)
    }
}

pub(crate) type EvntraceNativeResult<T> = Result<T, EvntraceNativeError>;

extern "system" fn trace_callback_thunk(p_record: *mut Etw::EVENT_RECORD) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let record_from_ptr = unsafe {
            // Safety: lifetime is valid at least until the end of the callback. A correct lifetime will be attached when we pass the reference to the child function
            EventRecord::from_ptr(p_record)
        };

        if let Some(event_record) = record_from_ptr {
            let p_user_context = event_record.user_context().cast::<CallbackData>();
            let user_context = unsafe {
                // Safety:
                //  * the API of this create guarantees this points to a `TraceData` already created
                //  * TODO: the API of this create guarantees this `TraceData` has not been dropped
                //  * TODO: the API of this crate does not guarantee this `TraceData` is not mutated during the trace (e.g. modifying the list of providers)
                p_user_context.as_ref()
            };
            if let Some(user_context) = user_context {
                user_context.on_event(event_record);
            }
        }
    })) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("UNIMPLEMENTED PANIC: {e:?}");
            std::process::exit(1);
        }
    }
}

fn filter_invalid_session_handles(h: TraceHandle) -> Option<TraceHandle> {
    // See https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew#return-value
    // We're conservative and we always filter out u32::MAX, although it could be valid on 64-bit setups.
    // But it turns out runtime detection of the current OS bitness is not that easy. Plus, it is not clear whether this depends on how the architecture the binary is compiled for, or the actual OS architecture.
    if h == INVALID_TRACE_HANDLE || h == u64::MAX || h == u32::MAX as u64 {
        None
    } else {
        Some(h)
    }
}

fn filter_invalid_registration_handles(h: TraceHandle) -> Option<TraceHandle> {
    // The session handle is 0 if the handle is not valid.
    // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
    if h == 0 {
        None
    } else {
        Some(h)
    }
}

/// Represents ETW tracing sessions
///
/// Microsoft wisely designed an API that has tons of similar-looking functions, that all operate on "trace", mixing the concepts of controller and providers.
/// All of them operate on "handle"s that are actually from two different kinds, and that should not be mixed.
/// There's the StartTrace/ControlTrace/EnableTraceEx family, and the OpenTrace/CloseTrace/ProcessTrace.
/// It looks simple. The first one is related to controller, the second to consumer, and the only link between both is the trace name.
/// Wait no, Actually, EnableTraceEx operates on "controller" handles but enable callbacks to consume data.
/// And also, StartTraceW needs to know provider flags (I'm a exaggerating slightly here, in reality it _could_ not need it, but this would require adding more complexity later by calling ControlTrace to set these flags when we enable providers)
///
/// I spent quite some time to try to make a right API that separates both, but I couldn't.
/// So, I threw all them in this struct. Don't try to open the hood. It works but it's very ugly.
///
/// Ah, yeah, also:
/// * some functions are deprecated but that's not documented everywhere.
/// * see https://caseymuratori.com/blog_0025, appearently I'm not the first one who lost quite some time trying to figure out how this marvellous API is supposed to be used.
pub(crate) struct NativeEtw {
    info: EventTraceProperties,
    /// Handle used by StartTrace, ControlTrace
    registration_handle: Option<TraceHandle>,

    /// Handle used by OpenTrace, ProcessTrace, CloseTrace
    subscription: Option<(TraceHandle, Box<CallbackData>)>,
}

impl std::fmt::Debug for NativeEtw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEtw")
            .field("subscribed", &self.subscription.is_some())
            .field("info", &self.info)
            .finish()
    }
}

impl NativeEtw {
    /// Create a new session.
    ///
    /// This calls `StartTraceW`
    pub fn start<T>(trace_name: &str, properties: &TraceProperties, callback_data: &CallbackData) -> EvntraceNativeResult<Self>
    where
        T: TraceTrait
    {
        let mut info = EventTraceProperties::new::<T>(trace_name, properties, callback_data.provider_flags::<T>());

        let mut registration_handle = TraceHandle::default();
        let status = unsafe {
            // Safety:
            //  * first argument points to a valid and allocated address (this is an output and will be modified)
            //  * second argument is a valid, null terminated widestring (note that it will be copied to the EventTraceProperties...from where it already comes. This will probably be overwritten by Windows, but heck.)
            //  * third argument is a valid, allocated EVENT_TRACE_PROPERTIES (and will be mutated)
            //  * Note: the size of the string (that will be overwritten to itself) ends with a null widechar before the end of its buffer (see EventTraceProperties::new())
            Etw::StartTraceW(
                &mut registration_handle,
                PCWSTR::from_raw(info.trace_name_array().as_ptr()),
                info.as_mut_ptr(),
            )
        };

        if status == ERROR_ALREADY_EXISTS.0 {
            return Err(EvntraceNativeError::AlreadyExist);
        } else if status != 0 {
            return Err(EvntraceNativeError::IoError(
                std::io::Error::from_raw_os_error(status as i32),
            ));
        }

        let registration_handle = filter_invalid_registration_handles(registration_handle);
        if registration_handle.is_none() {
            Err(EvntraceNativeError::InvalidHandle)
        } else {
            Ok(Self {
                info,
                registration_handle,
                subscription: None, // Will be populated when calling OpenTrace
            })
        }
    }

    /// Returns session handle if is is valid, None otherwise
    fn session_handle(&self) -> Option<TraceHandle> {
        self.subscription.as_ref().and_then(|s| filter_invalid_session_handles(s.0))
    }

    /// Returns the registration handle of this session if is is valid, None otherwise
    fn registration_handle(&self) -> Option<TraceHandle> {
        self.registration_handle.and_then(|s| filter_invalid_registration_handles(s))
    }


    /// Subscribe to a started trace
    ///
    /// Microsoft calls this "opening" the trace (and this calls `OpenTraceW`)
    pub fn open(&mut self, trace_name: &str, callback_data: Box<CallbackData>) -> EvntraceNativeResult<()> {
        if self.session_handle().is_some() {
            // That's probably possible to get multiple handles to the same trace, by opening them multiple times.
            // But that's left as a future TODO. Making things right and safe is difficult enough with a single opening of the trace already.
            return Err(EvntraceNativeError::AlreadyExist);
        }

        let mut log_file = EventTraceLogfile::create(&callback_data, trace_name, trace_callback_thunk);

        let session_handle = unsafe {
            // This function modifies the data pointed to by log_file.
            // This is fine because `as_mut_ptr()` takes a `&mut self`, and its call is wraps the call to `OpenTraceA`.
            //
            // > On success, OpenTrace will update the structure with information from the opened file or session.
            // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracea
            Etw::OpenTraceW(log_file.as_mut_ptr())
        };

        if filter_invalid_session_handles(session_handle).is_none() {
            Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()))
        } else {
            self.subscription = Some((session_handle, callback_data));
            Ok(())
        }
    }

    /// Attach a provider to this trace
    pub fn enable_provider(&mut self, provider: &Provider, parameters: &EnableTraceParameters) -> EvntraceNativeResult<()> {
        match self.registration_handle() {
            None => Err(EvntraceNativeError::InvalidHandle),
            Some(registration_handle) => {
                let owned_event_filter_descriptors: Vec<EventFilterDescriptor> = provider.filters()
                    .iter()
                    .filter_map(|filter| filter.to_event_filter_descriptor().ok()) // Silently ignoring invalid filters (basically, empty ones)
                    .collect();

                let parameters =
                    EnableTraceParameters::create(provider.guid(), provider.trace_flags(), &owned_event_filter_descriptors);

                let res = unsafe {
                    Etw::EnableTraceEx2(
                        registration_handle,
                        &provider.guid() as *const GUID,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                        provider.level(),
                        provider.any(),
                        provider.all(),
                        0,
                        parameters.as_ptr(),
                    )
                };

                if res == ERROR_SUCCESS.0 {
                    Ok(())
                } else {
                    Err(
                        EvntraceNativeError::IoError(
                            std::io::Error::from_raw_os_error(res as i32)
                        )
                    )
                }
            }
        }
    }

    /// Start processing a trace (this call is blocking until the trace is stopped)
    ///
    /// You probably want to spawn a thread that will block on this call.
    pub fn process(&self) -> EvntraceNativeResult<()> {
        match self.session_handle() {
            None => Err(EvntraceNativeError::InvalidHandle),
            Some(handle) => {
                if let Some((_, callback_data)) = self.subscription.as_ref() {
                    callback_data.reset_events_handled();
                }

                let mut now = FILETIME::default();
                let result = unsafe {
                    GetSystemTimeAsFileTime(&mut now);
                    Etw::ProcessTrace(&[handle], &mut now, std::ptr::null_mut())
                };

                if result == ERROR_SUCCESS.0 {
                    Ok(())
                } else {
                    Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()))
                }
            },
        }
    }

    /// Call `ControlTraceW` on the trace
    ///
    /// # Notes
    ///
    /// In case you want to close the trace, you probably want to drop the instance rather than calling `control(EVENT_TRACE_CONTROL_STOP)` yourself,
    /// because closing the trace makes the registration handle invalid.
    /// A closed trace could theoretically(?) be re-used, but the registration handle should be re-created, so `open` should be called again.
    fn control(
        &mut self,
        control_code: EvenTraceControl,
    ) -> EvntraceNativeResult<()> {
        match self.registration_handle() {
            None => return Err(EvntraceNativeError::InvalidHandle),
            Some(reg_handle) => {
                let status = unsafe {
                    // Safety:
                    //  * the registration handle is valid (by construction)
                    //  * depending on the control code, the `Properties` can be mutated
                    //    note that the PCWSTR also points to this mutable instance, but the PCWSTR is an input-only (hence constant) parameter
                    Etw::ControlTraceW(
                        reg_handle,
                        PCWSTR::null(),
                        self.info.as_mut_ptr(),
                        control_code,
                    )
                };

                if status != 0 && status != ERROR_WMI_INSTANCE_NOT_FOUND.0 {
                    return Err(EvntraceNativeError::IoError(
                        std::io::Error::from_raw_os_error(status as i32),
                    ));
                }

                if control_code == EVENT_TRACE_CONTROL_STOP {
                    // Stopping the trace invalidates the session_handle
                    self.registration_handle = None;
                }

                Ok(())
            }
        }

    }

    /// Close the trace
    ///
    /// It is suggested to stop the trace immediately after `close`ing it (that's what it done in the `impl Drop`), because I'm not sure how sensible it is to call other methods (apart from `stop`) afterwards
    fn close(&mut self) -> EvntraceNativeResult<()> {
        match self.session_handle() {
            None => Err(EvntraceNativeError::InvalidHandle),
            Some(session_handle) => {
                let status = unsafe {
                    Etw::CloseTrace(session_handle)
                };

                if status != ERROR_SUCCESS.0 && status != ERROR_CTX_CLOSE_PENDING.0 {
                    Err(EvntraceNativeError::IoError(
                        std::io::Error::from_raw_os_error(status as i32),
                    ))
                } else {
                    self.subscription = None;
                    Ok(())
                }
            },
        }
    }
}

impl Drop for NativeEtw {
    fn drop(&mut self) {
        // Close the trace
        let _ignored_error_in_the_impl_drop = self.close();

        // Stop the trace
        let _ignored_error_in_the_impl_drop = self.control(EVENT_TRACE_CONTROL_STOP);
    }
}

/// Queries the system for system-wide ETW information (that does not require an active session).
pub(crate) fn query_info(class: TraceInformation, buf: &mut [u8]) -> EvntraceNativeResult<()> {
    match unsafe {
        Etw::TraceQueryInformation(
            0,
            TRACE_QUERY_INFO_CLASS(class as i32),
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            std::ptr::null_mut(),
        )
    } {
        0 => Ok(()),
        e => Err(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(e as i32),
        )),
    }
}
