use winapi::{
    shared::minwindef::DWORD,
    um::winbase::{FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM},
};

use std::{convert::TryInto as _, ffi::NulError, fmt, ptr};

fn msg_from_error(err: DWORD) -> Option<String> {
    let mut buf = vec![0u8; 1024];

    let len = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM,
            ptr::null(),
            err,
            0,
            buf.as_mut_ptr() as *mut i8,
            buf.len().try_into().unwrap(),
            ptr::null_mut(),
        )
    };
    let len = len.try_into().ok()?;
    if len == 0 || len > buf.len() {
        return None;
    }

    let string_bytes = &buf[..len];
    let string = String::from_utf8_lossy(string_bytes).trim().into();
    Some(string)
}

pub enum Error {
    CStringNulError(NulError),
    LookupPrivilegeValueFailed(DWORD),
    GetSelfProcessTokenFailed(DWORD),
    AdjustTokenPrivilegesFailed(DWORD),
    FindFirstVolumeFailed(DWORD),
    FindNextVolumeFailed(DWORD),
    GetVolumePathNamesFailed(DWORD),
    OpenVolumeHandleFailed(DWORD),
    MissingNullTerminator,
    // FsctlEnumUsnDataResultTooSmall,
    // TimeConversionFailure(DWORD),
    // InvalidTimeRepr,
    // UnknownUsnRecordVersion,
    // FsctlEnumUsnDataFailed(DWORD),
    // UsnRecordBadLength,
    // UsnRecordBadFilenameLength,
    // OpenHandleForSizeFailed(DWORD),
    // GetFileInformationFailed(DWORD),
    // FileStreamInfoBadNextEntry,
    GetNtfsVolumeDataFailed(DWORD),
    UnknownNtfsVersion,
    GetNtfsVolumeDataBadSize,
    OpenMftFailed(DWORD),
    GetRetrievalPointersFailed(DWORD),
    ReadVolumeFailed(DWORD),
}
impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::CStringNulError(err)
    }
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        <Error as std::fmt::Debug>::fmt(self, fmt)
    }
}
impl std::fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        let (text, code, name) = match self {
            CStringNulError(_) => (None, None, "CStringNulError"),
            LookupPrivilegeValueFailed(code) => (
                msg_from_error(*code),
                Some(*code),
                "LookupPrivilegeValueFailed",
            ),
            GetSelfProcessTokenFailed(code) => (
                msg_from_error(*code),
                Some(*code),
                "GetSelfProcessTokenFailed",
            ),
            AdjustTokenPrivilegesFailed(code) => (
                msg_from_error(*code),
                Some(*code),
                "AdjustTokenPrivilegesFailed",
            ),
            FindFirstVolumeFailed(code) => {
                (msg_from_error(*code), Some(*code), "FindFirstVolumeFailed")
            }
            FindNextVolumeFailed(code) => {
                (msg_from_error(*code), Some(*code), "FindNextVolumeFailed")
            }
            GetVolumePathNamesFailed(code) => (
                msg_from_error(*code),
                Some(*code),
                "GetVolumePathNamesFailed",
            ),
            OpenVolumeHandleFailed(code) => {
                (msg_from_error(*code), Some(*code), "OpenVolumeHandleFailed")
            }
            MissingNullTerminator => (None, None, "MissingNullTerminator"),
            // FsctlEnumUsnDataResultTooSmall => (None, None, "FsctlEnumUsnDataResultTooSmall"),
            // TimeConversionFailure(code) => {
            //     (msg_from_error(*code), Some(*code), "TimeConversionFailure")
            // }
            // InvalidTimeRepr => (None, None, "InvalidTimeRepr"),
            // UnknownUsnRecordVersion => (None, None, "UnknownUsnRecordVersion"),
            // FsctlEnumUsnDataFailed(code) => {
            //     (msg_from_error(*code), Some(*code), "FsctlEnumUsnDataFailed")
            // }
            // UsnRecordBadLength => (None, None, "UsnRecordBadLength"),
            // UsnRecordBadFilenameLength => (None, None, "UsnRecordBadFilenameLength"),
            // OpenHandleForSizeFailed(code) => (
            //     msg_from_error(*code),
            //     Some(*code),
            //     "OpenHandleForSizeFailed",
            // ),
            // GetFileInformationFailed(code) => (
            //     msg_from_error(*code),
            //     Some(*code),
            //     "GetFileInformationFailed",
            // ),
            // FileStreamInfoBadNextEntry => (None, None, "FileStreamInfoBadNextEntry"),
            GetNtfsVolumeDataFailed(code) => (
                msg_from_error(*code),
                Some(*code),
                "GetNtfsVolumeDataFailed",
            ),
            UnknownNtfsVersion => (None, None, "UnknownNtfsVersion"),
            GetNtfsVolumeDataBadSize => (None, None, "GetNtfsVolumeDataBadSize"),
            OpenMftFailed(code) => (msg_from_error(*code), Some(*code), "OpenMftFailed"),
            GetRetrievalPointersFailed(code) => (
                msg_from_error(*code),
                Some(*code),
                "GetRetrievalPointersFailed",
            ),
            ReadVolumeFailed(code) => (msg_from_error(*code), Some(*code), "ReadVolumeFailed"),
        };

        match (text, code) {
            (Some(text), Some(code)) => fmt.debug_tuple(name).field(&text).field(&code).finish(),
            (None, Some(code)) => fmt.debug_tuple(name).field(&code).finish(),
            (_, _) => fmt.debug_tuple(name).finish(),
        }
    }
}
