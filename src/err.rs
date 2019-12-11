use winapi::shared::minwindef::DWORD;

use std::ffi::NulError;

#[derive(Debug)]
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
    FsctlEnumUsnDataResultTooSmall,
    TimeConversionFailure(DWORD),
    InvalidTimeRepr,
    UnknownUsnRecordVersion,
    FsctlEnumUsnDataFailed(DWORD),
    UsnRecordBadLength,
    UsnRecordBadFilenameLength,
}
impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::CStringNulError(err)
    }
}
