use winapi::shared::minwindef::DWORD;

use std::{ffi::NulError, fmt};

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
    TimeConversionFailure(DWORD),
    InvalidTimeRepr,
    GetNtfsVolumeDataFailed(DWORD),
    UnknownNtfsVersion,
    GetNtfsVolumeDataBadSize,
    OpenMftFailed(DWORD),
    GetRetrievalPointersFailed(DWORD),
    ReadVolumeFailed(DWORD),
    ReadVolumeTooShort,
    MftHasNoExtents,
    MftStartLcnNotFirstExtent,
    UnknownFormCode(u8),
    UnknownAttributeTypeCode(u32),
    UnknownFilenameType(u8),
    UnsupportedNonResident(crate::mft::sys::AttributeType),
    UnsupportedResident(crate::mft::sys::AttributeType),
    UnknownStandardInformationSize(usize),
    UnknownFilenameSize(usize),
    UnknownAttributeListEntrySize(usize),
    GuidParseError(uuid::Error),
    BadMultiSectorHeaderSignature,
    UnknownReparseDataSize(usize),
    UpdateSequenceValidationFailed,
    // UnknownIndexEntrySize(usize),
    // UnknownIndexNodeHeaderSize(usize),
    AttributeListPointedToUnusedFileRecord,
}
impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::CStringNulError(err)
    }
}
impl From<uuid::Error> for Error {
    fn from(err: uuid::Error) -> Self {
        Error::GuidParseError(err)
    }
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        <Error as std::fmt::Debug>::fmt(self, fmt)
    }
}
