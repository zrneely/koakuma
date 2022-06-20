use windows::core::Error as WinError;

use std::{ffi::NulError, fmt};

#[derive(Debug, Clone)]
pub enum Error {
    CStringNul(NulError),
    LookupPrivilegeValueFailed(WinError),
    GetSelfProcessTokenFailed(WinError),
    AdjustTokenPrivilegesFailed(WinError),
    FindFirstVolumeFailed(WinError),
    FindNextVolumeFailed(WinError),
    GetVolumePathNamesFailed(WinError),
    GetVolumeNameFailed(WinError),
    OpenVolumeHandleFailed(WinError),
    MissingNullTerminator,
    GetNtfsVolumeDataFailed(WinError),
    UnknownNtfsVersion,
    GetNtfsVolumeDataBadSize,
    OpenMftFailed(WinError),
    GetRetrievalPointersFailed(WinError),
    ReadVolumeFailed(WinError),
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
    BadMultiSectorHeaderSignature,
    UpdateSequenceValidationFailed,
    AttributeListPointedToUnusedFileRecord,
    OperationCancelled,
    NoSuchNode,
    TreeNavigatedToFile,
}
impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::CStringNul(err)
    }
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        <Error as std::fmt::Debug>::fmt(self, fmt)
    }
}
