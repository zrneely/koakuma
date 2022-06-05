use windows::core::HRESULT;

use std::{ffi::NulError, fmt};

#[derive(Debug)]
pub enum Error {
    CStringNul(NulError),
    LookupPrivilegeValueFailed(HRESULT),
    GetSelfProcessTokenFailed(HRESULT),
    AdjustTokenPrivilegesFailed(HRESULT),
    FindFirstVolumeFailed(HRESULT),
    FindNextVolumeFailed(HRESULT),
    GetVolumePathNamesFailed(HRESULT),
    OpenVolumeHandleFailed(HRESULT),
    MissingNullTerminator,
    GetNtfsVolumeDataFailed(HRESULT),
    UnknownNtfsVersion,
    GetNtfsVolumeDataBadSize,
    OpenMftFailed(HRESULT),
    GetRetrievalPointersFailed(HRESULT),
    ReadVolumeFailed(HRESULT),
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
