use crate::{err::Error, mft::parse_string};

use std::{convert::TryInto as _, ffi::OsString};

const MULTI_SECTOR_HEADER_FILE_SIGNATURE: [u8; 4] = [b'F', b'I', b'L', b'E'];

#[derive(Debug)]
pub struct MultiSectorHeader {
    pub update_sequence_array_offset: u16,
    pub update_sequence_array_size: u16,
}
impl MultiSectorHeader {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        if buf[0..4] != MULTI_SECTOR_HEADER_FILE_SIGNATURE {
            return Err(Error::BadMultiSectorHeaderSignature);
        }

        let header = MultiSectorHeader {
            update_sequence_array_offset: u16::from_le_bytes([buf[4], buf[5]]),
            update_sequence_array_size: u16::from_le_bytes([buf[6], buf[7]]),
        };
        Ok(header)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FileReference {
    pub segment_number_low: u32,
    pub segment_number_high: u16,
    pub sequence_number: u16,
}
impl FileReference {
    pub fn load(buf: &[u8]) -> Self {
        FileReference {
            segment_number_low: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            segment_number_high: u16::from_le_bytes([buf[4], buf[5]]),
            sequence_number: u16::from_le_bytes([buf[6], buf[7]]),
        }
    }
}
impl From<FileReference> for u64 {
    fn from(reference: FileReference) -> u64 {
        ((reference.segment_number_high as u64) << 32) | (reference.segment_number_low as u64)
    }
}

mod segment_header_flags {
    pub const FILE_RECORD_SEGMENT_IN_USE: u16 = 0x0001;
}

pub struct FileRecordSegmentHeader {
    pub multi_sector_header: MultiSectorHeader,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16, // offset of the first attribute record
    pub base_file_record_segment: FileReference,
}
impl FileRecordSegmentHeader {
    // Returns Ok(None) if not in use
    pub fn load(buf: &[u8]) -> Result<Option<Self>, Error> {
        let multi_sector_header = MultiSectorHeader::load(&buf[..8])?;

        let flags = u16::from_le_bytes(buf[22..24].try_into().unwrap());
        if is_flag_set16(flags, segment_header_flags::FILE_RECORD_SEGMENT_IN_USE) {
            Ok(Some(FileRecordSegmentHeader {
                multi_sector_header,
                hard_link_count: u16::from_le_bytes(buf[18..20].try_into().unwrap()),
                first_attribute_offset: u16::from_le_bytes(buf[20..22].try_into().unwrap()),
                base_file_record_segment: FileReference::load(&buf[32..40]),
            }))
        } else {
            Ok(None)
        }
    }
}

mod attribute_types {
    // read-only, timestamps, hard link count, etc
    pub const STANDARD_INFORMATION: u32 = 0x10;
    // list of attributes that make up the file
    pub const ATTRIBUTE_LIST: u32 = 0x20;
    // one of the names of the file
    pub const FILE_NAME: u32 = 0x30;
    // if present, a 64-bit identifier assigned by a link-tracking service
    pub const OBJECT_ID: u32 = 0x40;
    // security descriptors (ACLs and DACLs)
    pub const SECURITY_DESCRIPTOR: u32 = 0x50;
    // volume label; only present on volume files
    pub const VOLUME_NAME: u32 = 0x60;
    // only present on volume files
    pub const VOLUME_INFORMATION: u32 = 0x70;
    // actual file content
    pub const DATA: u32 = 0x80;
    // used for filename allocation for large directories
    pub const INDEX_ROOT: u32 = 0x90;
    // used for filename allocation for large directories
    pub const INDEX_ALLOCATION: u32 = 0xA0;
    // bitmap index for a large directory
    pub const BITMAP: u32 = 0xB0;
    // reparse data
    pub const REPARSE_POINT: u32 = 0xC0;
    // used to implement extended attributes
    pub const EA_INFORMATION: u32 = 0xD0;
    pub const EA: u32 = 0xE0;
    // unknown; related to EFS; the same structure as DATA
    pub const LOGGED_UTILITY_STREAM: u32 = 0x100;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AttributeType {
    StandardInformation,
    AttributeList,
    FileName,
    ObjectId,
    SecurityDescriptor,
    VolumeName,
    VolumeInformation,
    Data,
    IndexRoot,
    IndexAllocation,
    Bitmap,
    ReparsePoint,
    EaInformation,
    Ea,
    LoggedUtilityStream,
}
impl std::convert::TryFrom<u32> for AttributeType {
    type Error = Error;

    fn try_from(val: u32) -> Result<Self, Error> {
        use attribute_types::*;
        use AttributeType::*;

        Ok(match val {
            STANDARD_INFORMATION => StandardInformation,
            ATTRIBUTE_LIST => AttributeList,
            FILE_NAME => FileName,
            OBJECT_ID => ObjectId,
            SECURITY_DESCRIPTOR => SecurityDescriptor,
            VOLUME_NAME => VolumeName,
            VOLUME_INFORMATION => VolumeInformation,
            DATA => Data,
            INDEX_ROOT => IndexRoot,
            INDEX_ALLOCATION => IndexAllocation,
            BITMAP => Bitmap,
            REPARSE_POINT => ReparsePoint,
            EA_INFORMATION => EaInformation,
            EA => Ea,
            LOGGED_UTILITY_STREAM => LoggedUtilityStream,

            _ => return Err(Error::UnknownAttributeTypeCode(val)),
        })
    }
}

pub mod form_codes {
    pub const RESIDENT: u8 = 0;
    pub const NON_RESIDENT: u8 = 1;
}

mod attribute_record_header_flags {
    pub const COMPRESSED: u16 = 0x0001;
    pub const ENCRYPTED: u16 = 0x4000;
    pub const SPARSE: u16 = 0x8000;
}

pub const ATTRIBUTE_RECORD_HEADER_LENGTH: usize = 16;
#[derive(Debug)]
pub struct AttributeRecordHeader {
    pub type_code: AttributeType, // unspecified width, but due to padding it's effectively 32 bits
    pub record_length: u32,
    pub form_code: u8,
    pub name_length: u8, // attribute name, not file name
    pub name_offset: u16,
    pub is_compressed: bool,
    pub is_encrypted: bool,
    pub is_sparse: bool,
    pub instance: u16,
}
impl AttributeRecordHeader {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        let flags = u16::from_le_bytes([buf[12], buf[13]]);

        Ok(AttributeRecordHeader {
            type_code: u32::from_le_bytes(buf[0..4].try_into().unwrap()).try_into()?,
            record_length: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            form_code: buf[8],
            name_length: buf[9],
            name_offset: u16::from_le_bytes([buf[10], buf[11]]),
            is_compressed: is_flag_set16(flags, attribute_record_header_flags::COMPRESSED),
            is_encrypted: is_flag_set16(flags, attribute_record_header_flags::ENCRYPTED),
            is_sparse: is_flag_set16(flags, attribute_record_header_flags::SPARSE),
            instance: u16::from_le_bytes([buf[14], buf[15]]),
        })
    }
}

#[derive(Debug)]
pub struct AttributeRecordHeaderResident {
    pub value_length: u32,
    pub value_offset: u16,
}
impl AttributeRecordHeaderResident {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let header = AttributeRecordHeaderResident {
            value_length: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            value_offset: u16::from_le_bytes([buf[4], buf[5]]),
        };

        (header, 8)
    }
}

pub struct AttributeRecordHeaderNonResident {
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub mapping_pairs_offset: u16,
    pub allocated_length: u64,
    pub file_size: u64,
    pub valid_data_length: u64,
}
impl AttributeRecordHeaderNonResident {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let header = AttributeRecordHeaderNonResident {
            lowest_vcn: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            highest_vcn: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            mapping_pairs_offset: u16::from_le_bytes([buf[16], buf[17]]),
            allocated_length: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            file_size: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            valid_data_length: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
        };

        (header, 48)
    }
}

mod standard_info_flags {
    pub const READ_ONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const ARCHIVE: u32 = 0x0020;
    pub const DEVICE: u32 = 0x0040;
    pub const NORMAL: u32 = 0x0080;
    pub const TEMPORARY: u32 = 0x0100;
    pub const SPARSE: u32 = 0x0200;
    pub const REPARSE_POINT: u32 = 0x0400;
    pub const COMPRESSED: u32 = 0x0800;
    pub const OFFLINE: u32 = 0x1000;
    pub const NOT_INDEXED: u32 = 0x2000;
    pub const ENCRYPTED: u32 = 0x4000;
    pub const DIRECTORY: u32 = 0x1000_0000;
    pub const INDEX_VIEW: u32 = 0x2000_0000;
}

#[derive(Debug)]
pub struct StandardFlags {
    pub is_read_only: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub is_archive: bool,
    pub is_device: bool,
    pub is_normal: bool,
    pub is_temporary: bool,
    pub is_sparse: bool,
    pub is_reparse_point: bool,
    pub is_compressed: bool,
    pub is_offline: bool,
    pub is_not_indexed: bool,
    pub is_encrypted: bool,
    pub is_directory: bool,
    pub is_index_view: bool,
}
impl From<u32> for StandardFlags {
    fn from(flags: u32) -> Self {
        StandardFlags {
            is_read_only: is_flag_set(flags, standard_info_flags::READ_ONLY),
            is_hidden: is_flag_set(flags, standard_info_flags::HIDDEN),
            is_system: is_flag_set(flags, standard_info_flags::SYSTEM),
            is_archive: is_flag_set(flags, standard_info_flags::ARCHIVE),
            is_device: is_flag_set(flags, standard_info_flags::DEVICE),
            is_normal: is_flag_set(flags, standard_info_flags::NORMAL),
            is_temporary: is_flag_set(flags, standard_info_flags::TEMPORARY),
            is_sparse: is_flag_set(flags, standard_info_flags::SPARSE),
            is_reparse_point: is_flag_set(flags, standard_info_flags::REPARSE_POINT),
            is_compressed: is_flag_set(flags, standard_info_flags::COMPRESSED),
            is_offline: is_flag_set(flags, standard_info_flags::OFFLINE),
            is_not_indexed: is_flag_set(flags, standard_info_flags::NOT_INDEXED),
            is_encrypted: is_flag_set(flags, standard_info_flags::ENCRYPTED),
            is_directory: is_flag_set(flags, standard_info_flags::DIRECTORY),
            is_index_view: is_flag_set(flags, standard_info_flags::INDEX_VIEW),
        }
    }
}

// read-only, timestamps, hard link count, etc
#[derive(Debug)]
#[non_exhaustive]
pub struct StandardInformation {
    pub name: Option<OsString>,
    pub flags: StandardFlags,
}
impl StandardInformation {
    pub fn load(buf: &[u8], name: Option<OsString>) -> Result<Self, Error> {
        if buf.len() != 72 && buf.len() != 48 {
            return Err(Error::UnknownStandardInformationSize(buf.len()));
        }

        Ok(StandardInformation {
            name,
            flags: u32::from_le_bytes(buf[32..36].try_into().unwrap()).into(),
        })
    }
}

pub const FILE_NAME_LENGTH: usize = 66; // sizeof(FileName)

mod filename_types {
    // up to 255 WTF-16 "code points"; case sensitive; only NUL and / aren't allowed.
    pub const POSIX: u8 = 0;
    // up to 255 WTF-16 "code points"; case insensitive; these characters aren't allowed:
    // "*+,/:;<=>?\
    // and it can't end with a period or a space.
    pub const WIN32: u8 = 1;
    // 8.3 name; only upper case english letters allowed.
    pub const DOS: u8 = 2;
    // when the win32 name fits in 8.3
    pub const WIN32_DOS: u8 = 3;
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub enum FileNameType {
    Posix,
    Win32,
    Win32AndDos,
    Dos,
}

// One of the names of the file.
// Note: the fields of this, except parent, are only updated by
// Windows when the file's name changes.
#[derive(Debug)]
#[non_exhaustive]
pub struct FileName {
    // name OF THE ATTRIBUTE, not the file name
    pub name: Option<OsString>,
    pub filename: OsString,
    pub filename_type: FileNameType,
    pub parent: u64,
    pub flags: StandardFlags,
    pub logical_size: u64,
    pub physical_size: u64,
    pub reparse_tag: u32,
}
impl FileName {
    pub fn load(buf: &[u8], name: Option<OsString>) -> Result<Self, Error> {
        if buf.len() < (FILE_NAME_LENGTH + 2) {
            return Err(Error::UnknownFilenameSize(buf.len()));
        }

        let name_len: usize = buf[64].into();
        let name_len = name_len * 2;
        let filename_bytes = &buf[FILE_NAME_LENGTH..FILE_NAME_LENGTH + name_len];
        let filename = parse_string(filename_bytes);

        Ok(FileName {
            name,
            filename,
            filename_type: match buf[65] {
                filename_types::POSIX => FileNameType::Posix,
                filename_types::WIN32 => FileNameType::Win32,
                filename_types::DOS => FileNameType::Dos,
                filename_types::WIN32_DOS => FileNameType::Win32AndDos,
                unknown => return Err(Error::UnknownFilenameType(unknown)),
            },
            parent: FileReference::load(&buf[0..8]).into(),
            logical_size: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            physical_size: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[56..60].try_into().unwrap()).into(),
            reparse_tag: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
        })
    }
}

#[derive(Debug)]
pub struct DataRun {
    pub starting_lcn: i64,
    pub cluster_count: u64,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Data {
    pub name: Option<OsString>,
    pub logical_size: u64,
    pub physical_size: u64,
    pub runs: Option<Vec<DataRun>>,
    pub is_sparse: bool,
}
impl Data {
    pub fn compute_allocated_size(&self, bytes_per_cluster: u64) -> u64 {
        let mut total_size = 0;
        if let Some(ref runs) = self.runs {
            for run in runs {
                // Sparse files (including placeholders) have extents starting at 0
                // (discovered through experimentation - is that documented anywhere?)
                if self.is_sparse && run.starting_lcn == 0 {
                    continue;
                }

                total_size += run.cluster_count;
            }
        }
        total_size * bytes_per_cluster
    }
}

pub struct AttributeListEntry {
    pub type_code: u32,
    pub record_length: u16,
    pub name_length: u8,
    pub name_offset: u8,
    pub starting_vcn: u64,
    pub segment_reference: FileReference,
    pub instance: u16,
}
pub const MIN_ATTRIBUTE_LIST_ENTRY_SIZE: usize = 26;
impl AttributeListEntry {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < MIN_ATTRIBUTE_LIST_ENTRY_SIZE {
            return Err(Error::UnknownAttributeListEntrySize(buf.len()));
        }

        Ok(AttributeListEntry {
            type_code: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            record_length: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            name_length: buf[6],
            name_offset: buf[7],
            starting_vcn: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            segment_reference: FileReference::load(&buf[16..24]),
            instance: u16::from_le_bytes(buf[24..26].try_into().unwrap()),
        })
    }
}

fn is_flag_set(data: u32, flag: u32) -> bool {
    (data & flag) != 0
}

fn is_flag_set16(data: u16, flag: u16) -> bool {
    (data & flag) != 0
}
