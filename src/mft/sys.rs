use crate::{
    err::Error,
    mft::{parse_segment_number, parse_string},
};

use chrono::{DateTime, TimeZone as _, Utc};
use uuid::Uuid;
use winapi::{
    shared::{guiddef::GUID, minwindef::FILETIME},
    um::{errhandlingapi as ehapi, minwinbase::SYSTEMTIME, timezoneapi::FileTimeToSystemTime},
};

use std::{convert::TryInto as _, ffi::OsString};

const MULTI_SECTOR_HEADER_SIGNATURE: [u8; 4] = [b'F', b'I', b'L', b'E'];
pub struct MultiSectorHeader {
    pub signature: [u8; 4],
    pub update_sequence_array_offset: u16,
    pub update_sequence_array_size: u16,
}
pub const MULTI_SECTOR_HEADER_LEN: usize = 8;
impl MultiSectorHeader {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        if buf[0..4] != MULTI_SECTOR_HEADER_SIGNATURE {
            println!("Bad signature: {:?}", &buf[0..4]);
            return Err(Error::BadMultiSectorHeaderSignature);
        }

        let header = MultiSectorHeader {
            signature: [buf[0], buf[1], buf[2], buf[3]],
            update_sequence_array_offset: u16::from_le_bytes([buf[4], buf[5]]),
            update_sequence_array_size: u16::from_le_bytes([buf[6], buf[7]]),
        };
        Ok(header)
    }
}

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

pub mod segment_header_flags {
    pub const FILE_RECORD_SEGMENT_IN_USE: u16 = 0x0001;
    // pub const FILE_NAME_INDEX_PRESENT: u16 = 0x0002;
}

pub struct FileRecordSegmentHeader {
    pub multi_sector_header: MultiSectorHeader,
    pub log_file_sequence_number: u64,
    pub sequence_number: u16, // epoch-like counter used to track uses of the file
    pub hard_link_count: u16,
    pub first_attribute_offset: u16, // offset of the first attribute record
    pub flags: u16,
    pub used_size_of_file_record: u32,
    pub allocated_size_of_file_record: u32,
    pub base_file_record_segment: FileReference,
    pub next_attrib_id: u16,
    // reserved: u16,
    pub mft_record_num: u32,
}
impl FileRecordSegmentHeader {
    pub fn load(mut buf: &[u8]) -> Result<Self, Error> {
        let multi_sector_header = MultiSectorHeader::load(buf)?;
        buf = &buf[MULTI_SECTOR_HEADER_LEN..];

        let log_file_sequence_number = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        buf = &buf[8..];

        let sequence_number = u16::from_le_bytes([buf[0], buf[1]]);
        buf = &buf[2..];

        let hard_link_count = u16::from_le_bytes([buf[0], buf[1]]);
        buf = &buf[2..];

        let first_attribute_offset = u16::from_le_bytes([buf[0], buf[1]]);
        buf = &buf[2..];

        let flags = u16::from_le_bytes([buf[0], buf[1]]);
        buf = &buf[2..];

        let used_size_of_file_record = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf = &buf[4..];

        let allocated_size_of_file_record = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf = &buf[4..];

        let base_file_record_segment = FileReference::load(buf);
        buf = &buf[8..];

        let next_attrib_id = u16::from_le_bytes([buf[0], buf[1]]);
        buf = &buf[4..]; // skip 4 bytes, but only 2 are meaningful

        let mft_record_num = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        // buf = &buf[4..];

        let header = FileRecordSegmentHeader {
            multi_sector_header,
            log_file_sequence_number,
            sequence_number,
            hard_link_count,
            first_attribute_offset,
            flags,
            used_size_of_file_record,
            allocated_size_of_file_record,
            base_file_record_segment,
            next_attrib_id,
            mft_record_num,
        };

        Ok(header)
    }
}

pub mod attribute_types {
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

pub mod form_codes {
    pub const RESIDENT: u8 = 0;
    pub const NON_RESIDENT: u8 = 1;
}

pub struct AttributeRecordHeader {
    pub type_code: u32, // unspecified width, but due to padding it's effectively 32 bits
    pub record_length: u32,
    pub form_code: u8,
    pub name_length: u8, // attribute name, not file name
    pub name_offset: u16,
    pub flags: u16,
    pub instance: u16,
}
impl AttributeRecordHeader {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let header = AttributeRecordHeader {
            type_code: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            record_length: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            form_code: buf[8],
            name_length: buf[9],
            name_offset: u16::from_le_bytes([buf[10], buf[11]]),
            flags: u16::from_le_bytes([buf[12], buf[13]]),
            instance: u16::from_le_bytes([buf[14], buf[15]]),
        };

        (header, 16)
    }
}

pub struct AttributeRecordHeaderResident {
    pub value_length: u32,
    pub value_offset: u16,
    // reserved: [UCHAR; 2],
}
impl AttributeRecordHeaderResident {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let header = AttributeRecordHeaderResident {
            value_length: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            value_offset: u16::from_le_bytes([buf[4], buf[5]]),
            // reserved: [0, 0],
        };

        (header, 8)
    }
}

pub struct AttributeRecordHeaderNonResident {
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub mapping_pairs_offset: u16,
    pub compression_unit_size: u16,
    // reserved: u32,
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
            compression_unit_size: u16::from_le_bytes([buf[18], buf[19]]),
            // reserved: 0,
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
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_record_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub flags: StandardFlags,
}
impl StandardInformation {
    pub fn load(buf: &[u8], name: Option<OsString>) -> Result<Self, Error> {
        if buf.len() != 72 && buf.len() != 48 {
            return Err(Error::UnknownStandardInformationSize(buf.len()));
        }

        Ok(StandardInformation {
            name,
            created: parse_time(u64::from_le_bytes(buf[0..8].try_into().unwrap()))?,
            modified: parse_time(u64::from_le_bytes(buf[8..16].try_into().unwrap()))?,
            mft_record_modified: parse_time(u64::from_le_bytes(buf[16..24].try_into().unwrap()))?,
            accessed: parse_time(u64::from_le_bytes(buf[24..32].try_into().unwrap()))?,
            flags: u32::from_le_bytes(buf[32..36].try_into().unwrap()).into(),
        })
    }
}

pub const FILE_NAME_LENGTH: usize = 66; // sizeof(FileName)

#[derive(Debug, PartialEq)]
pub enum FileNameType {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
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
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_record_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
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
            parent: parse_segment_number(&FileReference::load(&buf[0..8])),
            created: parse_time(u64::from_le_bytes(buf[8..16].try_into().unwrap()))?,
            modified: parse_time(u64::from_le_bytes(buf[16..24].try_into().unwrap()))?,
            mft_record_modified: parse_time(u64::from_le_bytes(buf[24..32].try_into().unwrap()))?,
            accessed: parse_time(u64::from_le_bytes(buf[32..40].try_into().unwrap()))?,
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
}
impl Data {
    pub fn compute_allocated_size_bytes(&self, bytes_per_cluster: u64) -> u64 {
        let mut total_size = 0;
        if let Some(ref runs) = self.runs {
            for run in runs {
                total_size += run.cluster_count;
            }
        }
        total_size * bytes_per_cluster
    }
}

mod reparse_tag_flags {
    pub const IS_ALIAS: u32 = 0x2000_0000;
    pub const IS_HIGH_LATENCY: u32 = 0x4000_0000;
    pub const IS_MICROSOFT: u32 = 0x8000_0000;
}

#[derive(Debug)]
#[non_exhaustive]
pub struct ReparsePoint {
    pub name: Option<OsString>,
    pub tag: u32,
    pub length: u16,
    pub guid: Option<Uuid>,
    pub is_alias: bool,
    pub is_high_latency: bool,
    pub is_microsoft: bool,
}
impl ReparsePoint {
    pub fn load(buf: &[u8], name: Option<OsString>) -> Result<Self, Error> {
        if buf.len() < 8 {
            return Err(Error::UnknownReparseDataSize(buf.len()));
        }

        let tag = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let length = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        let guid = if (tag & reparse_tag_flags::IS_MICROSOFT) == 0 {
            Some(GUID {
                Data1: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
                Data2: u16::from_le_bytes(buf[12..14].try_into().unwrap()),
                Data3: u16::from_le_bytes(buf[14..16].try_into().unwrap()),
                Data4: buf[16..24].try_into().unwrap(),
            })
        } else {
            None
        };

        Ok(ReparsePoint {
            name,
            tag,
            length,
            guid: guid.map(Uuid::from_guid).transpose()?,
            is_alias: is_flag_set(tag, reparse_tag_flags::IS_ALIAS),
            is_high_latency: is_flag_set(tag, reparse_tag_flags::IS_HIGH_LATENCY),
            is_microsoft: is_flag_set(tag, reparse_tag_flags::IS_MICROSOFT),
        })
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

fn parse_time(time: u64) -> Result<DateTime<Utc>, Error> {
    let ftime = FILETIME {
        dwLowDateTime: (time & 0x0000_0000_FFFF_FFFF).try_into().unwrap(),
        dwHighDateTime: ((time & 0xFFFF_FFFF_0000_0000) >> 32).try_into().unwrap(),
    };
    let mut system_time = SYSTEMTIME::default();
    let result = unsafe { FileTimeToSystemTime(&ftime, &mut system_time) };
    if result == 0 {
        let err_code = unsafe { ehapi::GetLastError() };
        return Err(Error::TimeConversionFailure(err_code));
    }

    let local_result = Utc
        .ymd_opt(
            system_time.wYear.into(),
            system_time.wMonth.into(),
            system_time.wDay.into(),
        )
        .and_hms_milli_opt(
            system_time.wHour.into(),
            system_time.wMinute.into(),
            system_time.wSecond.into(),
            system_time.wMilliseconds.into(),
        );

    local_result.single().ok_or(Error::InvalidTimeRepr)
}

fn is_flag_set(data: u32, flag: u32) -> bool {
    (data & flag) != 0
}
