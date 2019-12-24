use crate::err::Error;

use winapi::shared::guiddef::GUID;

use std::convert::TryInto as _;

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

pub mod standard_info_flags {
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

pub mod filename_types {
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

// note: the fields of this, except parent_directory, are only updated by
// windows when the file's name changes.
pub struct FileName {
    pub parent_directory: FileReference,
    pub date_created: u64,
    pub date_modified: u64,
    pub date_mft_record_modified: u64,
    pub date_accessed: u64,
    pub logical_file_size: u64,
    pub size_on_disk: u64,
    pub flags: u32, // the same as the standard info flags
    pub reparse_tag: u32,
    pub filename_length: u8,
    pub filename_type: u8,
}
pub const FILE_NAME_LENGTH: usize = 66; // sizeof(FileName)
impl FileName {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < (FILE_NAME_LENGTH + 2) {
            return Err(Error::UnknownFilenameSize(buf.len()));
        }

        let parent_directory = FileReference::load(&buf[..8]);
        let filename = FileName {
            parent_directory,
            date_created: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            date_modified: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            date_mft_record_modified: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            date_accessed: u64::from_le_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]),
            logical_file_size: u64::from_le_bytes([
                buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
            ]),
            size_on_disk: u64::from_le_bytes([
                buf[48], buf[49], buf[50], buf[51], buf[52], buf[53], buf[54], buf[55],
            ]),
            flags: u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]),
            reparse_tag: u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]),
            filename_length: buf[64],
            filename_type: buf[65],
        };

        Ok(filename)
    }
}

pub struct StandardInformation {
    pub date_created: u64, // timestamps are "number of 100 ns intervals since Jan 1, 1601 UTC"
    pub date_modified: u64,
    pub date_mft_record_modified: u64,
    pub date_accessed: u64,
    pub flags: u32,
    pub max_versions: u32,
    pub version_number: u32,
    pub class_id: u32,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub quota_charged: Option<u64>,
    pub update_sequence_number: Option<u64>,
}
impl StandardInformation {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        let info = match buf.len() {
            72 => StandardInformation {
                date_created: u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ]),
                date_modified: u64::from_le_bytes([
                    buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]),
                date_mft_record_modified: u64::from_le_bytes([
                    buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
                ]),
                date_accessed: u64::from_le_bytes([
                    buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
                ]),
                flags: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
                max_versions: u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
                version_number: u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
                class_id: u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]),
                owner_id: Some(u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]])),
                security_id: Some(u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]])),
                quota_charged: Some(u64::from_le_bytes([
                    buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63],
                ])),
                update_sequence_number: Some(u64::from_le_bytes([
                    buf[64], buf[65], buf[66], buf[67], buf[68], buf[69], buf[70], buf[71],
                ])),
            },
            48 => StandardInformation {
                date_created: u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ]),
                date_modified: u64::from_le_bytes([
                    buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]),
                date_mft_record_modified: u64::from_le_bytes([
                    buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
                ]),
                date_accessed: u64::from_le_bytes([
                    buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
                ]),
                flags: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
                max_versions: u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
                version_number: u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
                class_id: u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]),
                owner_id: None,
                security_id: None,
                quota_charged: None,
                update_sequence_number: None,
            },
            unknown => return Err(Error::UnknownStandardInformationSize(unknown)),
        };

        Ok(info)
    }
}

pub struct ObjectId {
    pub object_id: Option<GUID>,
    pub birth_volume_id: Option<GUID>,
    pub birth_object_id: Option<GUID>,
    pub domain_id: Option<GUID>,
}
impl ObjectId {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        match buf.len() {
            0 | 16 | 32 | 48 | 64..=256 => {}
            unknown => return Err(Error::UnknownObjectIdSize(unknown)),
        }

        let object_id = if buf.len() >= 16 {
            Some(GUID {
                Data1: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                Data2: u16::from_le_bytes([buf[4], buf[5]]),
                Data3: u16::from_le_bytes([buf[6], buf[7]]),
                Data4: buf[8..16].try_into().unwrap(),
            })
        } else {
            None
        };

        let birth_volume_id = if buf.len() >= 32 {
            Some(GUID {
                Data1: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
                Data2: u16::from_le_bytes([buf[20], buf[21]]),
                Data3: u16::from_le_bytes([buf[22], buf[23]]),
                Data4: buf[24..32].try_into().unwrap(),
            })
        } else {
            None
        };

        let birth_object_id = if buf.len() >= 48 {
            Some(GUID {
                Data1: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
                Data2: u16::from_le_bytes([buf[36], buf[37]]),
                Data3: u16::from_le_bytes([buf[38], buf[39]]),
                Data4: buf[40..48].try_into().unwrap(),
            })
        } else {
            None
        };

        let domain_id = if buf.len() >= 64 {
            Some(GUID {
                Data1: u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]),
                Data2: u16::from_le_bytes([buf[52], buf[53]]),
                Data3: u16::from_le_bytes([buf[54], buf[55]]),
                Data4: buf[56..64].try_into().unwrap(),
            })
        } else {
            None
        };

        Ok(ObjectId {
            object_id,
            birth_volume_id,
            birth_object_id,
            domain_id,
        })
    }
}

pub mod volume_info_flags {
    pub const DIRTY: u16 = 0x0001; // tells windows to do chkdsk /F on next boot
    pub const RESIZE_LOGFILE: u16 = 0x0002;
    pub const UPGRADE_ON_MOUNT: u16 = 0x0004;
    pub const MOUNTED_ON_NT4: u16 = 0x0008;
    pub const DELETING_USN: u16 = 0x0010;
    pub const REPAIR_OBJECT_IDS: u16 = 0x0020;
    pub const CHKDSK_FLAG: u16 = 0x8000;
}

pub struct VolumeInformation {
    // reserved: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub flags: u16,
    // reserved: u32,
}
impl VolumeInformation {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != 12 {
            return Err(Error::UnknownVolumeInformationSize(buf.len()));
        }

        Ok(VolumeInformation {
            major_version: buf[8],
            minor_version: buf[9],
            flags: u16::from_le_bytes(buf[10..12].try_into().unwrap()),
        })
    }
}

pub struct EaInformation {
    pub size_packed: u16,
    pub num_required: u16,
    pub size_unpacked: u32,
}
impl EaInformation {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != 8 {
            return Err(Error::UnknownEaInformationSize(buf.len()));
        }

        Ok(EaInformation {
            size_packed: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            num_required: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            size_unpacked: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

pub mod reparse_tag_flags {
    pub const IS_ALIAS: u32 = 0x2000_0000;
    pub const IS_HIGH_LATENCY: u32 = 0x4000_0000;
    pub const IS_MICROSOFT: u32 = 0x8000_0000;
}

pub struct ReparsePoint {
    pub tag: u32,
    pub length: u16,
    pub guid: Option<GUID>,
}
impl ReparsePoint {
    pub fn load(buf: &[u8]) -> Result<Self, Error> {
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

        Ok(ReparsePoint { tag, length, guid })
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
pub const EXPECTED_ATTRIBUTE_LIST_ENTRY_SIZE: usize = 32;
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
