#[derive(Debug)]
pub struct MultiSectorHeader {
    pub signature: [u8; 4], // should always be "FILE"
    pub update_sequence_array_offset: u16,
    pub update_sequence_array_size: u16,
}
impl MultiSectorHeader {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let header = MultiSectorHeader {
            signature: [buf[0], buf[1], buf[2], buf[3]],
            update_sequence_array_offset: u16::from_le_bytes([buf[4], buf[5]]),
            update_sequence_array_size: u16::from_le_bytes([buf[6], buf[7]]),
        };
        (header, 8)
    }
}

#[derive(Debug)]
pub struct FileReference {
    pub segment_number_low: u32,
    pub segment_number_high: u16,
    pub sequence_number: u16,
}
impl FileReference {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let reference = FileReference {
            segment_number_low: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            segment_number_high: u16::from_le_bytes([buf[4], buf[5]]),
            sequence_number: u16::from_le_bytes([buf[6], buf[7]]),
        };

        (reference, 8)
    }
}

pub mod segment_header_flags {
    pub const FILE_RECORD_SEGMENT_IN_USE: u16 = 0x0001;
    pub const FILE_NAME_INDEX_PRESENT: u16 = 0x0002;
}

#[derive(Debug)]
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
    pub fn load(mut buf: &[u8]) -> (Self, usize) {
        let start_buf_len = buf.len();

        let (multi_sector_header, consumed) = MultiSectorHeader::load(buf);
        buf = &buf[consumed..];

        let log_file_sequence_number = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
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

        let (base_file_record_segment, consumed) = FileReference::load(buf);
        buf = &buf[consumed..];

        let next_attrib_id = u16::from_le_bytes([buf[0], buf[1]]);
        buf = &buf[4..]; // skip 4 bytes, but only 2 are meaningful

        let mft_record_num = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf = &buf[4..];

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

        (header, start_buf_len - buf.len())
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
}

pub mod form_codes {
    use winapi::shared::minwindef::UCHAR;

    pub const RESIDENT: UCHAR = 0;
    pub const NON_RESIDENT: UCHAR = 1;
}

#[repr(C)]
#[derive(Debug)]
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
            type_code: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            record_length: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            form_code: buf[8],
            name_length: buf[9],
            name_offset: u16::from_le_bytes([buf[10], buf[11]]),
            flags: u16::from_le_bytes([buf[12], buf[13]]),
            instance: u16::from_le_bytes([buf[14], buf[15]]),
        };

        (header, 16)
    }
}

#[repr(C)]
#[derive(Debug)]
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

#[repr(C)]
#[derive(Debug)]
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
            lowest_vcn: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            highest_vcn: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            mapping_pairs_offset: u16::from_le_bytes([buf[16], buf[17]]),
            compression_unit_size: u16::from_le_bytes([buf[18], buf[19]]),
            // reserved: 0,
            allocated_length: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            file_size: u64::from_le_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]),
            valid_data_length: u64::from_le_bytes([
                buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
            ]),
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
#[derive(Debug)]
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
impl FileName {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let (parent_directory, _) = FileReference::load(&buf[..8]);
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

        (filename, 66)
    }
}

#[derive(Debug)]
pub struct StandardInformation {
    pub date_created: u64, // timestamps are "number of 100 ns intervals since Jan 1, 1601 UTC"
    pub date_modified: u64,
    pub date_mft_record_modified: u64,
    pub date_accessed: u64,
    pub flags: u32,
    pub max_versions: u32,
    pub version_number: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota_charged: u64,
    pub update_sequence_number: u64,
}
impl StandardInformation {
    pub fn load(buf: &[u8]) -> (Self, usize) {
        let info = StandardInformation {
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
            owner_id: u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]),
            security_id: u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]]),
            quota_charged: u64::from_le_bytes([
                buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63],
            ]),
            update_sequence_number: u64::from_le_bytes([
                buf[64], buf[65], buf[66], buf[67], buf[68], buf[69], buf[70], buf[71],
            ]),
        };

        (info, 72)
    }
}
