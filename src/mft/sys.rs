use winapi::{
    shared::minwindef::{UCHAR, ULONG, USHORT},
    um::winnt::{LONGLONG, ULONGLONG},
};

#[repr(C)]
pub struct MultiSectorHeader {
    pub signature: [UCHAR; 4], // should always be "FILE"
    pub update_sequence_array_offset: USHORT,
    pub update_sequence_array_size: USHORT,
}

#[repr(C)]
pub struct FileReference {
    pub segment_number_low: ULONG,
    pub segment_number_high: USHORT,
    pub sequence_number: USHORT,
}

#[repr(C)]
pub struct FileRecordSegmentHeader {
    pub multi_sector_header: MultiSectorHeader,
    pub reserved_1: ULONGLONG,
    pub sequence_number: USHORT, // epoch-like counter used to track uses of the file
    pub reserved_2: USHORT,
    pub first_attribute_offset: USHORT, // offset of the first attribute record
    pub flags: USHORT,
    pub reserved_3: [ULONG; 2],
    pub base_file_record_segment: FileReference, // reference to the base file segment
    pub reserved_4: USHORT,
    // pub update_sequence_array: [USHORT]
}

#[repr(u8)] // TODO: unspecified; assuming u8 for now
pub enum AttributeTypeCode {
    // read-only, timestamps, hard link count, etc
    StandardInformation = 0x10,
    // list of attributes that make up the file
    AttributeList = 0x20,
    // one of the names of the file
    FileName = 0x30,
    // if present, a 64-bit identifier assigned by a link-tracking service
    ObjectId = 0x40,
    // volume label; only present on volume files
    VolumeName = 0x60,
    // only present on volume files
    VolumeInformation = 0x70,
    // actual file content
    Data = 0x80,
    // used for filename allocation for large directories
    IndexRoot = 0x90,
    // used for filename allocation for large directories
    IndexAllocation = 0xA0,
    // bitmap index for a large directory
    Bitmap = 0xB0,
    // reparse data
    ReparsePoint = 0xC0,
}

#[repr(u8)] // UCHAR
pub enum FormCode {
    Resident = 0,
    NonResident = 1,
}

#[repr(C)]
pub struct AttributeRecordHeader {
    pub type_code: AttributeTypeCode,
    pub record_length: ULONG,
    pub form_code: FormCode,
    pub name_length: UCHAR, // attribute name, not file name
    pub name_offset: USHORT,
    pub flags: USHORT,
    pub instance: USHORT,
}

#[repr(C)]
struct AttributeRecordHeaderResident {
    pub value_length: ULONG,
    pub value_offset: USHORT,
    pub reserved: [UCHAR; 2],
}

#[repr(C)]
struct AttributeRecordHeaderNonResident {
    pub lowest_vcn: LONGLONG, // LARGE_INTEGER
    pub highest_vcn: LONGLONG,
    pub mapping_pairs_offset: USHORT,
    pub reserved: [UCHAR; 6],
    pub allocated_length: LONGLONG,
    pub file_size: LONGLONG,
    pub valid_data_length: LONGLONG,
    pub total_allocated: LONGLONG,
}
