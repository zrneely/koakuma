use crate::{err::Error, SafeHandle};

use chrono::{DateTime, TimeZone as _, Utc};
use uuid::Uuid;
use winapi::{
    shared::minwindef::FILETIME,
    um::{
        errhandlingapi as ehapi,
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::INVALID_HANDLE_VALUE,
        ioapiset::DeviceIoControl,
        minwinbase::SYSTEMTIME,
        timezoneapi::FileTimeToSystemTime,
        winbase::FILE_FLAG_BACKUP_SEMANTICS,
        winioctl::{
            FSCTL_GET_NTFS_VOLUME_DATA, NTFS_EXTENDED_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER,
        },
        winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE},
    },
};

use std::{
    collections::HashSet,
    convert::TryInto as _,
    ffi::{c_void, OsStr, OsString},
    fmt, mem,
    os::windows::ffi::{OsStrExt as _, OsStringExt as _},
    path::Path,
    ptr,
};

mod stream;
mod sys;

use stream::MftStream;

const NTFS_VOLUME_DATA_BUFFER_SIZE: usize =
    (mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() + mem::size_of::<NTFS_EXTENDED_VOLUME_DATA>());

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
            is_read_only: is_flag_set(flags, sys::standard_info_flags::READ_ONLY),
            is_hidden: is_flag_set(flags, sys::standard_info_flags::HIDDEN),
            is_system: is_flag_set(flags, sys::standard_info_flags::SYSTEM),
            is_archive: is_flag_set(flags, sys::standard_info_flags::ARCHIVE),
            is_device: is_flag_set(flags, sys::standard_info_flags::DEVICE),
            is_normal: is_flag_set(flags, sys::standard_info_flags::NORMAL),
            is_temporary: is_flag_set(flags, sys::standard_info_flags::TEMPORARY),
            is_sparse: is_flag_set(flags, sys::standard_info_flags::SPARSE),
            is_reparse_point: is_flag_set(flags, sys::standard_info_flags::REPARSE_POINT),
            is_compressed: is_flag_set(flags, sys::standard_info_flags::COMPRESSED),
            is_offline: is_flag_set(flags, sys::standard_info_flags::OFFLINE),
            is_not_indexed: is_flag_set(flags, sys::standard_info_flags::NOT_INDEXED),
            is_encrypted: is_flag_set(flags, sys::standard_info_flags::ENCRYPTED),
            is_directory: is_flag_set(flags, sys::standard_info_flags::DIRECTORY),
            is_index_view: is_flag_set(flags, sys::standard_info_flags::INDEX_VIEW),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum FileNameType {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
}

#[derive(Debug)]
pub enum Attribute {
    // read-only, timestamps, hard link count, etc
    StandardInformation {
        name: Option<OsString>,
        created: DateTime<Utc>,
        modified: DateTime<Utc>,
        mft_record_modified: DateTime<Utc>,
        accessed: DateTime<Utc>,
        flags: StandardFlags,
        max_versions: u32,
        version_number: u32,
        class_id: u32,
        owner_id: Option<u32>,
        security_id: Option<u32>,
        quota_charged: Option<u64>,
        update_sequence_number: Option<u64>,
    },

    // one of the names of the file
    FileName {
        // name OF THE ATTRIBUTE, not the file name
        name: Option<OsString>,
        filename: OsString,
        filename_type: FileNameType,
        parent: u64,
        created: DateTime<Utc>,
        modified: DateTime<Utc>,
        mft_record_modified: DateTime<Utc>,
        accessed: DateTime<Utc>,
        flags: StandardFlags,
        logical_size: u64,
        physical_size: u64,
        reparse_tag: u32,
    },

    // if present, a 64-bit identifier used by .LNK files, and various other IDs
    ObjectId {
        name: Option<OsString>,
        object_id: Option<Uuid>,
        birth_volume_id: Option<Uuid>,
        birth_object_id: Option<Uuid>,
        domain_id: Option<Uuid>,
    },

    // volume label; only present on volume files
    VolumeName {
        name: Option<OsString>,
        volume_name: OsString,
    },

    // only present on volume files
    VolumeInformation {
        name: Option<OsString>,
        major_version: u8,
        minor_version: u8,
        is_dirty: bool,
        resize_logfile: bool,
        upgrade_on_mount: bool,
        mounted_on_nt4: bool,
        is_deleting_usn: bool,
        repair_object_ids: bool,
        chkdsk_flag: bool,
    },

    // actual file content
    Data {
        name: Option<OsString>,
        logical_size: u64,
        physical_size: u64,
    },

    // // used for filename allocation for large directories
    // IndexRoot {
    //     name: Option<OsString>,
    // },
    // // used for filename allocation for large directories
    // IndexAllocation {
    //     name: Option<OsString>,
    // },

    // bitmap index for a large directory
    Bitmap {
        name: Option<OsString>,
        logical_size: u64,
        physical_size: u64,
    },

    EaInformation {
        name: Option<OsString>,
        packed_size: u16,
        unpacked_size: u32,
        num_required: u16,
    },

    // reparse data
    ReparsePoint {
        name: Option<OsString>,
        tag: u32,
        length: u16,
        guid: Option<Uuid>,
        is_alias: bool,
        is_high_latency: bool,
        is_microsoft: bool,
    },
}

#[derive(Debug)]
pub struct MftEntry {
    pub attributes: Vec<Attribute>,
    pub base_record_segment_idx: u64,
}
impl fmt::Display for MftEntry {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let (filename, logical_size, physical_size) = {
            let mut idx = 0;
            loop {
                if let Attribute::FileName {
                    ref filename,
                    logical_size,
                    physical_size,
                    ..
                } = &self.attributes[idx]
                {
                    break (filename.to_string_lossy(), logical_size, physical_size);
                }

                idx += 1;
                if idx >= self.attributes.len() {
                    panic!("File with no name");
                }
            }
        };

        fmt.debug_struct("File Record")
            .field("first filename", &filename)
            .field("logical size", &logical_size)
            .field("physical size", &physical_size)
            .finish()
    }
}

pub struct MasterFileTable {
    mft_stream: MftStream,
    bytes_per_file_record_segment: u64,
    bytes_per_sector: u64,
    bytes_per_cluster: u64,
    next_file_record_segment: u64,
}
impl MasterFileTable {
    pub fn load(volume_handle: SafeHandle, volume_path: &OsStr) -> Result<Self, Error> {
        let (volume_data, extended_data) = get_ntfs_volume_data(&volume_handle)?;

        // We only know how to deal with NTFS 3.0 or 3.1 data. Make sure the volume
        // is the correct NTFS version.
        if !(extended_data.MajorVersion == 3
            && (extended_data.MinorVersion == 0 || extended_data.MinorVersion == 1))
        {
            return Err(Error::UnknownNtfsVersion);
        }

        let mft_handle = get_mft_handle(volume_path)?;

        Ok(MasterFileTable {
            mft_stream: MftStream::new(volume_handle, volume_data, &mft_handle)?,
            bytes_per_file_record_segment: volume_data.BytesPerFileRecordSegment.into(),
            bytes_per_sector: volume_data.BytesPerSector.into(),
            bytes_per_cluster: volume_data.BytesPerCluster.into(),
            next_file_record_segment: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.mft_stream.len()
    }

    pub fn entry_count(&self) -> u64 {
        self.mft_stream.get_file_record_segment_count()
    }

    // private helpers

    fn parse_resident_attribute(
        &self,
        attrib_header: &sys::AttributeRecordHeader,
        resident_header: &sys::AttributeRecordHeaderResident,
        attribute_name: Option<OsString>,
        current_file_record_segment: u64,
        attribute_data: &[u8],
    ) -> Result<Vec<Attribute>, Error> {
        let attribute = match attrib_header.type_code {
            sys::attribute_types::STANDARD_INFORMATION => {
                let attrib = sys::StandardInformation::load(attribute_data)?;
                vec![Attribute::StandardInformation {
                    name: attribute_name,
                    created: parse_time(attrib.date_created)?,
                    modified: parse_time(attrib.date_modified)?,
                    mft_record_modified: parse_time(attrib.date_mft_record_modified)?,
                    accessed: parse_time(attrib.date_accessed)?,
                    flags: attrib.flags.into(),
                    max_versions: attrib.max_versions,
                    version_number: attrib.version_number,
                    class_id: attrib.class_id,
                    owner_id: attrib.owner_id,
                    security_id: attrib.security_id,
                    quota_charged: attrib.quota_charged,
                    update_sequence_number: attrib.update_sequence_number,
                }]
            }

            sys::attribute_types::FILE_NAME => {
                let attrib = sys::FileName::load(attribute_data)?;
                let name_len: usize = attrib.filename_length.into();
                let name_len = name_len * 2;
                let filename_bytes =
                    &attribute_data[sys::FILE_NAME_LENGTH..sys::FILE_NAME_LENGTH + name_len];
                let filename = parse_string(filename_bytes);

                vec![Attribute::FileName {
                    name: attribute_name,
                    filename,
                    filename_type: match attrib.filename_type {
                        sys::filename_types::POSIX => FileNameType::Posix,
                        sys::filename_types::WIN32 => FileNameType::Win32,
                        sys::filename_types::DOS => FileNameType::Dos,
                        sys::filename_types::WIN32_DOS => FileNameType::Win32AndDos,
                        unknown => return Err(Error::UnknownFilenameType(unknown)),
                    },
                    parent: parse_segment_number(&attrib.parent_directory),
                    created: parse_time(attrib.date_created)?,
                    modified: parse_time(attrib.date_modified)?,
                    mft_record_modified: parse_time(attrib.date_mft_record_modified)?,
                    accessed: parse_time(attrib.date_accessed)?,
                    flags: attrib.flags.into(),
                    logical_size: attrib.logical_file_size,
                    physical_size: attrib.size_on_disk,
                    reparse_tag: attrib.reparse_tag,
                }]
            }

            sys::attribute_types::OBJECT_ID => {
                let attrib = sys::ObjectId::load(attribute_data)?;
                vec![Attribute::ObjectId {
                    name: attribute_name,
                    object_id: attrib.object_id.map(Uuid::from_guid).transpose()?,
                    birth_volume_id: attrib.birth_volume_id.map(Uuid::from_guid).transpose()?,
                    birth_object_id: attrib.birth_object_id.map(Uuid::from_guid).transpose()?,
                    domain_id: attrib.domain_id.map(Uuid::from_guid).transpose()?,
                }]
            }

            sys::attribute_types::VOLUME_NAME => vec![Attribute::VolumeName {
                name: attribute_name,
                volume_name: parse_string(attribute_data),
            }],

            sys::attribute_types::VOLUME_INFORMATION => {
                let attrib = sys::VolumeInformation::load(attribute_data)?;
                vec![Attribute::VolumeInformation {
                    name: attribute_name,
                    major_version: attrib.major_version,
                    minor_version: attrib.minor_version,
                    is_dirty: is_flag_set16(attrib.flags, sys::volume_info_flags::DIRTY),
                    resize_logfile: is_flag_set16(
                        attrib.flags,
                        sys::volume_info_flags::RESIZE_LOGFILE,
                    ),
                    upgrade_on_mount: is_flag_set16(
                        attrib.flags,
                        sys::volume_info_flags::UPGRADE_ON_MOUNT,
                    ),
                    mounted_on_nt4: is_flag_set16(
                        attrib.flags,
                        sys::volume_info_flags::MOUNTED_ON_NT4,
                    ),
                    is_deleting_usn: is_flag_set16(
                        attrib.flags,
                        sys::volume_info_flags::DELETING_USN,
                    ),
                    repair_object_ids: is_flag_set16(
                        attrib.flags,
                        sys::volume_info_flags::REPAIR_OBJECT_IDS,
                    ),
                    chkdsk_flag: is_flag_set16(attrib.flags, sys::volume_info_flags::CHKDSK_FLAG),
                }]
            }

            // For resident DATA and BITMAP streams, we report physical size equal to the
            // logical size.
            sys::attribute_types::DATA => vec![Attribute::Data {
                name: attribute_name,
                logical_size: resident_header.value_length.into(),
                physical_size: resident_header.value_length.into(),
            }],

            sys::attribute_types::BITMAP => vec![Attribute::Bitmap {
                name: attribute_name,
                logical_size: resident_header.value_length.into(),
                physical_size: resident_header.value_length.into(),
            }],

            sys::attribute_types::EA_INFORMATION => {
                let attrib = sys::EaInformation::load(attribute_data)?;
                vec![Attribute::EaInformation {
                    name: attribute_name,
                    packed_size: attrib.size_packed,
                    unpacked_size: attrib.size_unpacked,
                    num_required: attrib.num_required,
                }]
            }

            sys::attribute_types::ATTRIBUTE_LIST => {
                #[cfg(debug_assertions)]
                {
                    println!("Reading resident attribute list");
                }
                self.parse_attribute_list(current_file_record_segment, attribute_data)?
            }

            sys::attribute_types::REPARSE_POINT => {
                let reparse_point = sys::ReparsePoint::load(attribute_data)?;
                vec![Attribute::ReparsePoint {
                    name: attribute_name,
                    tag: reparse_point.tag,
                    length: reparse_point.length,
                    guid: reparse_point.guid.map(Uuid::from_guid).transpose()?,
                    is_alias: is_flag_set(reparse_point.tag, sys::reparse_tag_flags::IS_ALIAS),
                    is_high_latency: is_flag_set(
                        reparse_point.tag,
                        sys::reparse_tag_flags::IS_HIGH_LATENCY,
                    ),
                    is_microsoft: is_flag_set(
                        reparse_point.tag,
                        sys::reparse_tag_flags::IS_MICROSOFT,
                    ),
                }]
            }

            sys::attribute_types::SECURITY_DESCRIPTOR
            | sys::attribute_types::INDEX_ROOT
            | sys::attribute_types::INDEX_ALLOCATION
            | sys::attribute_types::LOGGED_UTILITY_STREAM
            | sys::attribute_types::EA => vec![],

            unknown => {
                return Err(Error::UnknownAttributeTypeCode(unknown));
            }
        };

        Ok(attribute)
    }

    fn parse_non_resident_attribute(
        &self,
        attrib_header: &sys::AttributeRecordHeader,
        non_resident_header: &sys::AttributeRecordHeaderNonResident,
        attribute_name: Option<OsString>,
        current_file_record_segment: u64,
        data_runs: &[u8],
    ) -> Result<Vec<Attribute>, Error> {
        let attribute = match attrib_header.type_code {
            type_code @ sys::attribute_types::STANDARD_INFORMATION
            | type_code @ sys::attribute_types::OBJECT_ID
            | type_code @ sys::attribute_types::VOLUME_NAME
            | type_code @ sys::attribute_types::VOLUME_INFORMATION
            | type_code @ sys::attribute_types::EA_INFORMATION => {
                return Err(Error::UnsupportedNonResident(type_code))
            }

            sys::attribute_types::DATA => vec![Attribute::Data {
                name: attribute_name,
                logical_size: non_resident_header.file_size,
                physical_size: non_resident_header.allocated_length,
            }],

            sys::attribute_types::BITMAP => vec![Attribute::Bitmap {
                name: attribute_name,
                logical_size: non_resident_header.file_size,
                physical_size: non_resident_header.allocated_length,
            }],

            sys::attribute_types::ATTRIBUTE_LIST => {
                // We actually need to go read this
                let data = self.read_non_resident_data(data_runs)?;
                debug_assert_eq!(data.len(), non_resident_header.allocated_length as usize);
                self.parse_attribute_list(
                    current_file_record_segment,
                    &data[..non_resident_header.valid_data_length as usize],
                )?
            }

            sys::attribute_types::SECURITY_DESCRIPTOR
            | sys::attribute_types::INDEX_ROOT
            | sys::attribute_types::INDEX_ALLOCATION
            | sys::attribute_types::LOGGED_UTILITY_STREAM
            | sys::attribute_types::EA => vec![],

            unknown => {
                return Err(Error::UnknownAttributeTypeCode(unknown));
            }
        };
        Ok(attribute)
    }

    fn parse_segment(
        &self,
        segment_header: &sys::FileRecordSegmentHeader,
        current_file_record_segment: u64,
        allow_extensions: bool,
        buf: &[u8],
    ) -> Result<Option<Vec<Attribute>>, Error> {
        let mut result = Vec::new();
        if (segment_header.flags & sys::segment_header_flags::FILE_RECORD_SEGMENT_IN_USE) == 0 {
            #[cfg(debug_assertions)]
            {
                println!("Skipping non-used record: {}", current_file_record_segment);
            }
            return Ok(None);
        }
        if !allow_extensions
            && ((segment_header.base_file_record_segment.segment_number_low != 0)
                || (segment_header.base_file_record_segment.segment_number_high != 0))
        {
            // This is an extension of a previous record; skip it.
            #[cfg(debug_assertions)]
            {
                println!("Skipping extension record: {}", current_file_record_segment);
            }
            return Ok(None);
        }
        let mut attribute_buffer = &buf[segment_header.first_attribute_offset as usize..];
        loop {
            let (attrib_header, consumed) = sys::AttributeRecordHeader::load(attribute_buffer);
            // Attribute names are WTF-16 but the maximum length is 255 *bytes*.
            let attribute_name = match attrib_header.name_length {
                0 => None,
                pseudo_code_points => {
                    let name_start: usize = attrib_header.name_offset.try_into().unwrap();
                    let name_end: usize = name_start + (2 * pseudo_code_points) as usize;
                    let name_buffer = &attribute_buffer[name_start..name_end];
                    Some(parse_string(name_buffer))
                }
            };
            result.extend(match attrib_header.form_code {
                sys::form_codes::RESIDENT => {
                    let (resident_header, _) =
                        sys::AttributeRecordHeaderResident::load(&attribute_buffer[consumed..]);
                    // The data is resident, so we don't need additional reads to get it.
                    // value_offset measures from the beginning of the attribute record.
                    let start_offset: usize = resident_header.value_offset.try_into().unwrap();
                    let value_length: usize = resident_header.value_length.try_into().unwrap();
                    let end_offset = start_offset + value_length;
                    let attribute_data = &attribute_buffer[start_offset..end_offset];
                    self.parse_resident_attribute(
                        &attrib_header,
                        &resident_header,
                        attribute_name,
                        current_file_record_segment,
                        attribute_data,
                    )?
                }
                sys::form_codes::NON_RESIDENT => {
                    let (nonresident_header, _) =
                        sys::AttributeRecordHeaderNonResident::load(&attribute_buffer[consumed..]);

                    let start_offset: usize =
                        nonresident_header.mapping_pairs_offset.try_into().unwrap();
                    let end_offset: usize = attrib_header.record_length.try_into().unwrap();
                    let data_runs = &attribute_buffer[start_offset..end_offset];
                    self.parse_non_resident_attribute(
                        &attrib_header,
                        &nonresident_header,
                        attribute_name,
                        current_file_record_segment,
                        data_runs,
                    )?
                }
                unknown => {
                    return Err(Error::UnknownFormCode(unknown));
                }
            });
            attribute_buffer = &attribute_buffer[attrib_header.record_length.try_into().unwrap()..];
            if attribute_buffer.len() <= 4 || attribute_buffer[0..4] == [0xFF, 0xFF, 0xFF, 0xFF] {
                break;
            }
        }
        Ok(Some(result))
    }

    fn parse_attribute_list(
        &self,
        current_file_record_segment: u64,
        mut buf: &[u8],
    ) -> Result<Vec<Attribute>, Error> {
        let mut result = Vec::with_capacity(buf.len() / sys::EXPECTED_ATTRIBUTE_LIST_ENTRY_SIZE);
        let mut segment_buf = vec![0; self.bytes_per_file_record_segment as usize];

        let mut record_segments = HashSet::new();

        while !buf.is_empty() {
            let attrib = sys::AttributeListEntry::load(buf)?;

            let record_len = {
                let mut len = sys::MIN_ATTRIBUTE_LIST_ENTRY_SIZE;
                let name_len_wtf16: usize = attrib.name_length.try_into().unwrap();
                len += 2 * name_len_wtf16;

                // Round up to the nearest multiple of 8
                ((len + 7) / 8) * 8
            };

            debug_assert!(record_len <= buf.len());
            buf = &buf[record_len..];

            // Seek to the new position
            let segment_to_read = parse_segment_number(&attrib.segment_reference);

            if segment_to_read != current_file_record_segment {
                record_segments.insert(segment_to_read);
            }
        }

        for segment_to_read in record_segments {
            // Read the segment
            self.mft_stream
                .read_file_record_segment(segment_to_read, &mut segment_buf[..])?;
            let segment_header = sys::FileRecordSegmentHeader::load(&segment_buf[..])?;
            self.fix_record_with_update_sequence(&segment_header, &mut segment_buf[..])?;

            result.extend(
                self.parse_segment(
                    &segment_header,
                    segment_to_read,
                    true, // allow extensions
                    &segment_buf[..],
                )?
                .unwrap_or_default(),
            );
        }

        Ok(result)
    }

    // The data must start on a sector boundary (will be the case for all file record segments).
    fn fix_record_with_update_sequence(
        &self,
        segment_header: &sys::FileRecordSegmentHeader,
        data: &mut [u8],
    ) -> Result<(), Error> {
        // First, find the update sequence array
        let start_offset: usize = segment_header
            .multi_sector_header
            .update_sequence_array_offset
            .try_into()
            .unwrap();

        let end_offset = {
            let size: usize = segment_header
                .multi_sector_header
                .update_sequence_array_size
                .try_into()
                .unwrap();
            start_offset + (size * 2)
        };

        let (before, after) = data.split_at_mut(end_offset);

        let update_sequence_array = &before[start_offset..];
        let update_sequence_number = &update_sequence_array[0..2];

        for (sector, replacement_sequence) in update_sequence_array[2..].chunks_exact(2).enumerate()
        {
            // In each sector, the last two bytes should equal the sequence number
            // and should be replaced with the bytes from the array.
            let offset = ((1 + sector) * self.bytes_per_sector as usize) - 2 - before.len();

            if after[offset] != update_sequence_number[0]
                || after[offset + 1] != update_sequence_number[1]
            {
                return Err(Error::UpdateSequenceValidationFailed);
            }

            after[offset] = replacement_sequence[0];
            after[offset + 1] = replacement_sequence[1];
        }

        Ok(())
    }

    fn read_non_resident_data(&self, data_runs: &[u8]) -> Result<Vec<u8>, Error> {
        #[derive(Debug)]
        struct Run {
            start_lcn: i64,
            length: u64,
        }

        let mut runs = Vec::<Run>::new();
        let mut remaining_data = data_runs;
        let mut last_offset: i64 = 0;
        let mut total_size: u64 = 0;
        while !remaining_data.is_empty() && remaining_data[0] != 0 {
            let header = remaining_data[0];
            let offset_size = (header & 0xF0) >> 4;
            let length_size = header & 0x0F;
            remaining_data = &remaining_data[1..];

            // Next, "length_size" bytes point to the length of the run, in clusters.
            // This can be anything from 0 -> 15 bytes. We support 0 - 8.
            let length = parse_runlist_unsigned_int(remaining_data, length_size);
            remaining_data = &remaining_data[length_size.into()..];

            // Then, "offset_size" bytes point to the LCN where the run can be read.
            // This is a signed value relative to the previous offset.
            let offset_rel = parse_runlist_signed_int(remaining_data, offset_size);
            remaining_data = &remaining_data[offset_size.into()..];

            let offset = last_offset.checked_add(offset_rel).unwrap(); // panic on over/underflow

            runs.push(Run {
                start_lcn: offset,
                length,
            });

            last_offset = offset;
            total_size += length * self.bytes_per_cluster;
        }

        let mut buffer = vec![0; total_size.try_into().unwrap()];
        let mut cur_buf_offset: usize = 0;
        for run in runs {
            let end_offset: usize = cur_buf_offset + (run.length * self.bytes_per_cluster) as usize;
            self.mft_stream.read_clusters(
                run.start_lcn as u64,
                run.length,
                &mut buffer[cur_buf_offset..end_offset],
            )?;

            cur_buf_offset += (self.bytes_per_cluster * run.length) as usize;
        }

        Ok(buffer)
    }
}
impl Iterator for MasterFileTable {
    type Item = Result<MftEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut segment_buffer = vec![0; self.bytes_per_file_record_segment as usize];

        // We loop until we read a record that's in use and is not an extension of a previous one.
        loop {
            if self.next_file_record_segment > self.mft_stream.get_file_record_segment_count() {
                break None;
            }

            match self
                .mft_stream
                .read_file_record_segment(self.next_file_record_segment, &mut segment_buffer[..])
            {
                Ok(_) => {}
                Err(err) => break Some(Err(err)),
            }

            // If the buffer's header is 0's instead of "FILE", just skip
            if segment_buffer.iter().take(4).all(|x| *x == 0) {
                #[cfg(debug_assertions)]
                {
                    println!("Skipping empty record: {}", self.next_file_record_segment);
                }
                self.next_file_record_segment += 1;
                continue;
            }

            let segment_header = match sys::FileRecordSegmentHeader::load(&segment_buffer[..]) {
                Ok(header) => header,
                Err(err) => break Some(Err(err)),
            };

            // Use the update sequence array to validate and correct the buffer.
            match self.fix_record_with_update_sequence(&segment_header, &mut segment_buffer[..]) {
                Ok(_) => {}
                Err(err) => break Some(Err(err)),
            }

            let entry = match self.parse_segment(
                &segment_header,
                self.next_file_record_segment,
                false, // allow extensions
                &segment_buffer[..],
            ) {
                Ok(Some(attributes)) => MftEntry {
                    attributes,
                    base_record_segment_idx: self.next_file_record_segment,
                },
                Ok(None) => {
                    self.next_file_record_segment += 1;
                    continue;
                }
                Err(err) => break Some(Err(err)),
            };

            self.next_file_record_segment += 1;
            break Some(Ok(entry));
        }
    }
}

fn get_ntfs_volume_data(
    handle: &SafeHandle,
) -> Result<(NTFS_VOLUME_DATA_BUFFER, NTFS_EXTENDED_VOLUME_DATA), Error> {
    let mut result_size = 0;
    // Build the buffer out of u64s to guarantee 8-byte alignment.
    let mut buf: Vec<u64> = vec![0; NTFS_VOLUME_DATA_BUFFER_SIZE / 8];
    let success = unsafe {
        DeviceIoControl(
            **handle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            ptr::null_mut(),
            0,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8).try_into().unwrap(),
            &mut result_size,
            ptr::null_mut(),
        )
    };
    if success == 0 {
        let err = unsafe { ehapi::GetLastError() };
        return Err(Error::GetNtfsVolumeDataFailed(err));
    }

    if result_size != (buf.len() as u32) * 8 {
        return Err(Error::GetNtfsVolumeDataBadSize);
    }

    // Parse the results into the two structs. NTFS_VOLUME_DATA_BUFFER always
    // comes first.
    let (volume_data_buffer_bytes, extended_volume_data_bytes) =
        buf.split_at(mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() / 8);

    let volume_data_buffer = volume_data_buffer_bytes.as_ptr() as *const NTFS_VOLUME_DATA_BUFFER;
    let extended_volume_data =
        extended_volume_data_bytes.as_ptr() as *const NTFS_EXTENDED_VOLUME_DATA;

    // We want to be very explicit about this clone - these pointers don't currently
    // have lifetimes known to rustc, so we have to copy the data on return.
    #[allow(clippy::clone_on_copy)]
    Ok((
        unsafe { *volume_data_buffer }.clone(),
        unsafe { *extended_volume_data }.clone(),
    ))
}

fn get_mft_handle(volume_path: &OsStr) -> Result<SafeHandle, Error> {
    let filename = {
        let mut path = Path::new(volume_path).to_path_buf();
        path.push("$MFT");
        path
    };
    let filename = {
        let mut filename = filename.as_os_str().encode_wide().collect::<Vec<_>>();
        // Add a null terminator.
        filename.push(0);
        filename
    };
    let handle = unsafe {
        CreateFileW(
            filename.as_ptr(),
            0, // no permissions - we won't be reading or writing directly with this handle
            FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
            ptr::null_mut(), // security attributes
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(), // template file
        )
    };

    if handle != INVALID_HANDLE_VALUE {
        Ok(SafeHandle { handle })
    } else {
        let err = unsafe { ehapi::GetLastError() };
        Err(Error::OpenMftFailed(err))
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

fn parse_string(utf16data: &[u8]) -> OsString {
    // Since we have no guarantees about the alignment of the buffer,
    // we can't safely cast the array of u8's to an array of u16's.
    let mut filename = vec![0u16; utf16data.len() / 2];
    for i in 0..filename.len() {
        filename[i] = u16::from_le_bytes([utf16data[i * 2], utf16data[(i * 2) + 1]]);
    }
    OsString::from_wide(&filename[..])
}

fn parse_segment_number(num: &sys::FileReference) -> u64 {
    ((num.segment_number_high as u64) << 32) | (num.segment_number_low as u64)
}

fn parse_runlist_unsigned_int(data: &[u8], width: u8) -> u64 {
    let mut out = [0u8; 8];
    let ptr_out = out.as_mut_ptr();
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr_out, width as usize);

        #[allow(clippy::cast_ptr_alignment)]
        std::ptr::read_unaligned(ptr_out as *const u64)
    }
}

fn parse_runlist_signed_int(data: &[u8], width: u8) -> i64 {
    #[inline]
    fn extend_sign(val: u64, width: usize) -> i64 {
        let shift = (8 - width) * 8;
        (val << shift) as i64 >> shift
    }

    extend_sign(parse_runlist_unsigned_int(data, width), width.into())
}

fn is_flag_set(data: u32, flag: u32) -> bool {
    (data & flag) != 0
}

fn is_flag_set16(data: u16, flag: u16) -> bool {
    (data & flag) != 0
}
