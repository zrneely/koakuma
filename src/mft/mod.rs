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
    convert::TryInto as _,
    ffi::{c_void, OsStr, OsString},
    io::{prelude::*, SeekFrom},
    mem,
    os::windows::ffi::{OsStrExt as _, OsStringExt as _},
    path::Path,
    ptr,
};

mod read_volume;
mod sys;

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

#[derive(Debug)]
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
    },
}

#[derive(Debug)]
pub struct MftEntry {
    pub attributes: Vec<Attribute>,
}

pub struct MasterFileTable {
    mft_stream: read_volume::CheatingFileStream,
    segment_buffer: Vec<u8>,
    bytes_per_file_record_segment: usize,
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
            mft_stream: read_volume::CheatingFileStream::new(
                volume_handle,
                volume_data,
                &mft_handle,
            )?,
            segment_buffer: vec![0; volume_data.BytesPerFileRecordSegment.try_into().unwrap()],
            bytes_per_file_record_segment: volume_data
                .BytesPerFileRecordSegment
                .try_into()
                .unwrap(),
        })
    }

    pub fn len(&self) -> usize {
        self.mft_stream.len()
    }
}
impl Iterator for MasterFileTable {
    type Item = Result<MftEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // We loop until we read a record that's in use and is not an extension of a previous one.
        loop {
            match self.mft_stream.read_exact(&mut self.segment_buffer[..]) {
                Ok(_) => {}
                Err(err) => return Some(Err(Error::ReadMftFailed(err))),
            }

            match parse_segment(
                &mut self.mft_stream,
                self.bytes_per_file_record_segment,
                false, // allow extensions
                &self.segment_buffer[..],
            ) {
                Ok(Some(attributes)) => return Some(Ok(MftEntry { attributes })),
                Ok(None) => continue,
                Err(err) => return Some(Err(err)),
            }
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

fn parse_non_resident_attribute(
    attrib_header: &sys::AttributeRecordHeader,
    non_resident_header: &sys::AttributeRecordHeaderNonResident,
    attribute_name: Option<OsString>,
) -> Result<Option<Attribute>, Error> {
    let attribute = match attrib_header.type_code {
        type_code @ sys::attribute_types::STANDARD_INFORMATION
        | type_code @ sys::attribute_types::OBJECT_ID
        | type_code @ sys::attribute_types::VOLUME_NAME
        | type_code @ sys::attribute_types::VOLUME_INFORMATION
        | type_code @ sys::attribute_types::ATTRIBUTE_LIST
        | type_code @ sys::attribute_types::EA_INFORMATION => {
            return Err(Error::UnsupportedNonResident(type_code))
        }

        sys::attribute_types::DATA => Some(Attribute::Data {
            name: attribute_name,
            logical_size: non_resident_header.file_size,
            physical_size: non_resident_header.allocated_length,
        }),

        sys::attribute_types::BITMAP => Some(Attribute::Bitmap {
            name: attribute_name,
            logical_size: non_resident_header.file_size,
            physical_size: non_resident_header.allocated_length,
        }),

        sys::attribute_types::SECURITY_DESCRIPTOR
        | sys::attribute_types::INDEX_ROOT
        | sys::attribute_types::INDEX_ALLOCATION
        | sys::attribute_types::LOGGED_UTILITY_STREAM
        | sys::attribute_types::EA => None,

        unknown => {
            return Err(Error::UnknownAttributeTypeCode(unknown));
        }
    };

    Ok(attribute)
}

fn parse_resident_attribute(
    attrib_header: &sys::AttributeRecordHeader,
    resident_header: &sys::AttributeRecordHeaderResident,
    attribute_name: Option<OsString>,
    stream: &mut read_volume::CheatingFileStream,
    bytes_per_file_record_segment: usize,
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
            let name_len = (attrib.filename_length * 2) as usize;
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
                resize_logfile: is_flag_set16(attrib.flags, sys::volume_info_flags::RESIZE_LOGFILE),
                upgrade_on_mount: is_flag_set16(
                    attrib.flags,
                    sys::volume_info_flags::UPGRADE_ON_MOUNT,
                ),
                mounted_on_nt4: is_flag_set16(attrib.flags, sys::volume_info_flags::MOUNTED_ON_NT4),
                is_deleting_usn: is_flag_set16(attrib.flags, sys::volume_info_flags::DELETING_USN),
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
            println!(">>> RECURSING <<<");
            parse_attribute_list(stream, bytes_per_file_record_segment, attribute_data)?
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
    stream: &mut read_volume::CheatingFileStream,
    bytes_per_file_record_segment: usize,
    allow_extensions: bool,
    buf: &[u8],
) -> Result<Option<Vec<Attribute>>, Error> {
    let mut result = Vec::new();
    let (segment_header, _) = sys::FileRecordSegmentHeader::load(&buf[..]);

    if (segment_header.flags & sys::segment_header_flags::FILE_RECORD_SEGMENT_IN_USE) == 0 {
        println!("Skipping non-used record segment");
        return Ok(None);
    }

    if !allow_extensions
        && ((segment_header.base_file_record_segment.segment_number_low != 0)
            || (segment_header.base_file_record_segment.segment_number_high != 0))
    {
        // This is an extension of a previous record; skip it.
        println!("Skipping extension record");
        return Ok(None);
    }

    let mut attribute_buffer = &buf[segment_header.first_attribute_offset as usize..];

    loop {
        // println!("attribute: {:?}", attribute_buffer);
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

        match attrib_header.form_code {
            sys::form_codes::RESIDENT => {
                let (resident_header, _) =
                    sys::AttributeRecordHeaderResident::load(&attribute_buffer[consumed..]);

                // The data is resident, so we don't need additional reads to get it.
                // value_offset measures from the beginning of the attribute record.
                let start_offset = resident_header.value_offset as usize;
                let end_offset = start_offset + resident_header.value_length as usize;
                let attribute_data = &attribute_buffer[start_offset..end_offset];

                result.extend(parse_resident_attribute(
                    &attrib_header,
                    &resident_header,
                    attribute_name,
                    stream,
                    bytes_per_file_record_segment,
                    attribute_data,
                )?);
            }
            sys::form_codes::NON_RESIDENT => {
                let (nonresident_header, _) =
                    sys::AttributeRecordHeaderNonResident::load(&attribute_buffer[consumed..]);

                match parse_non_resident_attribute(
                    &attrib_header,
                    &nonresident_header,
                    attribute_name,
                ) {
                    Ok(Some(attrib)) => {
                        result.push(attrib);
                    }
                    Ok(None) => println!(
                        "Skipping non-resident attribute we don't care about: {:X}",
                        attrib_header.type_code
                    ),
                    Err(err) => return Err(err),
                }
            }

            unknown => {
                return Err(Error::UnknownFormCode(unknown));
            }
        };

        attribute_buffer = &attribute_buffer[attrib_header.record_length.try_into().unwrap()..];
        if attribute_buffer.len() <= 4 || attribute_buffer[0..4] == [0xFF, 0xFF, 0xFF, 0xFF] {
            break;
        }
    }

    Ok(Some(result))
}

fn parse_attribute_list(
    stream: &mut read_volume::CheatingFileStream,
    bytes_per_file_record_segment: usize,
    mut buf: &[u8],
) -> Result<Vec<Attribute>, Error> {
    println!("Parsing attribute list: {:?}", buf);
    let mut result = Vec::with_capacity(buf.len() / sys::ATTRIBUTE_LIST_ENTRY_SIZE);
    let mut segment_buf = vec![0; bytes_per_file_record_segment];
    let cur_pos = stream.seek(SeekFrom::Current(0)).unwrap();

    while !buf.is_empty() {
        let attrib = sys::AttributeListEntry::load(buf)?;
        buf = &buf[sys::ATTRIBUTE_LIST_ENTRY_SIZE..];

        // We don't need the name here, so just skip it.
        // The name is guaranteed to come immediately after the header, if present.
        buf = &buf[attrib.name_length.try_into().unwrap()..];

        // Seek to the new position
        let target = (((attrib.segment_reference.segment_number_high as u64) << 16)
            | attrib.segment_reference.segment_number_low as u64)
            * bytes_per_file_record_segment as u64;
        stream.seek(SeekFrom::Start(target)).unwrap();

        // Read the segment
        stream.read_exact(&mut segment_buf[..]).unwrap();

        result.extend(
            parse_segment(
                stream,
                bytes_per_file_record_segment,
                true, // allow extensions
                &segment_buf[..],
            )?
            .unwrap_or_default(),
        );
    }

    // Restore the old position
    stream.seek(SeekFrom::Start(cur_pos)).unwrap();

    Ok(result)
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

fn is_flag_set(data: u32, flag: u32) -> bool {
    (data & flag) != 0
}

fn is_flag_set16(data: u16, flag: u16) -> bool {
    (data & flag) != 0
}
