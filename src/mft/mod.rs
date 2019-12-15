use crate::{err::Error, SafeHandle};

use chrono::{DateTime, TimeZone as _, Utc};
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
    io::prelude::*,
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
        name: Option<String>,
        created: DateTime<Utc>,
        modified: DateTime<Utc>,
        mft_record_modified: DateTime<Utc>,
        accessed: DateTime<Utc>,
        flags: StandardFlags,
        max_versions: u32,
        version_number: u32,
        class_id: u32,
        owner_id: u32,
        security_id: u32,
        quota_charged: u64,
        update_sequence_number: u64,
    },

    // list of attributes that make up the file
    AttributeList {
        name: Option<String>,
    },
    // one of the names of the file
    FileName {
        // name OF THE ATTRIBUTE, not the file name
        name: Option<String>,
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
    // if present, a 64-bit identifier assigned by a link-tracking service
    ObjectId {
        name: Option<String>,
    },
    // volume label; only present on volume files
    VolumeName {
        name: Option<String>,
    },
    // only present on volume files
    VolumeInformation {
        name: Option<String>,
    },
    // actual file content
    Data {
        name: Option<String>,
        logical_size: u64,
        physical_size: u64,
    },
    // used for filename allocation for large directories
    IndexRoot {
        name: Option<String>,
    },
    // used for filename allocation for large directories
    IndexAllocation {
        name: Option<String>,
    },
    // bitmap index for a large directory
    Bitmap {
        name: Option<String>,
        logical_size: u64,
        physical_size: u64,
    },
    // reparse data
    ReparsePoint {
        name: Option<String>,
    },
}

#[derive(Debug)]
pub struct MftEntry {
    pub attributes: Vec<Attribute>,
    pub is_file_name_index_present: bool,
}

pub struct MasterFileTable {
    mft_stream: read_volume::CheatingFileStream,
    segment_buffer: Vec<u8>,
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

            let (segment_header, _) = sys::FileRecordSegmentHeader::load(&self.segment_buffer[..]);

            if (segment_header.flags & sys::segment_header_flags::FILE_RECORD_SEGMENT_IN_USE) == 0 {
                println!("Skipping non-used record segment");
                continue;
            }

            if segment_header.base_file_record_segment.segment_number_low != 0
                || segment_header.base_file_record_segment.segment_number_high != 0
            {
                // This is an extension of a previous record; skip it.
                continue;
            }

            let mut attribute_buffer =
                &self.segment_buffer[segment_header.first_attribute_offset as usize..];

            let mut attribs = Vec::new();

            loop {
                let (attrib_header, consumed) = sys::AttributeRecordHeader::load(attribute_buffer);
                // TODO: use AttributeList-type attributes to read extension FILE records.

                // It looks like attribute names are some sort of ASCII, with one byte-per-character.
                // The length is explicitly one byte and the maximum characters are 255, according to the docs.
                // This means it's *probably* valid UTF-8.
                let attribute_name = match attrib_header.name_length {
                    0 => None,
                    length => {
                        println!("Reading attribute name!");
                        let name_start: usize = attrib_header.name_offset.try_into().unwrap();
                        let name_end: usize = name_start + length as usize;
                        let name_buffer = &attribute_buffer[name_start..name_end];
                        println!("name buffer: {:?}", String::from_utf8_lossy(name_buffer));
                        Some(String::from_utf8_lossy(name_buffer).into_owned())
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

                        match parse_resident_attribute(
                            &attrib_header,
                            attribute_name,
                            attribute_data,
                        ) {
                            Ok(attrib) => {
                                println!("got attrib: {:#?}", attrib);
                                attribs.push(attrib);
                            }
                            Err(err) => return Some(Err(err)),
                        }
                    }
                    sys::form_codes::NON_RESIDENT => {
                        let (nonresident_header, _) = sys::AttributeRecordHeaderNonResident::load(
                            &attribute_buffer[consumed..],
                        );

                        // We should never need to read non-resident data
                        match parse_non_resident_attribute(
                            &attrib_header,
                            &nonresident_header,
                            attribute_name,
                        ) {
                            Ok(attrib) => {
                                println!("got attrib: {:#?}", attrib);
                                attribs.push(attrib);
                            }
                            Err(err) => return Some(Err(err)),
                        }
                    }

                    unknown => {
                        return Some(Err(Error::UnknownFormCode(unknown)));
                    }
                };

                attribute_buffer =
                    &attribute_buffer[attrib_header.record_length.try_into().unwrap()..];
                if attribute_buffer.len() <= 4 || attribute_buffer[0..4] == [0xFF, 0xFF, 0xFF, 0xFF]
                {
                    println!("Found end thing");
                    break;
                }
            }

            return Some(Ok(MftEntry {
                attributes: attribs,
                is_file_name_index_present: (segment_header.flags
                    & sys::segment_header_flags::FILE_NAME_INDEX_PRESENT)
                    != 0,
            }));
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
    // have lifetimes known to rustc, so we have to follow them.
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
    attribute_name: Option<String>,
) -> Result<Attribute, Error> {
    println!(
        "non-resident: {:#?} {:#?} {:?}",
        attrib_header, non_resident_header, attribute_name
    );

    let attribute = match attrib_header.type_code {
        type_code @ sys::attribute_types::STANDARD_INFORMATION => {
            return Err(Error::UnsupportedNonResident(type_code))
        }

        sys::attribute_types::DATA => Attribute::Data {
            name: attribute_name,
            logical_size: non_resident_header.file_size,
            physical_size: non_resident_header.allocated_length,
        },

        sys::attribute_types::BITMAP => Attribute::Bitmap {
            name: attribute_name,
            logical_size: non_resident_header.file_size,
            physical_size: non_resident_header.allocated_length,
        },

        unknown => {
            return Err(Error::UnknownAttributeTypeCode(unknown));
        }
    };

    Ok(attribute)
}

fn parse_resident_attribute(
    attrib_header: &sys::AttributeRecordHeader,
    attribute_name: Option<String>,
    attribute_data: &[u8],
) -> Result<Attribute, Error> {
    println!("attribute data: {:?}", attribute_data);
    let attribute = match attrib_header.type_code {
        sys::attribute_types::STANDARD_INFORMATION => {
            let (attrib, _) = sys::StandardInformation::load(attribute_data);
            Attribute::StandardInformation {
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
            }
        }

        sys::attribute_types::FILE_NAME => {
            let (attrib, consumed) = sys::FileName::load(attribute_data);
            let name_len = (attrib.filename_length * 2) as usize;
            let filename_bytes = &attribute_data[consumed..consumed + name_len];
            // Since we have no guarantees about the alignment of the buffer,
            // we can't safely cast the array of u8's to an array of u16's.
            let filename = {
                let mut filename = vec![0u16; name_len / 2];
                for i in 0..filename.len() {
                    filename[i] =
                        u16::from_le_bytes([filename_bytes[i * 2], filename_bytes[(i * 2) + 1]]);
                }

                OsString::from_wide(&filename[..])
            };

            Attribute::FileName {
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
            }
        }

        unknown => {
            return Err(Error::UnknownAttributeTypeCode(unknown));
        }
    };

    Ok(attribute)
}

fn parse_time(time: u64) -> Result<DateTime<Utc>, Error> {
    let ftime = FILETIME {
        dwLowDateTime: (time & 0xFFFF_FFFF).try_into().unwrap(),
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
