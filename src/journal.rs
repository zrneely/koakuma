use crate::{err::Error, volumes::VolumeHandle};

use chrono::{DateTime, TimeZone as _, Utc};
use winapi::{
    shared::{
        minwindef::{DWORD, FILETIME, WORD},
        winerror,
    },
    um::{
        errhandlingapi as ehapi,
        fileapi::FILE_STREAM_INFO,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        ioapiset::DeviceIoControl,
        minwinbase::{FileStreamInfo, SYSTEMTIME},
        timezoneapi::FileTimeToSystemTime,
        winbase::{
            ExtendedFileIdType, GetFileInformationByHandleEx, OpenFileById,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_DESCRIPTOR,
        },
        winioctl::FSCTL_ENUM_USN_DATA,
        winnt::{
            DWORDLONG, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_TEMPORARY, FILE_ID_128, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, LARGE_INTEGER, LONGLONG, USN, WCHAR,
        },
    },
};

use std::{
    collections::VecDeque,
    convert::TryInto as _,
    ffi::{c_void, OsString},
    mem,
    os::windows::ffi::OsStringExt as _,
    ptr,
};

// Shockingly, these are  not defined in winapi!
#[repr(C)]
#[allow(non_snake_case)]
struct MFT_ENUM_DATA_V1 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
    MinMajorVersion: WORD,
    MaxMajorVersion: WORD,
}
// Never actually constructed; we just need it for size_of.
#[repr(C)]
#[allow(non_snake_case)]
struct USN_RECORD_V3 {
    RecordLength: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    FileReferenceNumber: FILE_ID_128,
    ParentFileReferenceNumber: FILE_ID_128,
    Usn: USN,
    TimeStamp: LARGE_INTEGER,
    Reason: DWORD,
    SourceInfo: DWORD,
    SecurityId: DWORD,
    FileAttributes: DWORD,
    FileNameLength: WORD,
    FileNameOffset: WORD,
    FileName: [WCHAR; 1],
}

fn parse_time(time: LARGE_INTEGER) -> Result<DateTime<Utc>, Error> {
    let ftime = FILETIME {
        dwLowDateTime: unsafe { time.u() }.LowPart,
        dwHighDateTime: unsafe { time.u() }.HighPart as u32, // i32 to u32 conversion
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

fn is_flag_set(data: DWORD, flag: DWORD) -> bool {
    (data & flag) != 0
}

#[derive(Debug)]
pub struct FileSizeInfo {
    pub logical_size: u64,
    pub physical_size: u64,
    pub stream_count: u64,
}

// Result is (logical, physical)
#[allow(non_snake_case)]
fn get_size_info_for_file(
    vol_handle: &VolumeHandle,
    file_id: &FILE_ID_128,
    buf: &mut [u8],
) -> Result<FileSizeInfo, Error> {
    // To get the file size, we need a handle. Since we have the ID, open with that.
    let mut file_id_descriptor = FILE_ID_DESCRIPTOR {
        dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>().try_into().unwrap(),
        Type: ExtendedFileIdType,
        u: Default::default(),
    };
    *unsafe { file_id_descriptor.u.ExtendedFileId_mut() } = *file_id;

    let handle = unsafe {
        OpenFileById(
            **vol_handle,
            &mut file_id_descriptor,
            0, // we need neither read nor write access
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null_mut(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { ehapi::GetLastError() };
        return Err(Error::OpenHandleForSizeFailed(err));
    }

    let success = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStreamInfo,
            buf.as_mut_ptr() as *mut c_void,
            buf.len().try_into().unwrap(),
        )
    };

    unsafe { CloseHandle(handle) };

    if success == 0 {
        let err = unsafe { ehapi::GetLastError() };
        return Err(Error::GetFileInformationFailed(err));
    }

    let mut stream_count = 0;
    let mut logical_size = 0u64;
    let mut physical_size = 0u64;

    let mut remaining_entry_data: &[u8] = buf;
    loop {
        stream_count += 1;

        let mut current_entry = &remaining_entry_data[..mem::size_of::<FILE_STREAM_INFO>()];
        // Read a FILE_STREAM_INFO from the beginning of the result_data.
        let NextEntryOffset = DWORD::from_le_bytes(
            current_entry[0..mem::size_of::<DWORD>()]
                .try_into()
                .unwrap(),
        );
        current_entry = &current_entry[mem::size_of::<DWORD>()..];

        // Skip StreamNameLength
        current_entry = &current_entry[mem::size_of::<DWORD>()..];

        let StreamSize = LONGLONG::from_le_bytes(
            current_entry[..mem::size_of::<LONGLONG>()]
                .try_into()
                .unwrap(),
        );
        current_entry = &current_entry[mem::size_of::<LARGE_INTEGER>()..];

        let StreamAllocationSize = LONGLONG::from_le_bytes(
            current_entry[..mem::size_of::<LONGLONG>()]
                .try_into()
                .unwrap(),
        );
        // current_entry = &current_entry[mem::size_of::<LARGE_INTEGER>()..];

        let next_entry_offset = NextEntryOffset.try_into().unwrap();
        logical_size = logical_size.saturating_add(StreamSize.try_into().unwrap());
        physical_size = physical_size.saturating_add(StreamAllocationSize.try_into().unwrap());

        // Skip stream name, etc.
        if next_entry_offset == 0 {
            break;
        } else if next_entry_offset > remaining_entry_data.len() {
            return Err(Error::FileStreamInfoBadNextEntry);
        } else {
            remaining_entry_data = &remaining_entry_data[..next_entry_offset];
        }
    }

    Ok(FileSizeInfo {
        logical_size,
        physical_size,
        stream_count,
    })
}

#[derive(Debug)]
pub struct JournalEntry {
    pub file_ref_number: u128,
    pub parent_file_ref_number: u128,
    pub usn: USN,
    pub timestamp: DateTime<Utc>,
    pub is_directory: bool,
    pub is_reparse_point: bool,
    pub is_temporary: bool,
    pub filename: String,
    pub file_size_info: FileSizeInfo,
}
impl JournalEntry {
    #[allow(non_snake_case)] // to match what the Windows API provides
    fn parse_usn_entry(
        vol_handle: &VolumeHandle,
        mut buf: &[u8],
        stream_info_buffer: &mut [u8],
    ) -> Result<Self, Error> {
        let orig_buf = buf;

        //let RecordLength = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let MajorVersion = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<WORD>()..];

        // let MinorVersion = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<WORD>()..];

        let FileReferenceNumber = FILE_ID_128 {
            Identifier: buf[..mem::size_of::<FILE_ID_128>()].try_into().unwrap(),
        };
        buf = &buf[mem::size_of::<FILE_ID_128>()..];

        let ParentFileReferenceNumber = FILE_ID_128 {
            Identifier: buf[..mem::size_of::<FILE_ID_128>()].try_into().unwrap(),
        };
        buf = &buf[mem::size_of::<FILE_ID_128>()..];

        let Usn = USN::from_le_bytes(buf[..mem::size_of::<USN>()].try_into().unwrap());
        buf = &buf[mem::size_of::<USN>()..];

        let TimeStamp = {
            let mut ts = LARGE_INTEGER::default();
            *unsafe { ts.QuadPart_mut() } =
                LONGLONG::from_le_bytes(buf[..mem::size_of::<LONGLONG>()].try_into().unwrap());
            ts
        };
        buf = &buf[mem::size_of::<LARGE_INTEGER>()..];

        // let Reason = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        // let SourceInfo = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        // let SecurityId = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let FileAttributes =
            DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let FileNameLength = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<WORD>()..];

        let FileNameOffset = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        //buf = &buf[mem::size_of::<WORD>()..];

        if MajorVersion != 3 {
            return Err(Error::UnknownUsnRecordVersion);
        }

        let filename_end: usize = (FileNameOffset + FileNameLength).into();
        if filename_end > orig_buf.len() {
            return Err(Error::UsnRecordBadFilenameLength);
        }

        let mut filename = &orig_buf[FileNameOffset.into()..filename_end];
        let filename = {
            let mut wchars = Vec::with_capacity(filename.len() / mem::size_of::<WCHAR>());
            while filename.len() >= mem::size_of::<WCHAR>() {
                let (wchar, rest) = filename.split_at(mem::size_of::<WCHAR>());
                filename = rest;
                wchars.push(u16::from_le_bytes(wchar.try_into().unwrap()));
            }
            wchars
        };
        let filename = OsString::from_wide(&filename[..])
            .as_os_str()
            .to_string_lossy()
            .into();

        let is_directory = is_flag_set(FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
        let file_size_info = if !is_directory {
            get_size_info_for_file(vol_handle, &FileReferenceNumber, stream_info_buffer)?
        } else {
            FileSizeInfo {
                logical_size: 0,
                physical_size: 0,
                stream_count: 0,
            }
        };

        Ok(JournalEntry {
            file_ref_number: u128::from_le_bytes(FileReferenceNumber.Identifier),
            parent_file_ref_number: u128::from_le_bytes(ParentFileReferenceNumber.Identifier),
            usn: Usn,
            timestamp: parse_time(TimeStamp)?,
            is_directory,
            is_reparse_point: is_flag_set(FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT),
            is_temporary: is_flag_set(FileAttributes, FILE_ATTRIBUTE_TEMPORARY),
            filename,
            file_size_info,
        })
    }
}

pub struct JournalEntryIterator {
    handle: VolumeHandle,
    next_start_number: DWORDLONG,
    parsed_entries: VecDeque<JournalEntry>,
    buffer: Vec<u8>,
    stream_info_buffer: Vec<u8>,
    has_errored: bool,
}
impl JournalEntryIterator {
    pub fn new(handle: VolumeHandle) -> Self {
        JournalEntryIterator {
            handle,
            next_start_number: 0,
            parsed_entries: VecDeque::with_capacity(1024),
            buffer: vec![0; 4 * 1024 * 1024],       // 4 MiB
            stream_info_buffer: vec![0; 64 * 1024], // 64 KiB
            has_errored: false,
        }
    }
}
impl Iterator for JournalEntryIterator {
    type Item = Result<JournalEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_errored {
            return None;
        }

        if let Some(entry) = self.parsed_entries.pop_front() {
            return Some(Ok(entry));
        }

        // We need to load a new batch of entries.
        // The API promises not to mutate this.
        let mut input_data = MFT_ENUM_DATA_V1 {
            StartFileReferenceNumber: self.next_start_number,
            LowUsn: DWORD::min_value().try_into().unwrap(),
            HighUsn: DWORD::max_value().try_into().unwrap(),
            MinMajorVersion: 3, // set these both to 3 - we want only USN_RECORD_V3
            MaxMajorVersion: 3, // structs in the output buffer
        };

        let mut bytes_returned = 0;
        let result = unsafe {
            DeviceIoControl(
                *self.handle,
                FSCTL_ENUM_USN_DATA,
                &mut input_data as *mut MFT_ENUM_DATA_V1 as *mut c_void,
                mem::size_of::<MFT_ENUM_DATA_V1>().try_into().unwrap(),
                self.buffer.as_mut_ptr() as *mut c_void,
                self.buffer.len().try_into().unwrap(),
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            // F
            self.has_errored = true;
            let err = unsafe { ehapi::GetLastError() };

            return if err == winerror::ERROR_HANDLE_EOF {
                None
            } else {
                self.has_errored = true;
                Some(Err(Error::FsctlEnumUsnDataFailed(err)))
            };
        }

        // Success! The first DWORDLONG in the output buffer is our next StartFileReferenceNumber.
        let bytes_returned = bytes_returned.try_into().unwrap();
        if bytes_returned < mem::size_of::<DWORDLONG>() {
            self.has_errored = true;
            return Some(Err(Error::FsctlEnumUsnDataResultTooSmall));
        }

        let result_data = &self.buffer[0..bytes_returned];
        self.next_start_number = DWORDLONG::from_le_bytes(
            result_data[0..mem::size_of::<DWORDLONG>()]
                .try_into()
                .unwrap(),
        );
        let mut result_data = &result_data[mem::size_of::<DWORDLONG>()..];
        println!(
            "next: {} {} {}",
            self.next_start_number,
            bytes_returned,
            result_data.len()
        );

        while !result_data.is_empty() {
            // Parse out one record.
            let record_length: usize =
                DWORD::from_le_bytes(result_data[0..mem::size_of::<DWORD>()].try_into().unwrap())
                    .try_into()
                    .unwrap();

            if record_length > result_data.len() || record_length < mem::size_of::<USN_RECORD_V3>()
            {
                self.has_errored = true;
                return Some(Err(Error::UsnRecordBadLength));
            }

            let (usn_data, rest) = result_data.split_at(record_length);
            result_data = rest;

            match JournalEntry::parse_usn_entry(
                &self.handle,
                usn_data,
                &mut self.stream_info_buffer[..],
            ) {
                Ok(entry) => self.parsed_entries.push_back(entry),
                Err(err) => {
                    self.has_errored = true;
                    return Some(Err(err));
                }
            }

            if result_data.is_empty() {
                break;
            }
        }

        if let Some(entry) = self.parsed_entries.pop_front() {
            Some(Ok(entry))
        } else {
            None
        }
    }
}
