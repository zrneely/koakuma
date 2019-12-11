use crate::{err::Error, volumes::VolumeHandle};

use chrono::{DateTime, TimeZone as _, Utc};
use winapi::{
    shared::{
        minwindef::{DWORD, FILETIME, WORD},
        winerror,
    },
    um::{
        errhandlingapi as ehapi,
        ioapiset::DeviceIoControl,
        minwinbase::SYSTEMTIME,
        timezoneapi::FileTimeToSystemTime,
        winioctl::FSCTL_ENUM_USN_DATA,
        winnt::{DWORDLONG, FILE_ID_128, LARGE_INTEGER, LONGLONG, USN, WCHAR},
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

// shockingly, these are not defined in winapi
#[repr(C)]
#[allow(non_snake_case)]
struct MFT_ENUM_DATA_V1 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
    MinMajorVersion: WORD,
    MaxMajorVersion: WORD,
}
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
impl USN_RECORD_V3 {
    #[allow(non_snake_case)]
    fn from_bytes(mut buf: &[u8]) -> Self {
        let RecordLength = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let MajorVersion = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<WORD>()..];

        let MinorVersion = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
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

        let Reason = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let SourceInfo = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let SecurityId = DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let FileAttributes =
            DWORD::from_le_bytes(buf[..mem::size_of::<DWORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<DWORD>()..];

        let FileNameLength = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        buf = &buf[mem::size_of::<WORD>()..];

        let FileNameOffset = WORD::from_le_bytes(buf[..mem::size_of::<WORD>()].try_into().unwrap());
        //buf = &buf[mem::size_of::<WORD>()..];

        USN_RECORD_V3 {
            RecordLength,
            MajorVersion,
            MinorVersion,
            FileReferenceNumber,
            ParentFileReferenceNumber,
            Usn,
            TimeStamp,
            Reason,
            SourceInfo,
            SecurityId,
            FileAttributes,
            FileNameLength,
            FileNameOffset,
            FileName: [0],
        }
    }

    fn to_entry(&self, filename: OsString) -> Result<MftEntry, Error> {
        Ok(MftEntry {
            file_ref_number: u128::from_le_bytes(self.FileReferenceNumber.Identifier),
            parent_file_ref_number: u128::from_le_bytes(self.ParentFileReferenceNumber.Identifier),
            usn: self.Usn,
            timestamp: parse_time(self.TimeStamp)?,
            attributes: self.FileAttributes,
            filename,
        })
    }
}

#[derive(Debug)]
pub struct MftEntry {
    pub file_ref_number: u128,
    pub parent_file_ref_number: u128,
    pub usn: USN,
    pub timestamp: DateTime<Utc>,
    pub attributes: DWORD,
    pub filename: OsString,
}

pub struct MftEntryIterator {
    handle: VolumeHandle,
    next_start_number: DWORDLONG,
    parsed_entries: VecDeque<MftEntry>,
    buffer: Vec<u8>,
    has_errored: bool,
}
impl MftEntryIterator {
    pub fn new(handle: VolumeHandle) -> Self {
        MftEntryIterator {
            handle,
            next_start_number: 0,
            parsed_entries: VecDeque::with_capacity(1024),
            buffer: vec![0; 4 * 1024 * 1024],
            has_errored: false,
        }
    }
}
impl Iterator for MftEntryIterator {
    type Item = Result<MftEntry, Error>;

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

            let usn_record = USN_RECORD_V3::from_bytes(usn_data);
            if usn_record.MajorVersion != 3 {
                self.has_errored = true;
                return Some(Err(Error::UnknownUsnRecordVersion));
            }

            let filename_end: usize =
                (usn_record.FileNameOffset + usn_record.FileNameLength).into();
            if filename_end > usn_data.len() {
                self.has_errored = true;
                return Some(Err(Error::UsnRecordBadFilenameLength));
            }

            let mut filename = &usn_data[usn_record.FileNameOffset.into()..filename_end];
            let filename = {
                let mut wchars = Vec::with_capacity(filename.len() / mem::size_of::<WCHAR>());
                while filename.len() >= mem::size_of::<WCHAR>() {
                    let (wchar, rest) = filename.split_at(mem::size_of::<WCHAR>());
                    filename = rest;
                    wchars.push(u16::from_le_bytes(wchar.try_into().unwrap()));
                }
                wchars
            };
            let filename = OsString::from_wide(&filename[..]);
            match usn_record.to_entry(filename) {
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
