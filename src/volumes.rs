use crate::{err::Error, SafeHandle};

use winapi::{
    shared::winerror,
    um::{
        errhandlingapi as ehapi,
        fileapi::{
            CreateFile2, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
            GetVolumePathNamesForVolumeNameW, OPEN_EXISTING,
        },
        handleapi::INVALID_HANDLE_VALUE,
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, HANDLE},
    },
};

use std::{
    convert::TryInto as _,
    ffi::OsString,
    os::windows::ffi::{OsStrExt as _, OsStringExt as _},
    ptr,
};

#[derive(Debug)]
pub struct VolumeInfo {
    pub name: OsString,
    pub paths: Vec<OsString>,
}
impl VolumeInfo {
    pub fn get_handle(&self) -> Result<SafeHandle, Error> {
        let filename = {
            let mut filename = self.name.as_os_str().encode_wide().collect::<Vec<_>>();
            // Replace the trailing backslash with a null terminator. We need the null
            // terminator in general, and if the name ends in a backslash CreateFile
            // will try to open the root directory of the volume instead.
            *filename.last_mut().unwrap() = 0;
            filename
        };
        let handle = unsafe {
            CreateFile2(
                filename.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                OPEN_EXISTING,
                ptr::null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE {
            Ok(SafeHandle { handle })
        } else {
            let err = unsafe { ehapi::GetLastError() };
            Err(Error::OpenVolumeHandleFailed(err))
        }
    }
}

pub struct VolumeIterator {
    iter_handle: HANDLE,
    buffer: Vec<u16>,
    first_vol_name: Option<Result<OsString, Error>>,
}
impl VolumeIterator {
    pub fn new() -> Result<Self, Error> {
        let mut buffer = vec![0; 1024];
        let handle =
            unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len().try_into().unwrap()) };

        let first_vol_name = Some(VolumeIterator::parse_buffer(&buffer[..]));

        if handle != INVALID_HANDLE_VALUE {
            Ok(VolumeIterator {
                iter_handle: handle,
                buffer,
                first_vol_name,
            })
        } else {
            let err = unsafe { ehapi::GetLastError() };
            Err(Error::FindFirstVolumeFailed(err))
        }
    }

    fn parse_string_list(mut buf: &[u16]) -> Result<Vec<OsString>, Error> {
        let mut string_list = Vec::new();

        loop {
            let next_null = buf.iter().position(|x| *x == 0);
            if let Some(next_null) = next_null {
                if next_null == 0 {
                    return Ok(string_list);
                }

                let (data, rest) = buf.split_at(next_null);
                buf = &rest[1..]; // skip the null byte

                string_list.push(OsString::from_wide(data));
            }
        }
    }

    fn get_paths_for_volume(&mut self, name: &OsString) -> Result<Vec<OsString>, Error> {
        let mut size = 0;
        let name = {
            let mut name = name.as_os_str().encode_wide().collect::<Vec<_>>();
            name.push(0);
            name
        };

        let success = unsafe {
            GetVolumePathNamesForVolumeNameW(
                name.as_ptr(),
                self.buffer.as_mut_ptr(),
                self.buffer.len().try_into().unwrap(),
                &mut size,
            )
        };

        if success == 0 {
            let err = unsafe { ehapi::GetLastError() };
            return Err(Error::GetVolumePathNamesFailed(err));
        }

        VolumeIterator::parse_string_list(&self.buffer[..])
    }

    fn parse_buffer(buf: &[u16]) -> Result<OsString, Error> {
        let null_terminator_offset = buf
            .iter()
            .position(|x| *x == 0)
            .ok_or(Error::MissingNullTerminator)?;

        Ok(OsString::from_wide(&buf[0..null_terminator_offset]))
    }
}
impl Iterator for VolumeIterator {
    type Item = Result<VolumeInfo, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first_vol_name) = self.first_vol_name.take() {
            Some(first_vol_name.and_then(|name| {
                self.get_paths_for_volume(&name)
                    .map(|paths| VolumeInfo { name, paths })
            }))
        } else {
            let success = unsafe {
                FindNextVolumeW(
                    self.iter_handle,
                    self.buffer.as_mut_ptr(),
                    self.buffer.len().try_into().unwrap(),
                )
            };

            if success == 0 {
                let err = unsafe { ehapi::GetLastError() };

                return if err == winerror::ERROR_NO_MORE_FILES {
                    None
                } else {
                    Some(Err(Error::FindNextVolumeFailed(err)))
                };
            }

            Some(
                VolumeIterator::parse_buffer(&self.buffer[..]).and_then(|name| {
                    self.get_paths_for_volume(&name)
                        .map(|paths| VolumeInfo { name, paths })
                }),
            )
        }
    }
}
impl Drop for VolumeIterator {
    fn drop(&mut self) {
        unsafe { FindVolumeClose(self.iter_handle) };
    }
}
