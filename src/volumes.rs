use crate::{err::Error, SafeHandle};
use std::{ffi::OsString, fmt::Display, os::windows::ffi::OsStringExt as _, ptr};
use windows::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, MAX_PATH},
    Storage::FileSystem::{
        CreateFile2, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, FindVolumeHandle,
        GetVolumeInformationW, GetVolumePathNamesForVolumeNameW, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};

fn parse_buffer(buf: &[u16]) -> Result<OsString, Error> {
    let null_terminator_offset = buf
        .iter()
        .position(|x| *x == 0)
        .ok_or(Error::MissingNullTerminator)?;

    Ok(OsString::from_wide(&buf[0..null_terminator_offset]))
}

#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub unc_name: OsString,
    pub paths: Vec<OsString>,
    name: Result<OsString, Error>,
}
impl VolumeInfo {
    fn new(unc_name: OsString, paths: Vec<OsString>) -> Self {
        let name = Self::get_volume_name(&unc_name);

        // Remove the trailing slash from the volume name.
        // With the trailing slash, CreateFile will attempt to
        // open the root directory of the volume instead of
        // the volume itself.
        let mut unc_name = unc_name.to_string_lossy().to_string();
        unc_name.pop();
        let unc_name = unc_name.into();

        Self {
            name,
            unc_name,
            paths,
        }
    }

    pub fn get_handle(&self) -> Result<SafeHandle, Error> {
        unsafe {
            CreateFile2(
                self.unc_name.as_os_str(),
                FILE_GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                OPEN_EXISTING,
                ptr::null_mut(),
            )
        }
        .map(|handle| SafeHandle { handle })
        .map_err(|err| Error::OpenVolumeHandleFailed(err))
    }

    fn get_volume_name(unc_name: &OsString) -> Result<OsString, Error> {
        let mut buffer = vec![0u16; MAX_PATH as usize];
        let mut buffer2 = vec![0u16; 0];
        unsafe {
            GetVolumeInformationW(
                unc_name.as_os_str(),
                &mut buffer[..],
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut buffer2[..],
            )
            .ok()
        }
        .map_err(|err| Error::GetVolumeNameFailed(err))
        .and_then(|_| parse_buffer(&buffer[..]))
    }
}
impl Display for VolumeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.paths
                .get(0)
                .map(|path| path.to_string_lossy())
                .unwrap_or_else(|| self.unc_name.to_string_lossy())
        )?;

        match self.name {
            Ok(ref volume_name) if volume_name.len() > 0 => write!(f, " ({})", volume_name.to_string_lossy())?,
            _ => {}
        }

        Ok(())
    }
}

pub struct VolumeIterator {
    iter_handle: FindVolumeHandle,
    buffer: Vec<u16>,
    first_vol_name: Option<Result<OsString, Error>>,
}
impl VolumeIterator {
    pub fn new() -> Result<Self, Error> {
        let mut volume_name = vec![0; 1024];
        match unsafe { FindFirstVolumeW(&mut volume_name[..]) } {
            Ok(handle) => {
                let name = parse_buffer(&volume_name[..]);
                Ok(Self {
                    iter_handle: handle,
                    buffer: volume_name,
                    first_vol_name: Some(name),
                })
            }
            Err(err) => Err(Error::FindFirstVolumeFailed(err)),
        }
    }

    fn get_paths_for_volume(&mut self, name: &OsString) -> Result<Vec<OsString>, Error> {
        let mut return_size = 0u32;

        unsafe {
            GetVolumePathNamesForVolumeNameW(
                name.as_os_str(),
                &mut self.buffer[..],
                &mut return_size,
            )
            .ok()
        }
        .map_err(|err| Error::GetVolumePathNamesFailed(err))?;

        Self::parse_string_list(&self.buffer[..])
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
}
impl Iterator for VolumeIterator {
    type Item = Result<VolumeInfo, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first_vol_name) = self.first_vol_name.take() {
            Some(first_vol_name.and_then(|name| {
                self.get_paths_for_volume(&name)
                    .map(|paths| VolumeInfo::new(name, paths))
            }))
        } else {
            let result = unsafe { FindNextVolumeW(self.iter_handle, &mut self.buffer[..]).ok() };

            match result {
                Ok(_) => Some(parse_buffer(&self.buffer[..]).and_then(|name| {
                    self.get_paths_for_volume(&name)
                        .map(|paths| VolumeInfo::new(name, paths))
                })),
                Err(err) => match err.win32_error() {
                    Some(ERROR_NO_MORE_FILES) => None,
                    _ => Some(Err(Error::FindNextVolumeFailed(err))),
                },
            }
        }
    }
}
impl Drop for VolumeIterator {
    fn drop(&mut self) {
        unsafe { FindVolumeClose(self.iter_handle) };
    }
}
