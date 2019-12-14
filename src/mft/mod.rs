use crate::{err::Error, SafeHandle};

use winapi::{
    shared::{minwindef::DWORD, winerror},
    um::{
        errhandlingapi as ehapi,
        fileapi::{CreateFileW, ReadFile, OPEN_EXISTING},
        handleapi::INVALID_HANDLE_VALUE,
        ioapiset::DeviceIoControl,
        minwinbase::OVERLAPPED,
        winbase::FILE_FLAG_BACKUP_SEMANTICS,
        winioctl::{
            FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_GET_RETRIEVAL_POINTERS, NTFS_EXTENDED_VOLUME_DATA,
            NTFS_VOLUME_DATA_BUFFER,
        },
        winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LARGE_INTEGER, LONGLONG},
    },
};

use std::{
    convert::TryInto as _,
    ffi::{c_void, OsStr},
    io::{self, prelude::*},
    mem,
    os::windows::ffi::OsStrExt as _,
    path::Path,
    ptr,
};

mod sys;

const NTFS_VOLUME_DATA_BUFFER_SIZE: usize =
    (mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() + mem::size_of::<NTFS_EXTENDED_VOLUME_DATA>());

// Represents a continuous list of logical clusters in one file.
#[derive(Debug, Clone, Copy)]
struct Extent {
    min_vcn: LONGLONG,
    min_lcn: LONGLONG,
    cluster_count: LONGLONG,
}

// Reads from a file using a file handle without read access, using a volume handle.
struct CheatingFileStream {
    volume_handle: SafeHandle,

    bytes_per_cluster: i64,
    extents: Vec<Extent>,
    current_extent: usize,
    current_extent_offset: i64,

    buffer: Vec<u8>,
    buffer_valid_from: usize,
    buffer_valid_to: usize,
}
impl CheatingFileStream {
    fn new(
        volume_handle: SafeHandle,
        volume_info: NTFS_VOLUME_DATA_BUFFER,
        file_handle: &SafeHandle,
    ) -> Result<Self, Error> {
        let extents = load_file_extents(&file_handle)?;
        println!("extents: {:#?}", extents);

        Ok(CheatingFileStream {
            volume_handle,
            bytes_per_cluster: volume_info.BytesPerCluster.into(),
            extents,
            current_extent: 0,
            current_extent_offset: 0,
            buffer: vec![0; 4 * 1024],
            buffer_valid_from: 4 * 1024, // not valid at all
            buffer_valid_to: 4 * 1024,
        })
    }

    fn consume_buffer(&mut self, consumed: usize) {
        self.buffer_valid_from = self.buffer_valid_from.saturating_add(consumed);
    }

    fn get_valid_buffer(&self) -> &[u8] {
        &self.buffer[self.buffer_valid_from..self.buffer_valid_to]
    }

    fn has_more_extents(&self) -> bool {
        self.current_extent < self.extents.len()
    }

    fn populate_buffers(&mut self) -> Result<(), Error> {
        let extent_to_read = self.extents[self.current_extent];
        println!(
            "populate_buffers: {:?} {:?} {:?}",
            extent_to_read, self.current_extent, self.current_extent_offset
        );

        let starting_offset =
            (extent_to_read.min_lcn * self.bytes_per_cluster) + self.current_extent_offset;
        let ending_offset =
            (extent_to_read.min_lcn + extent_to_read.cluster_count) * self.bytes_per_cluster;
        let len_to_read = self.buffer.len().min(
            ending_offset
                .saturating_sub(starting_offset)
                .try_into()
                .unwrap(),
        );

        let mut ov = OVERLAPPED::default();
        unsafe { ov.u.s_mut() }.Offset = ((starting_offset as u64) & 0x0000_0000_FFFF_FFFFu64)
            .try_into()
            .unwrap();
        unsafe { ov.u.s_mut() }.OffsetHigh =
            (((starting_offset as u64) & 0xFFFF_FFFF_0000_0000u64) >> 32)
                .try_into()
                .unwrap();

        println!("calling ReadFile");
        let mut num_bytes_read = 0;
        let success = unsafe {
            ReadFile(
                *self.volume_handle,
                self.buffer.as_mut_ptr() as *mut c_void,
                len_to_read.try_into().unwrap(),
                &mut num_bytes_read,
                &mut ov,
            )
        };
        if success == 0 {
            let err = unsafe { ehapi::GetLastError() };
            return Err(Error::ReadVolumeFailed(err));
        }

        println!("read done successfully: {:?}", num_bytes_read);

        self.buffer_valid_from = 0;
        self.buffer_valid_to = num_bytes_read.try_into().unwrap();
        self.current_extent_offset += num_bytes_read as i64;

        if self.current_extent_offset > extent_to_read.cluster_count * self.bytes_per_cluster {
            self.current_extent += 1;
            self.current_extent_offset = 0;
        }

        Ok(())
    }
}
impl io::Read for CheatingFileStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        println!("CFS::read, buf len: {}", buf.len());

        if self.get_valid_buffer().len() >= buf.len() {
            println!("in easy CFS::read case");
            buf.copy_from_slice(&self.get_valid_buffer()[..buf.len()]);
            self.consume_buffer(buf.len());
            return Ok(buf.len());
        }

        println!(
            "extents: {}, next_extent: {}",
            self.extents.len(),
            self.current_extent
        );

        let mut bytes_written = 0;
        while bytes_written < buf.len() && self.has_more_extents() {
            let valid_buffer = self.get_valid_buffer();
            println!(
                "CFS::read: buf len: {}, bytes written: {}, valid_buf len: {}",
                buf.len(),
                bytes_written,
                valid_buffer.len()
            );
            if !valid_buffer.is_empty() {
                let len_to_copy = valid_buffer.len().min(buf.len() - bytes_written);
                let source = &valid_buffer[..len_to_copy];
                let dest = &mut buf[bytes_written..bytes_written + len_to_copy];
                dest.copy_from_slice(source);
                self.consume_buffer(len_to_copy);
                bytes_written += len_to_copy;
            } else {
                self.populate_buffers()
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            }
        }

        println!("done with CFS::read: {}", bytes_written);
        Ok(bytes_written)
    }
}

pub struct MasterFileTable {
    mft_stream: CheatingFileStream,

    starting_lcn: LARGE_INTEGER, // the logical cluster number that the MFT begins at
    bytes_per_file_record_segment: DWORD, // the number of bytes in each segment of a file record
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
            mft_stream: CheatingFileStream::new(volume_handle, volume_data, &mft_handle)?,

            starting_lcn: volume_data.MftStartLcn,
            bytes_per_file_record_segment: volume_data.BytesPerFileRecordSegment,
        })
    }

    pub fn read_1k(&mut self) {
        let mut buf = vec![0; 5 * 1024];
        self.mft_stream.read_exact(&mut buf[..]).unwrap();

        println!("Read 1k of MFT: {:x?}", buf);
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

fn load_file_extents(handle: &SafeHandle) -> Result<Vec<Extent>, Error> {
    let mut result = Vec::new();
    let mut current_starting_vcn = 0;

    // This should be big enough for all but the most fragmented files.
    let mut retrieval_buffer = vec![0u8; 64 * 1024];

    loop {
        let mut result_size = 0;

        let success = unsafe {
            DeviceIoControl(
                **handle,
                FSCTL_GET_RETRIEVAL_POINTERS,
                &mut current_starting_vcn as *mut LONGLONG as *mut c_void,
                mem::size_of::<LONGLONG>().try_into().unwrap(),
                retrieval_buffer.as_mut_ptr() as *mut c_void,
                retrieval_buffer.len().try_into().unwrap(),
                &mut result_size,
                ptr::null_mut(),
            )
        };
        let err = unsafe { ehapi::GetLastError() };
        if success == 0 {
            return Err(Error::GetRetrievalPointersFailed(err));
        }

        let mut returned_buffer = &retrieval_buffer[..result_size as usize];

        // The first DWORD in the buffer is the number of Extents returned.
        let extent_count = DWORD::from_le_bytes(
            returned_buffer[0..mem::size_of::<DWORD>()]
                .try_into()
                .unwrap(),
        );
        // Note that we have now consumed sizeof(LONGLONG) bytes due to struct padding.
        returned_buffer = &returned_buffer[mem::size_of::<LONGLONG>()..];

        // That's followed by a LARGE_INTEGER representing the first VCN mapping returned.
        let mut min_vcn = LONGLONG::from_le_bytes(
            returned_buffer[..mem::size_of::<LONGLONG>()]
                .try_into()
                .unwrap(),
        );
        returned_buffer = &returned_buffer[mem::size_of::<LONGLONG>()..];

        // Then, there's a list of tuples, each giving the starting LCN for the current
        // extent and the VCN that starts the next extent.
        let mut next_min_vcn = min_vcn;

        for _ in 0..extent_count {
            next_min_vcn = LONGLONG::from_le_bytes(
                returned_buffer[..mem::size_of::<LONGLONG>()]
                    .try_into()
                    .unwrap(),
            );
            returned_buffer = &returned_buffer[mem::size_of::<LONGLONG>()..];

            let min_lcn = LONGLONG::from_le_bytes(
                returned_buffer[..mem::size_of::<LONGLONG>()]
                    .try_into()
                    .unwrap(),
            );
            returned_buffer = &returned_buffer[mem::size_of::<LONGLONG>()..];

            result.push(Extent {
                min_lcn,
                min_vcn,
                cluster_count: next_min_vcn - min_vcn,
            });
            min_vcn = next_min_vcn;
        }

        current_starting_vcn = next_min_vcn;
        if err != winerror::ERROR_MORE_DATA {
            break;
        }
    }

    Ok(result)
}
