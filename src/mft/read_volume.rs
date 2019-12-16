use crate::{err::Error, SafeHandle};

use winapi::{
    shared::{minwindef::DWORD, winerror},
    um::{
        errhandlingapi as ehapi,
        fileapi::ReadFile,
        ioapiset::DeviceIoControl,
        minwinbase::OVERLAPPED,
        winioctl::{FSCTL_GET_RETRIEVAL_POINTERS, NTFS_VOLUME_DATA_BUFFER},
        winnt::LONGLONG,
    },
};

use std::{convert::TryInto as _, ffi::c_void, io, mem, ptr};

// Represents a continuous list of logical clusters in one file.
#[derive(Debug, Clone, Copy)]
struct Extent {
    min_vcn: LONGLONG,
    min_lcn: LONGLONG,
    cluster_count: LONGLONG,
}

// Reads a file using a volume handle instead of a readable file handle.
// Although a file handle is needed to initialize this object, it's not
// persisted and does not need to be readable.
pub struct CheatingFileStream {
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
    pub fn new(
        volume_handle: SafeHandle,
        volume_info: NTFS_VOLUME_DATA_BUFFER,
        file_handle: &SafeHandle,
    ) -> Result<Self, Error> {
        let extents = load_file_extents(&file_handle)?;
        if extents.first().ok_or(Error::MftHasNoExtents)?.min_lcn
            != *unsafe { volume_info.MftStartLcn.QuadPart() }
        {
            return Err(Error::MftStartLcnNotFirstExtent);
        }

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

    pub fn len(&self) -> usize {
        let mut len = 0;
        for extent in &self.extents {
            len += extent.cluster_count * self.bytes_per_cluster;
        }
        len.try_into().unwrap()
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

        self.buffer_valid_from = 0;
        self.buffer_valid_to = num_bytes_read.try_into().unwrap();
        self.current_extent_offset += num_bytes_read as i64;

        if self.current_extent_offset >= extent_to_read.cluster_count * self.bytes_per_cluster {
            self.current_extent += 1;
            self.current_extent_offset = 0;
        }

        Ok(())
    }
}
impl io::Read for CheatingFileStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if self.get_valid_buffer().len() >= buf.len() {
            buf.copy_from_slice(&self.get_valid_buffer()[..buf.len()]);
            self.consume_buffer(buf.len());
            return Ok(buf.len());
        }

        let mut bytes_written = 0;
        while bytes_written < buf.len() && self.has_more_extents() {
            let valid_buffer = self.get_valid_buffer();
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

        Ok(bytes_written)
    }
}
impl io::Seek for CheatingFileStream {
    fn seek(&mut self, pos: io::SeekFrom) -> Result<u64, io::Error> {
        // Invalidate the current buffer
        self.buffer_valid_from = self.buffer.len();
        self.buffer_valid_to = self.buffer.len();

        let target_offset: i64 = match pos {
            io::SeekFrom::Start(offset) => offset as i64,
            io::SeekFrom::End(offset) => {
                let mut len = 0;
                for extent in &self.extents {
                    len += extent.cluster_count * self.bytes_per_cluster;
                }
                len - offset
            }
            io::SeekFrom::Current(offset) => {
                let mut len = 0;
                for extent in &self.extents[..self.current_extent] {
                    len += extent.cluster_count * self.bytes_per_cluster;
                }
                len += self.current_extent_offset;
                len + offset
            }
        };

        if target_offset < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "negative seek"));
        }

        self.current_extent = 0;
        self.current_extent_offset = 0;
        let mut cur_offset = 0;
        let mut found_offset = false;

        for extent in &self.extents {
            let end_of_extent = cur_offset + (extent.cluster_count * self.bytes_per_cluster);
            if end_of_extent >= target_offset {
                // We're in the correct extent
                self.current_extent_offset = end_of_extent - target_offset;
                found_offset = true;
                break;
            } else {
                self.current_extent += 1;
                cur_offset = end_of_extent;
            }
        }

        if found_offset {
            Ok(target_offset as u64)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "out-of-range seek",
            ))
        }
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
