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

use std::{convert::TryInto as _, ffi::c_void, mem, ptr};

// Represents a continuous list of logical clusters in one file.
#[derive(Debug, Clone, Copy)]
struct Extent {
    min_vcn: i64,
    min_lcn: i64,
    cluster_count: i64,
}

// Reads a file using a volume handle instead of a readable file handle.
// Although a file handle is needed to initialize this object, it's not
// persisted and does not need to be readable.
pub struct MftStream {
    volume_handle: SafeHandle,

    bytes_per_cluster: u64,
    bytes_per_file_record_segment: u64,
    len: u64,
    extents: Vec<Extent>,

    buffer: Vec<u8>,
    buffer_offset: u64, // into the volume
}
impl MftStream {
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

        let bytes_per_cluster = volume_info.BytesPerCluster.try_into().unwrap();

        Ok(MftStream {
            volume_handle,
            bytes_per_cluster,
            bytes_per_file_record_segment: volume_info
                .BytesPerFileRecordSegment
                .try_into()
                .unwrap(),
            len: unsafe { *volume_info.MftValidDataLength.QuadPart() }
                .try_into()
                .unwrap(),
            extents,
            // Keep a 4 MB buffer. Experimentation, at least on my device,
            // has shown this to be a good balance between reducing ReadFile
            // calls when reading sequential records and not taking to long
            // on extra ReadFile calls when reading non-resident data.
            buffer: vec![0; 4 * 1024 * 1024],
            buffer_offset: 0,
        })
    }

    pub fn get_file_record_segment_count(&self) -> u64 {
        self.len / self.bytes_per_file_record_segment
    }

    pub fn read_clusters(&mut self, lcn: u64, count: u64, buf: &mut [u8]) -> Result<(), Error> {
        debug_assert_eq!(buf.len() as u64, count * self.bytes_per_cluster);
        self.read_volume(lcn * self.bytes_per_cluster, buf)
    }

    pub fn read_file_record_segment(&mut self, segment: u64, buf: &mut [u8]) -> Result<(), Error> {
        debug_assert_eq!(0, self.len % self.bytes_per_file_record_segment);
        debug_assert_eq!(buf.len() as u64, self.bytes_per_file_record_segment);

        // Convert the segment to an LCN and offset. A file record segment can't be split
        // across multiple extents (I think/hope).
        let volume_offset: u64 = {
            // Convert the segment number to a offset in the file.
            let mut target_offset = segment * self.bytes_per_file_record_segment;
            let mut extent_idx = 0;
            loop {
                let extent = &self.extents[extent_idx];
                let extent_len = extent.cluster_count as u64 * self.bytes_per_cluster;
                if target_offset < extent_len {
                    // We found the correct extent!
                    let extent_start_lcn = extent.min_lcn as u64;

                    // #[cfg(debug_assertions)]
                    // {
                    //     println!(
                    //         "reading segment {} from extent {} (starting lcn: 0x{:X}, offset: 0x{:X})",
                    //         segment,
                    //         extent_idx,
                    //         extent_start_lcn,
                    //         (extent_start_lcn * self.bytes_per_cluster) + target_offset
                    //     );
                    // }

                    break Some((extent_start_lcn * self.bytes_per_cluster) + target_offset);
                } else {
                    extent_idx += 1;
                    target_offset -= extent_len;
                }

                if extent_idx >= self.extents.len() {
                    println!(
                        "WHOOPS: {:#?} {} {}",
                        self.extents, self.bytes_per_file_record_segment, segment,
                    );
                    break None;
                }
            }
        }
        .unwrap(); // TODO: proper error handling here

        self.read_volume(volume_offset, buf)
    }

    fn read_volume(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        {
            println!("read_volume: {:X}", offset);
        }

        let cur_buffer_end = self.buffer_offset + (self.buffer.len() as u64);
        let request_end = offset + (buf.len() as u64);

        if cur_buffer_end < request_end || offset < self.buffer_offset {
            // The read will go out of the buffer, so read a new one.
            #[cfg(debug_assertions)]
            {
                println!("reading new buffer");
            }

            self.buffer_offset = offset;

            let mut overlapped = {
                let offset: u64 = offset.try_into().unwrap();
                let mut ov = OVERLAPPED::default();
                unsafe { ov.u.s_mut() }.Offset =
                    (offset & 0x0000_0000_FFFF_FFFFu64).try_into().unwrap();
                unsafe { ov.u.s_mut() }.OffsetHigh = ((offset & 0xFFFF_FFFF_0000_0000u64) >> 32)
                    .try_into()
                    .unwrap();
                ov
            };

            let mut num_bytes_read = 0;
            let success = unsafe {
                ReadFile(
                    *self.volume_handle,
                    self.buffer.as_mut_ptr() as *mut c_void,
                    self.buffer.len().try_into().unwrap(),
                    &mut num_bytes_read,
                    &mut overlapped,
                )
            };
            if success == 0 {
                let err = unsafe { ehapi::GetLastError() };
                return Err(Error::ReadVolumeFailed(err));
            }
            let num_bytes_read: usize = num_bytes_read.try_into().unwrap();
            if num_bytes_read != self.buffer.len() {
                return Err(Error::ReadVolumeTooShort);
            }
        }

        let buffer_start: usize = (offset - self.buffer_offset).try_into().unwrap();
        let buffer_end = buffer_start + buf.len();
        buf.copy_from_slice(&self.buffer[buffer_start..buffer_end]);

        Ok(())
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
