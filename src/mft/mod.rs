use crate::{err::Error, SafeHandle};

use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi as ehapi,
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::INVALID_HANDLE_VALUE,
        ioapiset::DeviceIoControl,
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
    ffi::{OsStr, OsString},
    mem,
    os::windows::ffi::{OsStrExt as _, OsStringExt as _},
    path::Path,
    ptr,
};

mod stream;
pub mod sys;

use stream::MftStream;

const NTFS_VOLUME_DATA_BUFFER_SIZE: usize =
    mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() + mem::size_of::<NTFS_EXTENDED_VOLUME_DATA>();

#[derive(Debug)]
pub struct MftEntry {
    pub base_record_segment_idx: u64,
    pub hard_link_count: u16,
    pub standard_information: Vec<sys::StandardInformation>,
    pub filename: Vec<sys::FileName>,
    pub data: Vec<sys::Data>,
}
impl MftEntry {
    pub fn get_best_filename(&self) -> Option<OsString> {
        self.filename.first().map(|e| e.filename.clone())
    }

    pub fn parents(&self) -> Vec<u64> {
        self.filename.iter().map(|f| f.parent).collect()
    }

    pub fn get_allocated_size(&self, bytes_per_cluster: u64, only_alt: bool) -> u64 {
        self.data
            .iter()
            .filter(|data| !(only_alt && data.name.is_none()))
            .map(|data| data.compute_allocated_size(bytes_per_cluster))
            .sum()
    }
}

pub struct MasterFileTable {
    mft_stream: MftStream,
    bytes_per_file_record_segment: u64,
    bytes_per_sector: u64,
    bytes_per_cluster: u64,
    current_file_record_segment: u64,
}
impl MasterFileTable {
    pub fn load(volume_handle: SafeHandle, volume_path: &OsStr) -> Result<(Self, u64), Error> {
        let (volume_data, extended_data) = get_ntfs_volume_data(&volume_handle)?;

        // We only know how to deal with NTFS 3.0 or 3.1 data. Make sure the volume
        // is the correct NTFS version.
        if !(extended_data.MajorVersion == 3
            && (extended_data.MinorVersion == 0 || extended_data.MinorVersion == 1))
        {
            return Err(Error::UnknownNtfsVersion);
        }

        let mft_handle = get_mft_handle(volume_path)?;

        Ok((
            MasterFileTable {
                mft_stream: MftStream::new(volume_handle, volume_data, &mft_handle)?,
                bytes_per_file_record_segment: volume_data.BytesPerFileRecordSegment.into(),
                bytes_per_sector: volume_data.BytesPerSector.into(),
                bytes_per_cluster: volume_data.BytesPerCluster.into(),
                current_file_record_segment: 0,
            },
            volume_data.BytesPerCluster.into(),
        ))
    }

    pub fn entry_count(&self) -> u64 {
        self.mft_stream.get_file_record_segment_count()
    }

    // private helpers

    fn parse_resident_attribute(
        &mut self,
        attrib_header: &sys::AttributeRecordHeader,
        resident_header: &sys::AttributeRecordHeaderResident,
        attribute_name: Option<OsString>,
        attribute_data: &[u8],
        current_file_record_segment: u64,
        entry: &mut MftEntry,
    ) -> Result<(), Error> {
        use sys::AttributeType;

        match attrib_header.type_code {
            AttributeType::StandardInformation => {
                entry
                    .standard_information
                    .push(sys::StandardInformation::load(
                        attribute_data,
                        attribute_name,
                    )?);
            }

            AttributeType::FileName => {
                entry
                    .filename
                    .push(sys::FileName::load(attribute_data, attribute_name)?);
            }

            // For resident DATA streams, we report physical size equal to the
            // logical size.
            AttributeType::Data => {
                entry.data.push(sys::Data {
                    name: attribute_name,
                    logical_size: resident_header.value_length.into(),
                    physical_size: resident_header.value_length.into(),
                    runs: None,
                    is_sparse: false, // resident DATA can't be sparse
                });
            }

            AttributeType::AttributeList => {
                #[cfg(debug_assertions)]
                {
                    println!("Reading resident attribute list");
                }
                self.parse_attribute_list(attribute_data, current_file_record_segment, entry)?;
            }

            type_code @ AttributeType::IndexAllocation => {
                return Err(Error::UnsupportedResident(type_code));
            }

            AttributeType::SecurityDescriptor
            | AttributeType::LoggedUtilityStream
            | AttributeType::Ea
            | AttributeType::EaInformation
            | AttributeType::ObjectId
            | AttributeType::VolumeInformation
            | AttributeType::VolumeName
            | AttributeType::IndexRoot
            | AttributeType::Bitmap
            | AttributeType::ReparsePoint => {}
        };

        Ok(())
    }

    fn parse_non_resident_attribute(
        &mut self,
        attrib_header: &sys::AttributeRecordHeader,
        non_resident_header: &sys::AttributeRecordHeaderNonResident,
        attribute_name: Option<OsString>,
        current_file_record_segment: u64,
        data_runs: &[u8],
        entry: &mut MftEntry,
    ) -> Result<(), Error> {
        use sys::AttributeType;

        match attrib_header.type_code {
            type_code @ AttributeType::StandardInformation
            | type_code @ AttributeType::ObjectId
            | type_code @ AttributeType::VolumeName
            | type_code @ AttributeType::VolumeInformation
            | type_code @ AttributeType::EaInformation
            | type_code @ AttributeType::FileName
            | type_code @ AttributeType::ReparsePoint
            | type_code @ AttributeType::IndexRoot => {
                return Err(Error::UnsupportedNonResident(type_code))
            }

            AttributeType::Data => entry.data.push(sys::Data {
                name: attribute_name,
                logical_size: non_resident_header.file_size,
                physical_size: non_resident_header.allocated_length,
                runs: {
                    let (_, runs) = self.read_data_run_list(data_runs);
                    Some(runs)
                },
                is_sparse: attrib_header.is_sparse,
            }),

            AttributeType::AttributeList => {
                // We actually need to go read this
                let (total_size, data_runs) = self.read_data_run_list(data_runs);
                let data = self.read_non_resident_data(total_size, data_runs)?;
                debug_assert_eq!(data.len(), non_resident_header.allocated_length as usize);

                self.parse_attribute_list(
                    &data[..non_resident_header.valid_data_length as usize],
                    current_file_record_segment,
                    entry,
                )?;
            }

            AttributeType::SecurityDescriptor
            | AttributeType::LoggedUtilityStream
            | AttributeType::Ea
            | AttributeType::Bitmap
            | AttributeType::IndexAllocation => {}
        };

        Ok(())
    }

    fn parse_segment(
        &mut self,
        segment_header: &sys::FileRecordSegmentHeader,
        current_file_record_segment: u64,
        allow_extensions: bool,
        buf: &[u8],
        entry: &mut MftEntry,
    ) -> Result<bool, Error> {
        if !allow_extensions
            && ((segment_header.base_file_record_segment.segment_number_low != 0)
                || (segment_header.base_file_record_segment.segment_number_high != 0))
        {
            // This is an extension of a previous record; skip it.
            #[cfg(debug_assertions)]
            {
                println!("Skipping extension record: {}", current_file_record_segment);
            }
            return Ok(false);
        }

        let mut attribute_buffer = &buf[segment_header.first_attribute_offset as usize..];
        loop {
            let attrib_header = sys::AttributeRecordHeader::load(attribute_buffer)?;

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
                    let (resident_header, _) = sys::AttributeRecordHeaderResident::load(
                        &attribute_buffer[sys::ATTRIBUTE_RECORD_HEADER_LENGTH..],
                    );
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
                        attribute_data,
                        current_file_record_segment,
                        entry,
                    )?;
                }

                sys::form_codes::NON_RESIDENT => {
                    let (nonresident_header, _) = sys::AttributeRecordHeaderNonResident::load(
                        &attribute_buffer[sys::ATTRIBUTE_RECORD_HEADER_LENGTH..],
                    );

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
                        entry,
                    )?;
                }

                unknown => {
                    return Err(Error::UnknownFormCode(unknown));
                }
            }

            attribute_buffer = &attribute_buffer[attrib_header.record_length.try_into().unwrap()..];
            if attribute_buffer.len() <= 4 || attribute_buffer[0..4] == [0xFF, 0xFF, 0xFF, 0xFF] {
                break;
            }
        }

        Ok(true)
    }

    fn parse_attribute_list(
        &mut self,
        mut buf: &[u8],
        current_file_record_segment: u64,
        entry: &mut MftEntry,
    ) -> Result<(), Error> {
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

            buf = &buf[record_len..];

            let segment_to_read = attrib.segment_reference.into();
            if segment_to_read != current_file_record_segment {
                record_segments.insert(segment_to_read);
            }
        }

        for segment_to_read in record_segments {
            // Read the segment
            self.mft_stream.read_file_record_segment(
                segment_to_read,
                &mut segment_buf[..],
                false, // use_cache
            )?;
            let segment_header = sys::FileRecordSegmentHeader::load(&segment_buf[..])?
                .ok_or(Error::AttributeListPointedToUnusedFileRecord)?;
            self.fix_record_with_update_sequence(
                &segment_header.multi_sector_header,
                &mut segment_buf[..],
            )?;

            self.parse_segment(
                &segment_header,
                segment_to_read,
                true,
                &segment_buf[..],
                entry,
            )?;
        }

        Ok(())
    }

    // The data must start on a sector boundary (will be the case for all file record segments).
    fn fix_record_with_update_sequence(
        &self,
        header: &sys::MultiSectorHeader,
        data: &mut [u8],
    ) -> Result<(), Error> {
        // First, find the update sequence array
        let start_offset: usize = header.update_sequence_array_offset.try_into().unwrap();

        let end_offset = {
            let size: usize = header.update_sequence_array_size.try_into().unwrap();
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

    fn read_data_run_list(&self, data_runs: &[u8]) -> (u64, Vec<sys::DataRun>) {
        let mut runs = Vec::new();
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

            runs.push(sys::DataRun {
                starting_lcn: offset,
                cluster_count: length,
            });

            last_offset = offset;
            total_size += length * self.bytes_per_cluster;
        }
        (total_size, runs)
    }

    fn read_non_resident_data(
        &mut self,
        total_size: u64,
        data_runs: Vec<sys::DataRun>,
    ) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![0; total_size.try_into().unwrap()];
        let mut cur_buf_offset: usize = 0;

        for run in data_runs {
            let end_offset: usize =
                cur_buf_offset + (run.cluster_count * self.bytes_per_cluster) as usize;
            self.mft_stream.read_clusters(
                run.starting_lcn as u64,
                run.cluster_count,
                &mut buffer[cur_buf_offset..end_offset],
                false, // use_cache
            )?;

            cur_buf_offset += (self.bytes_per_cluster * run.cluster_count) as usize;
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
            if self.current_file_record_segment >= self.mft_stream.get_file_record_segment_count() {
                break None;
            }

            match self.mft_stream.read_file_record_segment(
                self.current_file_record_segment,
                &mut segment_buffer[..],
                true, // use_cache
            ) {
                Ok(_) => {}
                Err(err) => break Some(Err(err)),
            }

            // If the buffer's header is 0's instead of "FILE", just skip
            if segment_buffer.iter().take(4).all(|x| *x == 0) {
                #[cfg(debug_assertions)]
                {
                    println!(
                        "Skipping empty record: {}",
                        self.current_file_record_segment
                    );
                }

                self.current_file_record_segment += 1;
                continue;
            }

            let segment_header = match sys::FileRecordSegmentHeader::load(&segment_buffer[..]) {
                Ok(Some(header)) => header,
                Ok(None) => {
                    #[cfg(debug_assertions)]
                    {
                        println!(
                            "Skipping non-used record: {}",
                            self.current_file_record_segment
                        );
                    }

                    self.current_file_record_segment += 1;
                    continue;
                }
                Err(err) => break Some(Err(err)),
            };

            // Use the update sequence array to validate and correct the buffer.
            match self.fix_record_with_update_sequence(
                &segment_header.multi_sector_header,
                &mut segment_buffer[..],
            ) {
                Ok(_) => {}
                Err(err) => break Some(Err(err)),
            }

            let mut entry = MftEntry {
                base_record_segment_idx: self.current_file_record_segment,
                hard_link_count: segment_header.hard_link_count,
                // children: Default::default(),
                data: Default::default(),
                filename: Default::default(),
                standard_information: Default::default(),
            };

            match self.parse_segment(
                &segment_header,
                self.current_file_record_segment,
                false, // allow extensions
                &segment_buffer[..],
                &mut entry,
            ) {
                Ok(true) => {
                    self.current_file_record_segment += 1;
                    entry.filename.sort_by_key(|f| f.filename_type.clone());
                    break Some(Ok(entry));
                }
                Ok(false) => {
                    self.current_file_record_segment += 1;
                    continue;
                }
                Err(err) => break Some(Err(err)),
            };
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

fn parse_runlist_unsigned_int(data: &[u8], width: u8) -> u64 {
    #[repr(align(8))]
    struct Align8([u8; 8]);

    if width == 0 {
        return 0;
    }

    let mut out = Align8([0u8; 8]);
    let ptr_out = out.0.as_mut_ptr();
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr_out, width as usize);

        #[allow(clippy::cast_ptr_alignment)]
        {
            *(ptr_out as *const u64)
        }
    }
}

fn parse_runlist_signed_int(data: &[u8], width: u8) -> i64 {
    #[inline]
    fn extend_sign(val: u64, width: usize) -> i64 {
        let shift = (8 - width) * 8;
        (val << shift) as i64 >> shift
    }

    if width == 0 {
        return 0;
    }

    extend_sign(parse_runlist_unsigned_int(data, width), width.into())
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
