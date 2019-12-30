mod err;
mod mft;
mod privileges;
mod volumes;

use indicatif::{BinaryBytes, HumanDuration, ProgressBar, ProgressIterator};
use winapi::um::{handleapi::CloseHandle, winnt::HANDLE};

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    convert::TryInto as _,
    ffi::OsString,
    ops::Deref,
    path::Path,
};

#[derive(Debug)]
pub struct SafeHandle {
    handle: HANDLE,
}
impl Deref for SafeHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}
impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

#[derive(PartialEq, Eq)]
struct SizeHeapEntry<I> {
    index: I,
    size: u64,
}
impl<I: PartialOrd> PartialOrd for SizeHeapEntry<I> {
    fn partial_cmp(&self, other: &SizeHeapEntry<I>) -> Option<Ordering> {
        self.size.partial_cmp(&other.size)
    }
}
impl<I: Ord> Ord for SizeHeapEntry<I> {
    fn cmp(&self, other: &SizeHeapEntry<I>) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

struct Filesystem {
    drive_letter: String,
    entries: HashMap<u64, mft::MftEntry>,
    allocated_size_heap: BinaryHeap<SizeHeapEntry<u64>>,
    extension_size_map: HashMap<Option<OsString>, (u64, Vec<u64>)>,
    bytes_per_cluster: u64,
}
impl Filesystem {
    fn new(drive_letter: OsString, bytes_per_cluster: u64, entry_count: usize) -> Self {
        Filesystem {
            drive_letter: {
                let mut drive_letter = drive_letter.to_string_lossy().into_owned();
                if drive_letter.ends_with('\\') {
                    drive_letter.pop();
                }
                drive_letter
            },
            entries: HashMap::with_capacity(entry_count),
            allocated_size_heap: BinaryHeap::with_capacity(entry_count),
            extension_size_map: HashMap::new(),
            bytes_per_cluster,
        }
    }

    fn add_entry(&mut self, entry: mft::MftEntry) {
        if !entry.standard_information[0].flags.is_system {
            let extension = entry
                .get_best_filename()
                .and_then(|fname| Path::new(&fname).extension().map(|ext| ext.to_os_string()));
            let size = entry.get_allocated_size(self.bytes_per_cluster);

            self.extension_size_map
                .entry(extension)
                .and_modify(|&mut (ref mut counter, ref mut indecies)| {
                    *counter += size;
                    indecies.push(entry.base_record_segment_idx);
                })
                .or_insert((size, vec![entry.base_record_segment_idx]));
            self.allocated_size_heap.push(SizeHeapEntry {
                index: entry.base_record_segment_idx,
                size,
            });
        }

        self.entries.insert(entry.base_record_segment_idx, entry);
    }

    fn get_full_path(&self, entry: u64) -> Option<String> {
        let mut entry = self.entries.get(&entry).unwrap();
        let mut result = self.drive_letter.clone();

        let mut parts = Vec::new();

        loop {
            let parents = entry.parents();

            if parents[0] != entry.base_record_segment_idx {
                parts.push(entry.get_best_filename()?);
                entry = self.entries.get(&parents[0]).unwrap();
            } else {
                break;
            }
        }

        for part in parts.iter().rev() {
            result.push('\\');
            result.push_str(&part.to_string_lossy());
        }

        Some(result)
    }
}

fn handle_volume(volume: volumes::VolumeInfo) -> Result<(), err::Error> {
    println!("Reading {}...", volume.paths[0].to_string_lossy());

    let handle = volume.get_handle()?;
    let (mft, bytes_per_cluster) = mft::MasterFileTable::load(handle, &volume.paths[0])?;
    let entry_count = mft.entry_count();

    let begin = std::time::Instant::now();
    let mut filesystem = Filesystem::new(
        volume.paths[0].clone(),
        bytes_per_cluster,
        mft.entry_count().try_into().unwrap(),
    );

    let progress = ProgressBar::new(entry_count);
    progress.set_draw_delta(entry_count / 20);
    for entry in mft.progress_with(progress) {
        filesystem.add_entry(entry?);
    }

    let time_taken = begin.elapsed();
    println!(
        "Read {} MFT entries in {} ({:.0} entries/sec)",
        entry_count,
        HumanDuration(time_taken),
        1000f64 * (entry_count as f64) / (time_taken.as_millis() as f64)
    );

    println!(
        "Largest files on {} by allocated size:",
        filesystem.drive_letter
    );
    let mut count = 0;
    while count < 5 {
        let candidate_idx = filesystem.allocated_size_heap.pop().unwrap();
        if candidate_idx.index < 24 {
            // The first 24 files are special and shouldn't be reported to the user.
            // See https://flatcap.org/linux-ntfs/ntfs/files/index.html.
            continue;
        }

        println!(
            "\t{}: {}",
            filesystem
                .get_full_path(candidate_idx.index)
                .expect("large file with no name :/"),
            BinaryBytes(candidate_idx.size),
        );
        count += 1;
    }

    println!();
    println!(
        "Largest extensions on {} by total allocated size:",
        filesystem.drive_letter
    );
    let mut extension_heap = BinaryHeap::new();
    for (ext, (size, _)) in filesystem.extension_size_map.iter() {
        extension_heap.push(SizeHeapEntry {
            index: ext.clone(),
            size: *size,
        });
    }

    let mut count = 0;
    while count < 5 {
        let candidate_idx = extension_heap.pop().unwrap();
        if let Some(extension) = candidate_idx.index {
            println!(
                "\t{} (total size: {})",
                extension.to_string_lossy(),
                BinaryBytes(candidate_idx.size)
            );
            count += 1;
        }
    }

    println!();

    Ok(())
}

fn main() {
    match privileges::has_sufficient_privileges() {
        Ok(true) => {}
        Ok(false) => {
            println!("Koumakan must be run elevated!");
            println!("Continuing anyway, although things will almost certainly fail.");
        }
        Err(err) => {
            println!("Failed to check privilege level: {:?}", err);
            println!("Continuing anyway, although things will probably fail.");
        }
    }

    for volume in volumes::VolumeIterator::new().unwrap() {
        let volume = volume.unwrap();
        if !volume.paths.is_empty() {
            handle_volume(volume).unwrap();
        }
    }
}
