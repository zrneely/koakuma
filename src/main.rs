#![cfg_attr(feature = "cli", windows_subsystem = "console")]
#![cfg_attr(feature = "gui", windows_subsystem = "windows")]

mod err;
mod mft;
mod privileges;
mod volumes;

#[cfg(feature = "cli")]
mod cli;

#[cfg(feature = "gui")]
mod gui;

use windows::Win32::Foundation::{CloseHandle, HANDLE};

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet},
    ffi::OsString,
    ops::Deref,
    path::Path,
};

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

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
    extension_size_map: HashMap<Option<OsString>, u64>,
    directory_size_map: HashMap<u64, u64>,
    bytes_per_cluster: u64,

    count_system: bool,
    count_hidden: bool,
    extension_whitelist: Option<HashSet<OsString>>,
    extension_blacklist: Option<HashSet<OsString>>,
    only_count_alternate_datastreams: bool,
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
            directory_size_map: HashMap::new(),
            bytes_per_cluster,

            count_system: true,
            count_hidden: true,
            extension_whitelist: None,
            extension_blacklist: None,
            only_count_alternate_datastreams: false,
        }
    }

    fn add_entry(&mut self, entry: mft::MftEntry) {
        let allowed_system = self.count_system || !entry.standard_information[0].flags.is_system;
        let allowed_hidden = self.count_hidden || !entry.standard_information[0].flags.is_hidden;

        if allowed_system && allowed_hidden {
            let extension = entry
                .get_best_filename()
                .and_then(|fname| Path::new(&fname).extension().map(|ext| ext.to_os_string()));

            let allowed_whitelist = if let Some(ref whitelist) = self.extension_whitelist {
                if let Some(ref extension) = extension {
                    whitelist.contains(extension)
                } else {
                    // if the file doesn't have an extension and there's a whitelist, it
                    // can't match anything on the whitelist
                    false
                }
            } else {
                true
            };

            let allowed_blacklist = if let Some(ref blacklist) = self.extension_blacklist {
                if let Some(ref extension) = extension {
                    !blacklist.contains(extension)
                } else {
                    // if the file doesn't have an extension, it can't match the blacklist
                    true
                }
            } else {
                true
            };

            if allowed_blacklist && allowed_whitelist {
                let size = entry.get_allocated_size(
                    self.bytes_per_cluster,
                    self.only_count_alternate_datastreams,
                );
                self.allocated_size_heap.push(SizeHeapEntry {
                    index: entry.base_record_segment_idx,
                    size,
                });

                self.extension_size_map
                    .entry(extension)
                    .and_modify(|counter| {
                        *counter += size;
                    })
                    .or_insert(size);

                for parent in entry.parents() {
                    self.directory_size_map
                        .entry(parent)
                        .and_modify(|counter| {
                            *counter += size;
                        })
                        .or_insert(size);
                }
            }
        }

        self.entries.insert(entry.base_record_segment_idx, entry);
    }

    fn get_full_path(&self, entry: u64) -> Option<String> {
        let mut entry = self.entries.get(&entry)?;
        let mut result = self.drive_letter.clone();

        let mut parts = Vec::new();

        loop {
            let parents = entry.parents();

            if parents[0] != entry.base_record_segment_idx {
                parts.push(entry.get_best_filename()?);
                entry = self.entries.get(&parents[0])?;
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

#[cfg(feature = "cli")]
fn main() {
    cli::main();
}

#[cfg(feature = "gui")]
fn main() {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        APP_NAME,
        native_options,
        Box::new(|cc| Box::new(gui::KoakumaApp::new(cc))),
    );
}
