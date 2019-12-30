mod err;
mod mft;
mod privileges;
mod volumes;

use clap::{App, Arg};
use indicatif::{BinaryBytes, HumanDuration, ProgressBar, ProgressIterator};
use winapi::um::{handleapi::CloseHandle, winnt::HANDLE};

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet},
    convert::TryInto as _,
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
        }
    }

    fn add_entry(&mut self, entry: mft::MftEntry, options: &Options) {
        let allowed_system =
            options.include_system || !entry.standard_information[0].flags.is_system;
        let allowed_hidden =
            !(options.skip_hidden && entry.standard_information[0].flags.is_hidden);

        if allowed_system && allowed_hidden {
            let extension = entry
                .get_best_filename()
                .and_then(|fname| Path::new(&fname).extension().map(|ext| ext.to_os_string()));

            let allowed_extension = match (options.extension_list.as_ref(), extension.as_ref()) {
                (Some((true, ref whitelist)), Some(extension)) => whitelist.contains(extension),
                (Some((false, ref blacklist)), Some(extension)) => !blacklist.contains(extension),
                (None, _) => true,
                (_, None) => false,
            };

            if allowed_extension {
                let size = entry.get_allocated_size(self.bytes_per_cluster, options.only_alt);
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

fn handle_volume(volume: volumes::VolumeInfo, options: &Options) -> Result<(), err::Error> {
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
        filesystem.add_entry(entry?, options);
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
    while count < options.max_count {
        if let Some(candidate_idx) = filesystem.allocated_size_heap.pop() {
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
        } else {
            break;
        }
    }

    println!();
    println!(
        "Largest directories on {} by total allocated size of immediate children:",
        filesystem.drive_letter
    );
    let mut directory_heap = BinaryHeap::new();
    for (dir, size) in filesystem.directory_size_map.iter() {
        directory_heap.push(SizeHeapEntry {
            index: *dir,
            size: *size,
        });
    }

    let mut count = 0;
    while count < options.max_count {
        if let Some(candidate_idx) = directory_heap.pop() {
            println!(
                "\t{}: {}",
                filesystem
                    .get_full_path(candidate_idx.index)
                    .expect("large directory with no name :/"),
                BinaryBytes(candidate_idx.size)
            );
            count += 1;
        } else {
            break;
        }
    }

    println!();
    println!(
        "Largest extensions on {} by total allocated size:",
        filesystem.drive_letter
    );
    let mut extension_heap = BinaryHeap::new();
    for (ext, size) in filesystem.extension_size_map.iter() {
        extension_heap.push(SizeHeapEntry {
            index: ext.clone(),
            size: *size,
        });
    }

    let mut count = 0;
    while count < options.max_count {
        if let Some(candidate_idx) = extension_heap.pop() {
            if let Some(extension) = candidate_idx.index {
                println!(
                    "\t{} (total size: {})",
                    extension.to_string_lossy(),
                    BinaryBytes(candidate_idx.size)
                );
                count += 1;
            }
        } else {
            break;
        }
    }

    println!();

    Ok(())
}

#[derive(Debug)]
struct Options {
    include_system: bool,
    skip_hidden: bool,
    only_alt: bool,
    skip_priv_check: bool,
    max_count: usize,
    extension_list: Option<(bool, HashSet<OsString>)>, // true for whitelist
}
impl Options {
    fn load() -> Self {
        let matches = App::new(APP_NAME)
        .version(APP_VERSION)
        .about(APP_DESCRIPTION)
        .arg(
            Arg::with_name("include_system")
                .short("i")
                .long("include_system")
                .help("Include files marked 'system' in the analysis"),
        )
        .arg(
            Arg::with_name("skip_hidden")
                .short("s")
                .long("skip_hidden")
                .help("Exclude files marked 'hidden' from the analysis"),
        )
        .arg(
            Arg::with_name("only_alt_data")
                .short("d")
                .long("only_alt_data")
                .help("Include only non-default $DATA streams in the analysis"),
        )
        .arg(
            Arg::with_name("skip_priv_check")
                .short("p")
                .long("skip_priv_check")
                .help("Skip the privilege check usually performed when the app starts"),
        )
        .arg(
            Arg::with_name("extension_whitelist")
                .short("w")
                .long("extension_whitelist")
                .help("A comma-separated list of extensions (do not include dots) to include in the analysis")
                .takes_value(true)
                .conflicts_with("extension_blacklist"),
        )
        .arg(
            Arg::with_name("extension_blacklist")
                .short("b")
                .long("extension_blacklist")
                .help("A comma-separated ist of extensions (do not include dots) to exclude from the analysis")
                .takes_value(true)
                .conflicts_with("extension_whitelist"),
        )
        .arg(
            Arg::with_name("max_count")
                .short("n")
                .long("max_count")
                .help("The maximum number of results to display")
                .takes_value(true),
        )
        .get_matches();

        Options {
            include_system: matches.is_present("include_system"),
            skip_hidden: matches.is_present("skip_hidden"),
            only_alt: matches.is_present("only_alt_data"),
            skip_priv_check: matches.is_present("skip_priv_check"),
            max_count: matches
                .value_of("max_count")
                .map(|c| c.parse().unwrap())
                .unwrap_or(5),
            extension_list: {
                if let Some(whitelist) = matches.value_of_os("extension_whitelist") {
                    let whitelist = whitelist
                        .to_string_lossy()
                        .split(',')
                        .map(|s| s.into()) // convert back to OsString
                        .collect();
                    Some((true, whitelist))
                } else if let Some(blacklist) = matches.value_of_os("extension_blacklist") {
                    let blacklist = blacklist
                        .to_string_lossy()
                        .split(',')
                        .map(|s| s.into()) // convert back to OsString
                        .collect();
                    Some((false, blacklist))
                } else {
                    None
                }
            },
        }
    }
}

fn main() {
    let options = Options::load();

    match privileges::has_sufficient_privileges() {
        Ok(true) => {}
        Ok(false) => {
            println!("{} must be run elevated!", APP_NAME);
            if options.skip_priv_check {
                println!("Continuing anyway, although things will almost certainly fail.");
            } else {
                return;
            }
        }
        Err(err) => {
            println!("Failed to check privilege level: {:?}", err);
            println!("Continuing anyway, although things will probably fail.");
        }
    }

    for volume in volumes::VolumeIterator::new().unwrap() {
        let volume = volume.unwrap();
        if !volume.paths.is_empty() {
            handle_volume(volume, &options).unwrap();
        }
    }
}
