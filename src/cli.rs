use std::{
    collections::{BinaryHeap, HashSet},
    ffi::OsString,
};

use clap::{Arg, Command};
use indicatif::{BinaryBytes, HumanDuration, ProgressBar, ProgressIterator};

use crate::{err, mft, privileges, volumes, Filesystem, SizeHeapEntry, APP_NAME};

pub fn main() {
    let options = Options::load();

    match privileges::has_sufficient_privileges() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("{} must be run elevated!", APP_NAME);
            if options.skip_priv_check {
                println!("Continuing anyway, although things will almost certainly fail.");
            } else {
                return;
            }
        }
        Err(err) => {
            eprintln!("Failed to check privilege level: {:?}", err);
            println!("Continuing anyway, although things will probably fail.");
        }
    }

    for volume in volumes::VolumeIterator::new().unwrap() {
        match volume {
            Ok(volume) => {
                if !volume.paths.is_empty() {
                    if let Some(ref whitelist) = options.drive_letters {
                        let checker = |path: &OsString| {
                            if let Some(first_char) = path.to_string_lossy().chars().next() {
                                whitelist.contains(&first_char)
                            } else {
                                false
                            }
                        };

                        if !volume.paths.iter().any(checker) {
                            continue;
                        }
                    }

                    match handle_volume(volume, &options) {
                        Ok(_) => {}
                        Err(err) => {
                            eprintln!("Failed to process volume: {:?}", err);
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("VolumeIterator produced an error: {:?}", err);
            }
        }
    }
}

#[derive(Debug)]
struct Options {
    include_system: bool,
    skip_hidden: bool,
    only_alt: bool,
    skip_priv_check: bool,
    max_count: usize,
    extension_whitelist: Option<HashSet<OsString>>,
    extension_blacklist: Option<HashSet<OsString>>,
    drive_letters: Option<HashSet<char>>,
}
impl Options {
    fn load() -> Self {
        let matches = Command::new(crate::APP_NAME)
        .version(crate::APP_VERSION)
        .about(crate::APP_DESCRIPTION)
        .arg(
            Arg::new("include_system")
                .short('i')
                .long("include_system")
                .help("Include files marked 'system' in the analysis"),
        )
        .arg(
            Arg::new("skip_hidden")
                .short('s')
                .long("skip_hidden")
                .help("Exclude files marked 'hidden' from the analysis"),
        )
        .arg(
            Arg::new("only_alt_data")
                .short('d')
                .long("only_alt_data")
                .help("Include only non-default $DATA streams in the analysis"),
        )
        .arg(
            Arg::new("skip_priv_check")
                .short('p')
                .long("skip_priv_check")
                .help("Skip the privilege check usually performed when the app starts"),
        )
        .arg(
            Arg::new("extension_whitelist")
                .short('w')
                .long("extension_whitelist")
                .help("A comma-separated list of extensions (do not include dots) to include in the analysis")
                .takes_value(true)
                .conflicts_with("extension_blacklist"),
        )
        .arg(
            Arg::new("extension_blacklist")
                .short('b')
                .long("extension_blacklist")
                .help("A comma-separated ist of extensions (do not include dots) to exclude from the analysis")
                .takes_value(true)
                .conflicts_with("extension_whitelist"),
        )
        .arg(
            Arg::new("max_count")
                .short('n')
                .long("max_count")
                .help("The maximum number of results to display")
                .takes_value(true),
        )
        .arg(
            Arg::new("drive")
                .short('f')
                .long("drive")
                .help("A comma-separated list of drive letters to include in the analysis. All drives will be included if not specified.")
                .takes_value(true)
        )
        .get_matches();

        Options {
            include_system: matches.is_present("include_system"),
            skip_hidden: matches.is_present("skip_hidden"),
            only_alt: matches.is_present("only_alt_data"),
            skip_priv_check: matches.is_present("skip_priv_check"),
            max_count: matches
                .value_of("max_count")
                .and_then(|c| c.parse().ok())
                .unwrap_or(5),
            extension_whitelist: matches.value_of_os("extension_whitelist").map(|whitelist| {
                whitelist
                    .to_string_lossy()
                    .split(',')
                    .map(|s| s.into())
                    .collect()
            }),
            extension_blacklist: matches.value_of_os("extension_blacklist").map(|blacklist| {
                blacklist
                    .to_string_lossy()
                    .split(',')
                    .map(|s| s.into())
                    .collect()
            }),
            drive_letters: {
                matches.value_of_os("drive").map(|values| {
                    values
                        .to_string_lossy()
                        .split(',')
                        .filter_map(|s| s.chars().next())
                        .collect()
                })
            },
        }
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

    filesystem.count_hidden = !options.skip_hidden;
    filesystem.count_system = options.include_system;
    filesystem.only_count_alternate_datastreams = options.only_alt;
    filesystem.extension_blacklist = options.extension_blacklist.clone();
    filesystem.extension_whitelist = options.extension_whitelist.clone();

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
    while count < options.max_count {
        if let Some(candidate_idx) = filesystem.allocated_size_heap.pop() {
            if candidate_idx.index < 24 {
                // The first 24 files are special and shouldn't be reported to the user.
                // See https://flatcap.github.io/linux-ntfs/ntfs/files/index.html.
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
