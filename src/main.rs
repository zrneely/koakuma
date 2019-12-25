mod err;
mod mft;
mod privileges;
mod volumes;

use winapi::um::{
    handleapi::CloseHandle,
    winnt::{CHAR, HANDLE},
};

use std::ops::Deref;

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

#[link(name = "ntdll")]
extern "C" {
    fn RtlSetThreadPlaceholderCompatibilityMode(Mode: CHAR) -> CHAR;
}

fn main() {
    let old_compat_mode = unsafe { RtlSetThreadPlaceholderCompatibilityMode(2) };
    if old_compat_mode != 2 {
        println!(
            "Changed placeholder compatibility mode from {} to 2!",
            old_compat_mode
        );
    }

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
            println!("Opening handle to {:?}...", volume.paths[0]);

            match volume.get_handle() {
                Ok(handle) => {
                    println!("Reading MFT...");
                    let mft = mft::MasterFileTable::load(handle, &volume.paths[0]).unwrap();
                    println!(
                        "Loaded MFT. Length: {}; Entries: {}",
                        mft.len(),
                        mft.entry_count()
                    );

                    println!(
                        "Enumerated all entries in {:?}",
                        chrono::Duration::span(|| {
                            let mut entries = 0;
                            for entry in mft {
                                let entry = entry.unwrap();
                                entries += 1;

                                if entries % 10000 == 0 {
                                    println!("Read {} entries...", entries);
                                }
                            }

                            println!("Read {} entries total", entries);
                        })
                    );
                }
                Err(err) => {
                    println!("Failed to open volume handle: {:?}", err);
                }
            }
        }
    }
}
