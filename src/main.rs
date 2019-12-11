mod err;
mod mft;
mod privileges;
mod volumes;

fn main() {
    match privileges::has_sufficient_privileges() {
        Ok(true) => {}
        Ok(false) => {
            println!("Koumakan must be run elevated!");
            println!("Continuing anyway, although things will probably fail.");
        }
        Err(err) => {
            println!("Failed to check privilege level: {:?}", err);
            println!("Continuing anyway, although things will probably fail.");
        }
    }

    for volume in volumes::VolumeIterator::new().unwrap() {
        let volume = volume.unwrap();
        if !volume.paths.is_empty() {
            println!("Opening handle to {:?}", volume.paths[0]);

            match volume.get_handle() {
                Ok(handle) => {
                    println!("Counting MFT entries...");
                    let mft_iter = mft::MftEntryIterator::new(handle);

                    let mut count = 0;
                    let time_taken = chrono::Duration::span(|| {
                        count = mft_iter
                            .inspect(|x| {
                                if x.is_err() {
                                    panic!("wow")
                                }
                            })
                            .count();
                    });

                    println!("{} total MFT entries read in {:?}", count, time_taken);
                }
                Err(err) => {
                    println!("Failed to open volume handle: {:?}", err);
                }
            }
        }
    }
}
