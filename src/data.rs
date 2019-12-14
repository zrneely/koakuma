use crate::journal::JournalEntry;

use std::{collections::HashMap, iter::FromIterator};

#[derive(Debug)]
struct SizeData {
    total: u64,
    cloudfiles: u64,
    sparse: u64,
}

struct VolumeData {
    files: HashMap<u128, JournalEntry>,
    folders: HashMap<u128, JournalEntry>,
    extension_sizes: HashMap<String, u64>,
}
impl FromIterator<JournalEntry> for VolumeData {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = JournalEntry>,
    {
        unimplemented!()
    }
}
