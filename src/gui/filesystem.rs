use std::{
    collections::{HashMap, VecDeque},
    ffi::OsString,
};

use crate::{err::Error, mft::MftEntry};

#[derive(Debug)]
struct Node {
    filename: Option<OsString>,
    self_size: u64,
    children_indices: Vec<u64>,
    recursive_size: u64,
    parent_index: u64,
}

pub struct FilesystemDataBuilder {
    nodes: HashMap<u64, Node>,
    max_record_segment_index: u64,
    bytes_per_cluster: u64,
    drive_letter: OsString,
}
impl FilesystemDataBuilder {
    pub fn new(drive_letter: OsString, bytes_per_cluster: u64, size_hint: usize) -> Self {
        FilesystemDataBuilder {
            nodes: HashMap::with_capacity(size_hint),
            max_record_segment_index: 0,
            bytes_per_cluster,
            drive_letter,
        }
    }

    pub fn add_entry(&mut self, entry: MftEntry) {
        if Self::should_exclude(&entry) {
            return;
        }

        let idx = entry.base_record_segment_idx;
        let size = entry.get_allocated_size(self.bytes_per_cluster, false);
        let node = Node {
            filename: entry.get_best_filename(),
            self_size: size,
            recursive_size: size,
            children_indices: Vec::new(),
            // The vast majority of files and directories have only one
            // parent, but they could have more than one if they are hardlinked
            // to multiple locations. However, counting them more than one can
            // lead to double counting sizes. Pick only the first parent - if
            // there are multiple, it's *probably* the 8.3 filename, and any other
            // scenario is probably rare enough that we don't care.
            parent_index: entry.parents().next().unwrap(),
        };

        self.nodes.insert(idx, node);
        if idx > self.max_record_segment_index {
            self.max_record_segment_index = idx;
        }
    }

    fn should_exclude(entry: &MftEntry) -> bool {
        // The first 24 files are special and some shouldn't be reported to the user.
        // See https://flatcap.github.io/linux-ntfs/ntfs/files/index.html.
        match entry.base_record_segment_idx {
            8 => true, // $BadClus - lists known bad clusters; "allocated size" is not actually allocated
            12..=23 => true, // Always unused
            _ => false,
        }
    }

    /// Call this after all entries are added
    pub fn finish(mut self) -> FilesystemData {
        let mut root_idx = None;

        // Pass 1: populate children
        for idx in (0u64..).take(self.max_record_segment_index as usize) {
            let parent_index = if let Some(node) = self.nodes.get(&idx) {
                node.parent_index
            } else {
                continue;
            };

            if parent_index == idx {
                root_idx = Some(idx);
            } else if let Some(parent_node) = self.nodes.get_mut(&parent_index) {
                parent_node.children_indices.push(idx);
            }
        }

        let root_idx = root_idx.expect("drive has no root");
        println!("Child pointers populated");

        // Pass 2: compute recursive size
        for idx in (0u64..).take(self.max_record_segment_index as usize) {
            let mut next_parent;
            let node_self_size = if let Some(node) = self.nodes.get(&idx) {
                next_parent = node.parent_index;
                node.self_size
            } else {
                continue;
            };

            // Walk the parent tree, adding our own size to each parent's recursive size.
            // We can't use our own recursive size since it may not be accurate yet.
            loop {
                if let Some(parent) = self.nodes.get_mut(&next_parent) {
                    parent.recursive_size = parent.recursive_size.saturating_add(node_self_size);

                    // Also add it to that node's parents
                    if next_parent != root_idx {
                        next_parent = parent.parent_index;
                    } else {
                        break;
                    }
                }
            }
        }

        println!("Recursive sizes calculated");

        FilesystemData {
            nodes: self.nodes,
            drive_letter: self.drive_letter,
            root_idx,
        }
    }
}

#[derive(Debug)]
pub struct FilesystemData {
    nodes: HashMap<u64, Node>,
    root_idx: u64,
    drive_letter: OsString,
}
impl FilesystemData {
    pub fn get_root_node(&self) -> u64 {
        self.root_idx
    }

    pub fn get_children<'a>(
        &'a self,
        node: u64,
    ) -> Result<Option<impl Iterator<Item = u64> + 'a>, Error> {
        let node = self.nodes.get(&node).ok_or(Error::NoSuchNode)?;
        Ok(if node.children_indices.is_empty() {
            None
        } else {
            Some(FilesystemChildrenIterator { node, idx: 0 })
        })
    }

    pub fn get_parent(&self, node: u64) -> Result<u64, Error> {
        let node = self.nodes.get(&node).ok_or(Error::NoSuchNode)?;
        Ok(node.parent_index)
    }

    pub fn get_full_path(&self, node: u64) -> Result<Option<OsString>, Error> {
        let mut path_segments = VecDeque::new();
        let mut cur_node = node;

        loop {
            match self.get_filename(cur_node)? {
                Some(segment) => path_segments.push_front(segment),
                None => return Ok(None),
            }

            let parent = self.get_parent(cur_node)?;

            // don't include the root, to avoid paths like "C:\.\foo\bar"
            if parent == self.root_idx {
                let mut result = self.drive_letter.clone();
                for (idx, segment) in path_segments.into_iter().enumerate() {
                    if idx != 0 {
                        result.push("\\");
                    }
                    result.push(segment);
                }
                return Ok(Some(result));
            } else {
                cur_node = parent;
            }
        }
    }

    pub fn get_filename(&self, node: u64) -> Result<Option<OsString>, Error> {
        let node = self.nodes.get(&node).ok_or(Error::NoSuchNode)?;
        Ok(node.filename.clone())
    }

    pub fn get_allocated_size(&self, node: u64) -> Result<u64, Error> {
        let node = self.nodes.get(&node).ok_or(Error::NoSuchNode)?;
        Ok(node.self_size)
    }

    pub fn get_allocated_size_recursive(&self, node: u64) -> Result<u64, Error> {
        let node = self.nodes.get(&node).ok_or(Error::NoSuchNode)?;
        Ok(node.recursive_size)
    }
}

struct FilesystemChildrenIterator<'a> {
    node: &'a Node,
    idx: usize,
}
impl<'a> Iterator for FilesystemChildrenIterator<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.node.children_indices.get(self.idx).cloned();
        self.idx += 1;
        result
    }
}
