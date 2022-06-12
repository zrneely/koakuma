use std::{collections::HashMap, ffi::OsString};

use smallvec::SmallVec;

use crate::{err::Error, mft::MftEntry};

struct Node {
    filename: Option<OsString>,
    self_size: u64,
    children_indices: Vec<u64>,
    recursive_size: u64,
    // The vast majority of files and directories have only one
    // parent, but they could have more than one if they are hardlinked
    // to multiple locations.
    parent_indices: SmallVec<[u64; 1]>,
}

pub struct FilesystemDataBuilder {
    nodes: HashMap<u64, Node>,
    max_record_segment_index: u64,
    bytes_per_cluster: u64,
}
impl FilesystemDataBuilder {
    pub fn new(bytes_per_cluster: u64, size_hint: usize) -> Self {
        FilesystemDataBuilder {
            nodes: HashMap::with_capacity(size_hint),
            max_record_segment_index: 0,
            bytes_per_cluster,
        }
    }

    pub fn add_entry(&mut self, entry: MftEntry) {
        let idx = entry.base_record_segment_idx;
        let size = entry.get_allocated_size(self.bytes_per_cluster, false);
        let node = Node {
            filename: entry.get_best_filename(),
            self_size: size,
            recursive_size: size,
            children_indices: Vec::new(),
            parent_indices: entry.parents().collect(),
        };

        self.nodes.insert(idx, node);
        if idx > self.max_record_segment_index {
            self.max_record_segment_index = idx;
        }
    }

    /// Call this after all entries are added
    pub fn finish(mut self) -> FilesystemData {
        let mut root_idx = None;

        // Pass 1: populate children
        for idx in (0u64..).take(self.max_record_segment_index as usize) {
            let parent_indices = if let Some(node) = self.nodes.get(&idx) {
                node.parent_indices.clone()
            } else {
                continue;
            };

            for parent_idx in parent_indices {
                if parent_idx == idx {
                    root_idx = Some(idx);
                } else if let Some(parent_node) = self.nodes.get_mut(&parent_idx) {
                    parent_node.children_indices.push(idx);
                }
            }
        }

        let root_idx = root_idx.expect("drive has no root");
        println!("Child pointers populated");

        // Pass 2: compute recursive size
        let mut recursive_parents = Vec::with_capacity(100);
        for idx in (0u64..).take(self.max_record_segment_index as usize) {
            recursive_parents.clear();

            let node_self_size = if let Some(node) = self.nodes.get(&idx) {
                recursive_parents.extend(&node.parent_indices);
                node.self_size
            } else {
                continue;
            };

            // Walk the parent tree, adding our own size to each parent's recursive size.
            // We can't use our own recursive size since it may not be accurate yet.
            while let Some(parent_idx) = recursive_parents.pop() {
                if let Some(parent) = self.nodes.get_mut(&parent_idx) {
                    parent.recursive_size = parent.recursive_size.saturating_add(node_self_size);

                    // Also add it to that node's parents
                    if parent_idx != root_idx {
                        recursive_parents.extend(&parent.parent_indices);
                    }
                }
            }
        }

        println!("Recursive sizes calculated");

        FilesystemData {
            bytes_per_cluster: self.bytes_per_cluster,
            nodes: self.nodes,
            root_idx,
        }
    }
}

pub struct FilesystemData {
    nodes: HashMap<u64, Node>,
    bytes_per_cluster: u64,
    root_idx: u64,
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
        node.parent_indices
            .get(0)
            .copied()
            .ok_or(Error::MissingParent)
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
