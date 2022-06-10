use std::{collections::HashMap, ffi::OsString};

use smallvec::SmallVec;

use crate::mft::MftEntry;

struct Node {
    filename: Option<OsString>,
    size: u64,
    children_indices: Vec<u64>,
    parent_indices: SmallVec<[u64; 1]>,
}

pub struct FilesystemData {
    nodes: HashMap<u64, Node>,
    max_record_segment_index: u64,
    bytes_per_cluster: u64,
}
impl FilesystemData {
    pub fn new(bytes_per_cluster: u64, size_hint: usize) -> Self {
        FilesystemData {
            nodes: HashMap::with_capacity(size_hint),
            max_record_segment_index: 0,
            bytes_per_cluster,
        }
    }

    pub fn add_entry(&mut self, entry: MftEntry) {
        let idx = entry.base_record_segment_idx;
        let node = Node {
            filename: entry.get_best_filename(),
            size: entry.get_allocated_size(self.bytes_per_cluster, false),
            children_indices: Vec::new(),
            parent_indices: entry.parents().collect(),
        };

        self.nodes.insert(idx, node);
        if idx > self.max_record_segment_index {
            self.max_record_segment_index = idx;
        }
    }

    pub fn populate_children(&mut self) {
        for idx in (0u64..).take(self.max_record_segment_index as usize) {
            let parent_indices = if let Some(node) = self.nodes.get(&idx) {
                node.parent_indices.clone()
            } else {
                continue;
            };

            for parent_idx in parent_indices {
                if let Some(parent_node) = self.nodes.get_mut(&parent_idx) {
                    parent_node.children_indices.push(idx);
                }
            }
        }
    }
}
