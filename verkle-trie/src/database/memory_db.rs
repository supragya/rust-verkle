use super::{BranchChild, Flush, ReadOnlyHigherDb, WriteOnlyHigherDb};
use crate::database::{BranchMeta, StemMeta};
use std::{collections::{HashMap, HashSet}, convert::TryInto};
extern crate queues;
use ark_serialize::CanonicalSerialize;
use queues::*;

#[derive(Debug, Clone)]
pub struct MemoryDb {
    pub leaf_table: HashMap<[u8; 32], [u8; 32]>,
    pub stem_table: HashMap<[u8; 31], StemMeta>,
    // TODO maybe change to use BChild and also include the index in the key (Vec<u8>, u8)
    pub branch_table: HashMap<Vec<u8>, BranchChild>,
}

impl MemoryDb {
    pub fn new() -> Self {
        MemoryDb {
            leaf_table: HashMap::new(),
            stem_table: HashMap::new(),
            branch_table: HashMap::new(),
        }
    }

    pub fn num_items(&self) -> usize {
        self.leaf_table.len() + self.stem_table.len() + self.branch_table.len()
    }

    pub fn clear(&mut self) {
        self.leaf_table.clear();
        self.stem_table.clear();
        self.branch_table.clear();
    }

    pub fn to_dot(&self, file: &str) {
        const lrbox: &str = "fillcolor=\"#e3dfa4\"\nfontname=\"Courier New\"\nstyle=\"filled\"\nshape=\"box\"\n";
        const lbbox: &str = "fillcolor=\"#cbf1f7\"\nfontname=\"Courier New\"\nstyle=\"filled\"\nshape=\"box\"\n";
        const lgbox: &str = "fillcolor=\"#f3f9ed\"\nfontname=\"Courier New\"\nstyle=\"filled\"\nshape=\"box\"\n";

        let root = hex::decode("00000000000000000000000000000000").unwrap();

        // Dot gen
        let mut dot = "digraph D {\n".to_string();
        let mut root_commitment: String = "".to_string();
        let root_meta = self.branch_table.get(&vec![]);
        if let Some(BranchChild::Branch(x)) = root_meta {
            let mut comm_serialised = [0u8; 32];
            x.commitment.serialize(&mut comm_serialised[..]).unwrap();
            let comm_str = hex::encode(comm_serialised);
            root_commitment = comm_str.replace("\"", "'");
        }

        let mut queue: Queue<(Option<Vec<u8>>, Vec<u8>)> = queue![(None, vec![])];
        while queue.size() > 0 {
            let node = queue.remove().unwrap();
            if node.0 == None {
                dot = dot + format!("{} [{}label=\"{}\"]\n", "root", lrbox, format!(
                    "ROOT\nrootcomm: '{}'",
                    root_commitment,
                )).as_str();
            } else {
                let mut parent = "n".to_string() + hex::encode(node.0.unwrap()).as_str();
                if parent == "n".to_string() {
                    parent = "root".to_string();
                }
                let me = "n".to_string() + hex::encode(node.1.clone()).as_str();
                let branchinfo = self.branch_table.get(&node.1).unwrap();
                match branchinfo {
                    &BranchChild::Branch(x) => {
                        // Internal node
                        let mut comm_serialised = [0u8; 32];
                        x.commitment.serialize(&mut comm_serialised[..]).unwrap();
                        let comm_str = hex::encode(comm_serialised);

                        // node creation
                        dot = dot
                        + format!(
                            "{} [{}label=\"{}\"]\n{} -> {}\n",
                            me,
                            lbbox,
                            format!(
                                "InternalNode: {}\ncomm: {}",
                                me,
                                comm_str
                            ),
                            parent,
                            me
                        ).as_str()
                    }
                    &BranchChild::Stem(x) => {
                        let stem_name = hex::encode(x);
                        // Leaf node
                        let stem_meta = self.stem_table.get(&x).unwrap();
                        let mut comm_serialised = [0u8; 32];
                        stem_meta.stem_commitment.serialize(&mut comm_serialised[..]).unwrap();
                        let comm_str = hex::encode(comm_serialised);

                        let mut c1 = [0u8; 32];
                        stem_meta.C_1.serialize(&mut c1[..]).unwrap();
                        let c1_str = hex::encode(c1);

                        let mut c2 = [0u8; 32];
                        stem_meta.C_2.serialize(&mut c2[..]).unwrap();
                        let c2_str = hex::encode(c2);

                        let mut leafkey: [u8; 32] = Default::default();
                        for i in 0..31 {
                            leafkey[i] = x[i];
                        }
                        let mut leafvals = String::new();
                        for last in 0..255 {
                            leafkey[31] = last;
                            if let Some(val) = self.leaf_table.get(&leafkey) {
                                leafvals = leafvals + format!(" [{}] {}\n", leafkey[31], hex::encode(val)).as_str();
                            }
                        }
                        dot = dot
                        + format!(
                            "{} [{}label=\"{}\"]\n{} -> {}\n",
                            me,
                            lgbox,
                            format!(
                                "ExtNode: '{}'\ncomm: {}\nc1: {}\nc2: {}\nValues:\n{}",
                                stem_name,
                                comm_str,
                                c1_str,
                                c2_str,
                                leafvals,
                            ),
                            parent,
                            me
                        )
                        .as_str();
                    }
                }
            }
            let children = self.get_branch_children(&node.1.clone()[..]);
            for child in children {
                let parent = Some(node.1.clone());
                let mut child_vec = node.1.clone();
                child_vec.append(&mut vec![child.0]);
                queue.add((parent, child_vec)).unwrap();
            }
        }
        dot = dot + "}\n";

        // Dot save
        std::fs::write(file, dot).expect(format!("Unable to write file: {}", file).as_str());
    }
}

impl ReadOnlyHigherDb for MemoryDb {
    fn get_stem_meta(&self, stem_key: [u8; 31]) -> Option<StemMeta> {
        self.stem_table.get(&stem_key).copied()
    }

    fn get_branch_meta(&self, key: &[u8]) -> Option<BranchMeta> {
        let branch_child = match self.branch_table.get(key) {
            Some(b_child) => b_child,
            None => return None,
        };

        match branch_child {
            BranchChild::Stem(stem_id) => panic!(
                "expected branch meta data, however under this path there is a stem: {}",
                hex::encode(stem_id)
            ),
            BranchChild::Branch(b_meta) => Some(*b_meta),
        }
    }

    fn get_leaf(&self, key: [u8; 32]) -> Option<[u8; 32]> {
        self.leaf_table
            .get(&key)
            .map(|val| val.to_vec().try_into().unwrap())
    }

    fn get_branch_children(&self, branch_id: &[u8]) -> Vec<(u8, BranchChild)> {
        let mut children = Vec::with_capacity(256);

        for i in 0u8..=255 {
            let mut child = branch_id.to_vec();
            child.push(i);

            let value = self.branch_table.get(&child);

            // If its a stem, we return the stem_id
            // If it's a branch, we return the branch_id
            // TODO: we could return the BranchChild instead and leave the caller to do what they want with it

            if let Some(b_child) = value {
                children.push((i, *b_child))
            }
        }

        children
    }

    fn get_stem_children(&self, stem_key: [u8; 31]) -> Vec<(u8, [u8; 32])> {
        let mut children = Vec::with_capacity(256);

        for i in 0u8..=255 {
            let mut child = stem_key.to_vec();
            child.push(i);
            let child: [u8; 32] = child.try_into().unwrap();

            let value = self.leaf_table.get(&child);

            if let Some(i_vec) = value {
                children.push((i, i_vec.to_vec().try_into().unwrap()))
            }
        }

        children
    }

    fn get_branch_child(&self, branch_id: &[u8], index: u8) -> Option<BranchChild> {
        let mut child_index = Vec::with_capacity(branch_id.len());
        child_index.extend_from_slice(&branch_id);
        child_index.push(index);

        self.branch_table.get(&child_index).copied()
    }
}

impl WriteOnlyHigherDb for MemoryDb {
    fn insert_stem(&mut self, key: [u8; 31], meta: StemMeta, _depth: u8) -> Option<StemMeta> {
        self.stem_table.insert(key, meta)
    }

    fn insert_branch(&mut self, key: Vec<u8>, meta: BranchMeta, _depth: u8) -> Option<BranchMeta> {
        let b_child = match self.branch_table.insert(key, BranchChild::Branch(meta)) {
            Some(b_child) => b_child,
            None => return None,
        };
        match b_child {
            BranchChild::Stem(_) => None, // If its a stem, we return None, this only happens in ChainInsert
            BranchChild::Branch(b_meta) => return Some(b_meta),
        }
    }

    fn insert_leaf(&mut self, key: [u8; 32], value: [u8; 32], _depth: u8) -> Option<Vec<u8>> {
        self.leaf_table
            .insert(key, value)
            .map(|old_val| old_val.to_vec())
    }

    fn add_stem_as_branch_child(
        &mut self,
        branch_child_id: Vec<u8>,
        stem_id: [u8; 31],
        _depth: u8,
    ) -> Option<BranchChild> {
        self.branch_table
            .insert(branch_child_id, BranchChild::Stem(stem_id))
    }
}

impl Flush for MemoryDb {
    fn flush(&mut self) {
        // No-op since this database is in memory
        // The flush trait is for databases which have a
        // memory database and a disk storage, flush signals them to flush the
        // memory to database to disk
        //
        // This is implemented for the MemoryDb so that we can use it for
        // tests in the Trie
    }
}
