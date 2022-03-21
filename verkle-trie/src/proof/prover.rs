use super::{VerificationHint, VerkleProof};
use crate::{
    constants::CRS,
    database::ReadOnlyHigherDb,
    proof::opening_data::{OpeningData, Openings},
};
use ark_serialize::CanonicalSerialize;
use ipa_multipoint::multiproof::MultiPoint;
use ipa_multipoint::multiproof::ProverQuery;
use itertools::Itertools;
use std::collections::BTreeSet;

pub fn create_verkle_proof<Storage: ReadOnlyHigherDb>(
    storage: &Storage,
    keys: Vec<[u8; 32]>,
) -> VerkleProof {
    assert!(keys.len() > 0, "cannot create a proof with no keys");

    let (queries, verification_hint) = create_prover_queries(storage, keys);
    print!("queries: ");
    for x in queries.iter() {
        let mut comm_serialised = [0u8; 32];
        x.commitment.serialize(&mut comm_serialised[..]).unwrap();
        print!("{} ", hex::encode(comm_serialised));
    }
    println!("");

    // Commitments without duplicates and without the root, (implicitly) sorted by path, since the queries were
    // processed by path order
    let root_comm = queries
        .first()
        .expect("expected to have at least one query. The first query will be against the root")
        .commitment;

    let comms_sorted: Vec<_> = queries
        .iter()
        // Filter out the root commitment
        .filter(|query| query.commitment != root_comm)
        // Pull out the commitments from each query
        .map(|query| query.commitment)
        // Duplicate all commitments
        .dedup()
        .collect();

    use crate::constants::{PRECOMPUTED_WEIGHTS, VERKLE_NODE_WIDTH};
    use ipa_multipoint::transcript::Transcript;

    let mut transcript = Transcript::new(b"vt");
    let proof = MultiPoint::open(CRS.clone(), &PRECOMPUTED_WEIGHTS, &mut transcript, queries);

    VerkleProof {
        comms_sorted,
        verification_hint,
        proof,
    }
}

// First we need to produce all of the key paths for a key
// We can do some caching here to save memory, in particular if we fetch the same node more than once
// we just need to save it once.
//
// Notes on this abstraction, since a stem always comes with an extension, we can abstract this away
// An extension always has two openings, so we can also abstract this away (1, stem)
pub(super) fn create_prover_queries<Storage: ReadOnlyHigherDb>(
    storage: &Storage,
    keys: Vec<[u8; 32]>,
) -> (Vec<ProverQuery>, VerificationHint) {
    assert!(keys.len() > 0, "cannot create a proof with no keys");

    let opening_data = OpeningData::collect_opening_data(keys, storage);
    let openings = opening_data.openings;
    let extension_present_by_stem = opening_data.extension_present_by_stem;
    let depths_by_stem = opening_data.depths_by_stem;

    // Process all of the node openings data and create polynomial queries from them
    // We also collect all of the stems which are in the trie, however they do not have their own proofs
    // These are the Openings which are jus extensions
    let mut queries = Vec::new();

    //Stems that are in the trie, but don't have their own extension proofs
    let mut diff_stem_no_proof = BTreeSet::new();
    for (path, openings) in &openings {
        let mut prover_q = Vec::new();
        prover_q = match openings {
            Openings::Suffix(so) => so.open_query(storage),
            Openings::Branch(bo) => bo.open_query(path, storage),
            Openings::Extension(eo) => {
                diff_stem_no_proof.insert(eo.stem);
                eo.open_query(false, false)
            }
        };
        print!("\nopenings: {:?}, prover_q: ", openings);
        for x in prover_q.iter() {
            let mut comm_serialised = [0u8; 32];
            x.commitment.serialize(&mut comm_serialised[..]).unwrap();
            print!("{} ", hex::encode(comm_serialised));
        }
        println!("\n");
        queries.extend(prover_q);
    }

    // Values to help the verifier reconstruct the trie and verify the proof
    let depths: Vec<_> = depths_by_stem.into_values().into_iter().collect();
    let extension_present: Vec<_> = extension_present_by_stem
        .into_values()
        .into_iter()
        .collect();

    (
        queries,
        VerificationHint {
            depths,
            extension_present,
            diff_stem_no_proof,
        },
    )
}
