use anyhow::{bail, Result};
use std::{env, path::PathBuf};

use curv::{elliptic::curves::{secp256_k1::Secp256k1}};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
    state_machine::{
        keygen::{Keygen, LocalKey},
    },
};
use round_based::StateMachine;

const THRESHOLD: u16 = 1;
const PARTIES: u16 = 3;

fn main() -> Result<()> {
    let mut args = env::args();
    let _ = args.next();

    if let Some(path) = args.next() {
        let path = PathBuf::from(path);

        println!("Path is: {}", path.display());

        if path.is_dir() {
            println!(
                "Generating key shares (threshold = {}, parties = {})",
                THRESHOLD, PARTIES
            );
            let key_shares = generate_keys(THRESHOLD, PARTIES)?;
            println!("Write keys to {}", path.display());
            for (index, share) in key_shares.into_iter().enumerate() {
                let key_share = serde_json::to_string_pretty(&share)?;
                let file_name = format!("key-share-{}.json", index + 1);
                let file_path = path.join(file_name);
                println!("Write key share to {}", file_path.display());
                std::fs::write(file_path, key_share)?
            }
        } else {
            bail!("path argument must be a directory")
        }

        Ok(())
    } else {
        bail!("directory path argument is required")
    }
}

fn generate_keys(
    threshold: u16,
    parties: u16,
) -> Result<Vec<LocalKey<Secp256k1>>> {
    let mut c1 = Keygen::new(1, threshold, parties)?;
    let mut c2 = Keygen::new(2, threshold, parties)?;
    let mut c3 = Keygen::new(3, threshold, parties)?;

    debug_assert!(c1.wants_to_proceed());
    debug_assert!(c2.wants_to_proceed());
    debug_assert!(c3.wants_to_proceed());

    debug_assert!(c1.message_queue().is_empty());
    debug_assert!(c2.message_queue().is_empty());
    debug_assert!(c3.message_queue().is_empty());

    let c1_r1: Vec<_> = {
        c1.proceed()?;
        c1.message_queue().drain(..).collect()
    };
    debug_assert!(!c1_r1.is_empty());

    let c2_r1: Vec<_> = {
        c2.proceed()?;
        c2.message_queue().drain(..).collect()
    };
    debug_assert!(!c2_r1.is_empty());

    let c3_r1: Vec<_> = {
        c3.proceed()?;
        c3.message_queue().drain(..).collect()
    };
    debug_assert!(!c3_r1.is_empty());

    debug_assert_eq!(1, c1.current_round());
    debug_assert_eq!(1, c2.current_round());
    debug_assert_eq!(1, c3.current_round());

    // Feed incoming messages to client 1 for round 1
    for m in c2_r1.iter().chain(c3_r1.iter()) {
        c1.handle_incoming(m.clone())?;
    }
    //debug_assert!(c1.wants_to_proceed());

    // Feed incoming messages to client 2 for round 1
    for m in c1_r1.iter().chain(c3_r1.iter()) {
        c2.handle_incoming(m.clone())?;
    }
    //debug_assert!(c2.wants_to_proceed());

    // Feed incoming messages to client 3 for round 1
    for m in c1_r1.iter().chain(c2_r1.iter()) {
        c3.handle_incoming(m.clone())?;
    }
    //debug_assert!(c3.wants_to_proceed());

    let c1_r2: Vec<_> = {
        c1.proceed()?;
        c1.message_queue().drain(..).collect()
    };
    debug_assert!(!c1_r2.is_empty());

    let c2_r2: Vec<_> = {
        c2.proceed()?;
        c2.message_queue().drain(..).collect()
    };
    debug_assert!(!c2_r2.is_empty());

    let c3_r2: Vec<_> = {
        c3.proceed()?;
        c3.message_queue().drain(..).collect()
    };
    debug_assert!(!c3_r2.is_empty());

    debug_assert_eq!(2, c1.current_round());
    debug_assert_eq!(2, c2.current_round());
    debug_assert_eq!(2, c3.current_round());

    // Feed incoming messages to client 1 for round 2
    for m in c2_r2.iter().chain(c3_r2.iter()) {
        c1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to client 2 for round 2
    for m in c1_r2.iter().chain(c3_r2.iter()) {
        c2.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to client 3 for round 2
    for m in c1_r2.iter().chain(c2_r2.iter()) {
        c3.handle_incoming(m.clone())?;
    }

    let c1_r3: Vec<_> = {
        c1.proceed()?;
        c1.message_queue().drain(..).collect()
    };
    debug_assert!(!c1_r3.is_empty());

    let c2_r3: Vec<_> = {
        c2.proceed()?;
        c2.message_queue().drain(..).collect()
    };
    debug_assert!(!c2_r3.is_empty());

    let c3_r3: Vec<_> = {
        c3.proceed()?;
        c3.message_queue().drain(..).collect()
    };
    debug_assert!(!c3_r3.is_empty());

    debug_assert_eq!(3, c1.current_round());
    debug_assert_eq!(3, c2.current_round());
    debug_assert_eq!(3, c3.current_round());

    // Handle round 3 as p2p
    for m in c1_r3.iter().chain(c2_r3.iter()).chain(c3_r3.iter()) {
        if let Some(receiver) = &m.receiver {
            match receiver {
                1 => c1.handle_incoming(m.clone())?,
                2 => c2.handle_incoming(m.clone())?,
                3 => c3.handle_incoming(m.clone())?,
                _ => panic!("unknown party index (keygen)"),
            }
        }
    }

    let c1_r4: Vec<_> = {
        c1.proceed()?;
        c1.message_queue().drain(..).collect()
    };
    debug_assert!(!c1_r4.is_empty());

    let c2_r4: Vec<_> = {
        c2.proceed()?;
        c2.message_queue().drain(..).collect()
    };
    debug_assert!(!c2_r4.is_empty());

    let c3_r4: Vec<_> = {
        c3.proceed()?;
        c3.message_queue().drain(..).collect()
    };
    debug_assert!(!c3_r4.is_empty());

    debug_assert_eq!(4, c1.current_round());
    debug_assert_eq!(4, c2.current_round());
    debug_assert_eq!(4, c3.current_round());

    // Feed incoming messages to client 1 for round 4
    for m in c2_r4.iter().chain(c3_r4.iter()) {
        c1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to client 2 for round 4
    for m in c1_r4.iter().chain(c3_r4.iter()) {
        c2.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to client 3 for round 4
    for m in c1_r4.iter().chain(c2_r4.iter()) {
        c3.handle_incoming(m.clone())?;
    }

    c1.proceed()?;
    c2.proceed()?;
    c3.proceed()?;

    debug_assert_eq!(5, c1.current_round());
    debug_assert_eq!(5, c2.current_round());
    debug_assert_eq!(5, c3.current_round());

    debug_assert!(c1.is_finished());
    debug_assert!(c2.is_finished());
    debug_assert!(c3.is_finished());

    let ks1 = c1.pick_output().unwrap()?;
    let ks2 = c2.pick_output().unwrap()?;
    let ks3 = c3.pick_output().unwrap()?;

    Ok(vec![ks1, ks2, ks3])
}
