#![forbid(unsafe_code)]

pub mod audit;
pub mod capability;
pub mod catalog;
pub mod compute;
pub mod credit;
pub mod crypto;
pub mod federation;
pub mod grimoire;
pub mod identity;
pub mod legacy;
pub mod memory;
pub mod recovery;
pub mod research;
pub mod settlement;
pub mod spell;
pub mod store;
pub mod vault;

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

pub fn cid(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
