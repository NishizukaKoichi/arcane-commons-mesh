#![forbid(unsafe_code)]

pub mod audit;
pub mod credit;
pub mod crypto;
pub mod identity;
pub mod recovery;
pub mod store;
pub mod vault;

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

pub fn cid(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
