use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use hex::FromHex;
use keccak_hash::{keccak, KECCAK_EMPTY};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::{collections::HashMap, fs::File, io::BufReader, str::FromStr, sync::Mutex};
use verkle_spec::{
    addr20_to_addr32, code::chunkify_code, Address20, Code, Hasher, Header, Storage, H256, U256,
};
use verkle_trie::{database::memory_db::MemoryDb, Trie, TrieTrait, Value, VerkleConfig};

const GENESIS_FILEPATH: &str = "assets/devnet6_genesis.json";
const STATE_ROOT: &str = "0x1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee";

pub struct DefaultHasher;

impl Hasher for DefaultHasher {}

#[derive(Deserialize)]
pub struct GenesisAccountState {
    balance: String,
    nonce: Option<String>,
    code: Option<String>,
    storage: Option<HashMap<U256, H256>>,
}

#[derive(Deserialize)]
pub struct GenesisConfig {
    alloc: HashMap<Address20, GenesisAccountState>,
}

pub static CONFIG: Lazy<Mutex<VerkleConfig<MemoryDb>>> =
    Lazy::new(|| Mutex::new(VerkleConfig::new(MemoryDb::new())));

fn to_trie_value(u256: U256) -> Value {
    let mut value = Value::default();
    u256.to_little_endian(value.as_mut_slice());
    value
}

#[test]
fn genesis_state_root() -> Result<()> {
    let file = File::open(GENESIS_FILEPATH)?;
    let genesis_config: GenesisConfig = serde_json::from_reader(BufReader::new(file))?;

    let mut trie = Trie::new(CONFIG.lock().unwrap().clone());

    for (address, account_state) in genesis_config.alloc {
        let address = addr20_to_addr32(address);
        let header = Header::new::<DefaultHasher>(address);

        let balance = U256::from_dec_str(&account_state.balance)?;
        let nonce = U256::from_dec_str(&account_state.nonce.unwrap_or("0".to_string()))?;
        trie.insert(
            [
                (header.version().0, to_trie_value(U256::zero())),
                (header.balance().0, to_trie_value(balance)),
                (header.nonce().0, to_trie_value(nonce)),
            ]
            .into_iter(),
        );

        match account_state.code {
            None => {
                trie.insert_single(header.code_keccak().0, KECCAK_EMPTY.0);
            }
            Some(code) => {
                let code = code.strip_prefix("0x").unwrap_or(&code);
                let code = <Vec<u8>>::from_hex(code)?;

                trie.insert(
                    [
                        (header.code_keccak().0, keccak(&code).0),
                        (header.code_size().0, to_trie_value(U256::from(code.len()))),
                    ]
                    .into_iter(),
                );

                let code_kv = chunkify_code(code)
                    .into_iter()
                    .enumerate()
                    .map(|(chunk_id, code_chunk)| {
                        let tree_key =
                            Code::new::<DefaultHasher>(address, U256::from(chunk_id)).code_chunk();
                        (tree_key.0, code_chunk)
                    })
                    .collect::<Vec<_>>();
                trie.insert(code_kv.into_iter());
            }
        }

        if let Some(storage) = account_state.storage {
            let storage_kv = storage
                .into_iter()
                .map(|(storage_slot, storage_value)| {
                    let storage_slot_tree_key =
                        Storage::new::<DefaultHasher>(address, storage_slot).storage_slot();
                    (storage_slot_tree_key.0, storage_value.0)
                })
                .collect::<Vec<_>>();
            trie.insert(storage_kv.into_iter());
        }
    }

    let mut root_hash = H256::zero();
    trie.root_commitment()
        .serialize_compressed(root_hash.as_bytes_mut())?;
    assert_eq!(root_hash, H256::from_str(STATE_ROOT)?);

    Ok(())
}
