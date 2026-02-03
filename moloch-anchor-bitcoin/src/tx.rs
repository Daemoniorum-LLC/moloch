//! Bitcoin transaction building for OP_RETURN anchoring.

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use crate::error::{BitcoinError, Result};
use crate::{ANCHOR_DATA_SIZE, MAX_OP_RETURN_SIZE, MOLOCH_MAGIC};

/// Build an OP_RETURN script for anchoring.
///
/// Format: OP_RETURN [MOLOCH_MAGIC (4)] [commitment_hash (32)] [chain_id_hash (8)]
pub fn build_op_return_script(commitment_hash: &[u8; 32], chain_id: &str) -> Result<ScriptBuf> {
    let mut data = Vec::with_capacity(ANCHOR_DATA_SIZE);

    // Magic bytes
    data.extend_from_slice(MOLOCH_MAGIC);

    // Commitment hash
    data.extend_from_slice(commitment_hash);

    // Chain ID hash (first 8 bytes of hash)
    let chain_hash = moloch_core::hash(chain_id.as_bytes());
    data.extend_from_slice(&chain_hash.as_bytes()[..8]);

    if data.len() > MAX_OP_RETURN_SIZE {
        return Err(BitcoinError::InvalidOpReturn(format!(
            "data too large: {} > {}",
            data.len(),
            MAX_OP_RETURN_SIZE
        )));
    }

    let push_bytes =
        PushBytesBuf::try_from(data).map_err(|e| BitcoinError::InvalidOpReturn(e.to_string()))?;

    Ok(Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_slice(push_bytes)
        .into_script())
}

/// Parse an OP_RETURN script to extract anchor data.
pub fn parse_op_return_script(script: &ScriptBuf) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let bytes = script.as_bytes();

    // Check for OP_RETURN
    if bytes.is_empty() || bytes[0] != opcodes::all::OP_RETURN.to_u8() {
        return Err(BitcoinError::InvalidOpReturn(
            "not an OP_RETURN script".into(),
        ));
    }

    // Skip OP_RETURN and push opcode
    let data = if bytes.len() > 2 && bytes[1] <= 75 {
        // Direct push
        &bytes[2..]
    } else if bytes.len() > 3 && bytes[1] == opcodes::all::OP_PUSHDATA1.to_u8() {
        // OP_PUSHDATA1
        &bytes[3..]
    } else {
        return Err(BitcoinError::InvalidOpReturn(
            "unexpected script format".into(),
        ));
    };

    if data.len() < ANCHOR_DATA_SIZE {
        return Err(BitcoinError::InvalidOpReturn(format!(
            "data too small: {} < {}",
            data.len(),
            ANCHOR_DATA_SIZE
        )));
    }

    // Check magic
    if &data[0..4] != MOLOCH_MAGIC {
        return Err(BitcoinError::InvalidOpReturn("invalid magic bytes".into()));
    }

    Ok((
        data[0..4].to_vec(),   // magic
        data[4..36].to_vec(),  // commitment hash
        data[36..44].to_vec(), // chain id hash
    ))
}

/// UTXO for building transactions.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Utxo {
    /// Previous output point.
    pub outpoint: OutPoint,
    /// Amount in satoshis.
    pub amount: Amount,
    /// Script pubkey.
    pub script_pubkey: ScriptBuf,
}

/// Transaction builder for anchor transactions.
#[allow(dead_code)]
pub struct AnchorTxBuilder {
    /// Network.
    network: Network,
    /// Available UTXOs.
    utxos: Vec<Utxo>,
    /// Fee rate in sat/vB.
    fee_rate: f64,
    /// Change address.
    change_address: Option<Address>,
}

impl AnchorTxBuilder {
    /// Create a new transaction builder.
    pub fn new(network: Network) -> Self {
        Self {
            network,
            utxos: Vec::new(),
            fee_rate: 10.0,
            change_address: None,
        }
    }

    /// Add available UTXOs.
    pub fn with_utxos(mut self, utxos: Vec<Utxo>) -> Self {
        self.utxos = utxos;
        self
    }

    /// Set fee rate.
    pub fn with_fee_rate(mut self, sat_per_vb: f64) -> Self {
        self.fee_rate = sat_per_vb;
        self
    }

    /// Set change address.
    pub fn with_change_address(mut self, address: Address) -> Self {
        self.change_address = Some(address);
        self
    }

    /// Estimate transaction virtual size.
    fn estimate_vsize(num_inputs: usize, has_change: bool) -> usize {
        // Rough estimates for P2WPKH:
        // - Version: 4 bytes
        // - Marker + Flag: 2 bytes
        // - Input count: 1 byte
        // - Per input: 32 (txid) + 4 (vout) + 1 (script len) + 4 (sequence) = 41 bytes
        // - Witness per input: ~27 vbytes (discounted)
        // - Output count: 1 byte
        // - OP_RETURN output: 8 (value) + 1 (len) + 46 (script) = 55 bytes
        // - Change output (P2WPKH): 8 + 1 + 22 = 31 bytes
        // - Locktime: 4 bytes

        let base = 4 + 2 + 1 + 1 + 4;
        let inputs = num_inputs * (41 + 27);
        let op_return = 55;
        let change = if has_change { 31 } else { 0 };

        base + inputs + op_return + change
    }

    /// Build an anchor transaction.
    pub fn build(&self, commitment_hash: &[u8; 32], chain_id: &str) -> Result<Transaction> {
        // Build OP_RETURN script
        let op_return_script = build_op_return_script(commitment_hash, chain_id)?;

        // Calculate required fee
        let estimated_vsize = Self::estimate_vsize(1, self.change_address.is_some());
        let required_fee = (estimated_vsize as f64 * self.fee_rate).ceil() as u64;

        // Select UTXOs (simple: just use first one that's large enough)
        let utxo = self
            .utxos
            .iter()
            .find(|u| u.amount.to_sat() > required_fee)
            .ok_or_else(|| BitcoinError::InsufficientFunds {
                need: required_fee,
                have: self.utxos.iter().map(|u| u.amount.to_sat()).sum(),
            })?;

        // Build inputs
        let inputs = vec![TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }];

        // Build outputs
        let mut outputs = vec![
            // OP_RETURN output (0 value)
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            },
        ];

        // Add change output if we have a change address
        if let Some(ref change_addr) = self.change_address {
            let change_amount = utxo.amount.to_sat() - required_fee;
            if change_amount > 546 {
                // Dust threshold
                outputs.push(TxOut {
                    value: Amount::from_sat(change_amount),
                    script_pubkey: change_addr.script_pubkey(),
                });
            }
        }

        Ok(Transaction {
            version: transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        })
    }
}

/// Generate a merkle proof for a transaction in a block.
pub fn generate_merkle_proof(
    block_txids: &[Txid],
    tx_index: usize,
) -> Result<(Vec<[u8; 32]>, u32)> {
    if tx_index >= block_txids.len() {
        return Err(BitcoinError::SpvProof(
            "transaction index out of range".into(),
        ));
    }

    let mut proof = Vec::new();
    let mut index = tx_index;
    let mut level: Vec<[u8; 32]> = block_txids
        .iter()
        .map(|txid| *txid.as_byte_array())
        .collect();

    while level.len() > 1 {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

        // Handle odd number of elements by duplicating last
        let sibling = if sibling_index < level.len() {
            level[sibling_index]
        } else {
            level[level.len() - 1]
        };

        proof.push(sibling);

        // Compute next level
        let mut next_level = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };

            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);

            let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next_level.push(*hash.as_byte_array());
        }

        level = next_level;
        index /= 2;
    }

    Ok((proof, tx_index as u32))
}

/// Verify a merkle proof.
#[allow(dead_code)]
pub fn verify_merkle_proof(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    proof: &[[u8; 32]],
    index: u32,
) -> bool {
    let mut current = *txid;
    let mut idx = index;

    for sibling in proof {
        let mut combined = [0u8; 64];

        if idx % 2 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }

        let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
        current = *hash.as_byte_array();
        idx /= 2;
    }

    current == *merkle_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_return_script() {
        let commitment = [0xab; 32];
        let script = build_op_return_script(&commitment, "test-chain").unwrap();

        assert!(script.is_op_return());
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        // Create some fake txids
        let txids: Vec<Txid> = (0..8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i as u8;
                Txid::from_byte_array(bytes)
            })
            .collect();

        // Get merkle root
        let root = compute_merkle_root(&txids);

        // Generate and verify proof for each tx
        for i in 0..txids.len() {
            let (proof, index) = generate_merkle_proof(&txids, i).unwrap();
            let txid = *txids[i].as_byte_array();

            assert!(verify_merkle_proof(&txid, &root, &proof, index));
        }
    }

    fn compute_merkle_root(txids: &[Txid]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = txids.iter().map(|txid| *txid.as_byte_array()).collect();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..level.len()).step_by(2) {
                let left = level[i];
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    level[i]
                };

                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&left);
                combined[32..].copy_from_slice(&right);

                let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
                next_level.push(*hash.as_byte_array());
            }
            level = next_level;
        }

        level[0]
    }
}
