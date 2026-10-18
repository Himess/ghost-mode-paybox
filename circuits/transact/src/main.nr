// Ghost Mode `transact` circuit: 2 inputs, 2 outputs, one asset per transaction.
//
// Spend authority is the user's PayBox wallet. The circuit verifies a secp256k1
// ECDSA signature over an EIP-712 `GhostSpend` digest that commits to this exact
// spend (nullifiers, output commitments, external data), so the PayBox key never
// leaves PayBox and a leaked privacy key (`nk`) cannot move funds on its own.
//
// Note:        { asset, amount, ownerTag, blinding, label }
// precommit:   H2(ownerTag, blinding)
// commitment:  H4(asset, amount, label, precommit)   (the pool recomputes this on deposit)
// ownerTag:    H2(pkHash, H1(nk)),  pkHash = H4(x_hi, x_lo, y_hi, y_lo)
// nullifier:   H3(commitment, leafIndex, nk)
// H* = circomlib-compatible Poseidon over BN254 (matches poseidon-solidity and poseidon-lite).

use poseidon::poseidon::bn254::{hash_1, hash_2, hash_3, hash_4, hash_5};

global DEPTH: u32 = 16;
global ASP_DEPTH: u32 = 16;

// v1.1: the approval screen states the hidden flow and the public flow separately.
// keccak256("GhostSpend(bytes32 intent,address token,uint256 privateAmount,bytes32 privateRecipient,uint256 publicAmount,address publicRecipient,uint256 fee,uint256 deadline)")
global SPEND_TYPEHASH: [u8; 32] = [
    226, 71, 126, 190, 39, 51, 158, 195, 101, 63, 170, 181, 90, 71, 28, 180, 53, 29, 87, 180, 100,
    236, 137, 75, 78, 161, 133, 114, 134, 74, 195, 95,
];
global STRUCT_LEN: u32 = 288; // typehash + 8 fields

fn merkle_root<let D: u32>(leaf: Field, index: Field, path: [Field; D]) -> Field {
    let bits: [bool; D] = index.to_le_bits();
    let mut node = leaf;
    for i in 0..D {
        let sibling = path[i];
        let (left, right) = if bits[i] { (sibling, node) } else { (node, sibling) };
        node = hash_2([left, right]);
    }
    node
}

fn note_commitment(asset: Field, amount: Field, label: Field, owner_tag: Field, blinding: Field) -> Field {
    hash_4([asset, amount, label, hash_2([owner_tag, blinding])])
}

fn be_bytes_to_field<let N: u32>(bytes: [u8; N], start: u32, len: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..N {
        if (i >= start) & (i < start + len) {
            acc = acc * 256 + bytes[i] as Field;
        }
    }
    acc
}

fn write32(buf: &mut [u8; STRUCT_LEN], offset: u32, word: [u8; 32]) {
    for k in 0..32 {
        buf[offset + k] = word[k];
    }
}

fn main(
    // ---- public inputs (order is the verifier's publicInputs layout) ----
    root: pub Field,
    asp_root: pub Field,
    nullifiers: pub [Field; 2],
    out_commitments: pub [Field; 2],
    public_out: pub u64,
    ext_data_hash: pub Field,
    asset: pub Field,
    recipient: pub Field,
    fee: pub u64,
    deadline: pub u64,
    domain_hi: pub Field,
    domain_lo: pub Field,
    // ---- private inputs ----
    in_amounts: [u64; 2],
    in_blindings: [Field; 2],
    in_labels: [Field; 2],
    in_indices: [Field; 2],
    in_paths: [[Field; DEPTH]; 2],
    asp_indices: [Field; 2],
    asp_paths: [[Field; ASP_DEPTH]; 2],
    nk: Field,
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    signature: [u8; 64],
    out_amounts: [u64; 2],
    out_owner_tags: [Field; 2],
    out_blindings: [Field; 2],
) {
    // 1. Owner binding: input notes belong to (PayBox public key, nk).
    let pk_hash = hash_4([
        be_bytes_to_field(pub_x, 0, 16),
        be_bytes_to_field(pub_x, 16, 16),
        be_bytes_to_field(pub_y, 0, 16),
        be_bytes_to_field(pub_y, 16, 16),
    ]);
    let owner_tag = hash_2([pk_hash, hash_1([nk])]);

    let live0 = in_amounts[0] != 0;
    let live1 = in_amounts[1] != 0;
    assert(live0 | live1, "at least one input must carry value");
    if live0 & live1 {
        assert(in_labels[0] == in_labels[1], "inputs must share one ASP label");
    }
    let label = if live0 { in_labels[0] } else { in_labels[1] };

    // 2. Inputs: commitment, nullifier, state-tree and ASP-tree membership.
    for i in 0..2 {
        let commitment =
            note_commitment(asset, in_amounts[i] as Field, in_labels[i], owner_tag, in_blindings[i]);
        assert(hash_3([commitment, in_indices[i], nk]) == nullifiers[i], "bad nullifier");
        if in_amounts[i] != 0 {
            // Labels are keccak-derived and never 0; 0 is the empty ASP leaf (v1.1).
            assert(in_labels[i] != 0, "live input needs a deposit label");
            assert(merkle_root(commitment, in_indices[i], in_paths[i]) == root, "note not in tree");
            assert(
                merkle_root(in_labels[i], asp_indices[i], asp_paths[i]) == asp_root,
                "label not in association set",
            );
        }
    }

    // 3. Outputs inherit the input label. Output 1 is always the change and must return
    //    to the spender: the approval screen shows output 0 and the public payout, so a
    //    malicious preparer must not be able to redirect change to another owner.
    assert(out_owner_tags[1] == owner_tag, "change must return to the spender");
    // v1.1: the change blinding is derived from the nullifier key, so the change note can be
    //       recomputed from the chain and the ghost key even if its ciphertext were unreadable.
    assert(out_blindings[1] == hash_2([nk, nullifiers[0]]), "change blinding must be derived");
    for j in 0..2 {
        assert(
            note_commitment(asset, out_amounts[j] as Field, label, out_owner_tags[j], out_blindings[j])
                == out_commitments[j],
            "bad output commitment",
        );
    }

    // 4. Value conservation (u64 amounts, so the Field sums cannot wrap).
    let sum_in = in_amounts[0] as Field + in_amounts[1] as Field;
    let sum_out = out_amounts[0] as Field + out_amounts[1] as Field + public_out as Field;
    assert(sum_in == sum_out, "value not conserved");
    assert(public_out >= fee, "fee exceeds public output");

    // 5. Intent: binds nullifiers, outputs and external data (relayer + encrypted notes).
    let intent = hash_5([nullifiers[0], nullifiers[1], out_commitments[0], out_commitments[1], ext_data_hash]);

    // 6. EIP-712 GhostSpend struct hash. Readable fields are recomputed from the
    //    real spend so the PayBox approval screen cannot be lied to:
    //    privateAmount/privateRecipient = the hidden output to another ghost owner,
    //    publicAmount/publicRecipient   = what leaves the pool (relayer fee shown separately).
    let private_amount = out_amounts[0] as Field;
    let private_recipient = if out_amounts[0] != 0 { out_owner_tags[0] } else { 0 };
    let public_amount = (public_out - fee) as Field;
    let mut enc: [u8; STRUCT_LEN] = [0; STRUCT_LEN];
    write32(&mut enc, 0, SPEND_TYPEHASH);
    write32(&mut enc, 32, intent.to_be_bytes());
    write32(&mut enc, 64, asset.to_be_bytes());
    write32(&mut enc, 96, private_amount.to_be_bytes());
    write32(&mut enc, 128, private_recipient.to_be_bytes());
    write32(&mut enc, 160, public_amount.to_be_bytes());
    write32(&mut enc, 192, recipient.to_be_bytes());
    write32(&mut enc, 224, (fee as Field).to_be_bytes());
    write32(&mut enc, 256, (deadline as Field).to_be_bytes());
    let struct_hash = keccak256::keccak256(enc, STRUCT_LEN);

    let dom_hi: [u8; 16] = domain_hi.to_be_bytes();
    let dom_lo: [u8; 16] = domain_lo.to_be_bytes();
    let mut digest_input: [u8; 66] = [0; 66];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    for k in 0..16 {
        digest_input[2 + k] = dom_hi[k];
        digest_input[18 + k] = dom_lo[k];
    }
    for k in 0..32 {
        digest_input[34 + k] = struct_hash[k];
    }
    let digest = keccak256::keccak256(digest_input, 66);

    // 7. PayBox wallet signature (secp256k1), verified inside the proof.
    assert(
        std::ecdsa_secp256k1::verify_signature(pub_x, pub_y, signature, digest),
        "PayBox signature invalid",
    );
}
