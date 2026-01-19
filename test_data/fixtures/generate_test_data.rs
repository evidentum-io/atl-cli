//! Test data generator for atl-cli integration tests
//!
//! This script generates:
//! - Source files with known content
//! - Valid receipts with correct proofs
//! - Invalid receipts with various failure modes
//! - Batch test scenarios (consistent/inconsistent/partial)
//!
//! IMPORTANT: Uses atl-core for ALL cryptographic operations!

use atl_core::compute_leaf_hash;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

type Hash = [u8; 32];

/// Generate a simple test file with known content
fn generate_test_file(path: &Path, content: &[u8]) {
    fs::write(path, content).expect("Failed to write test file");
}

/// Compute root hash for a single-entry tree using atl-core
/// For a single entry: root = leaf_hash (no parent nodes needed)
fn compute_single_entry_root(payload_hash: &Hash, metadata_hash: &Hash) -> Hash {
    // Use atl-core's compute_leaf_hash - DO NOT reimplement!
    compute_leaf_hash(payload_hash, metadata_hash)
}

/// Generate a valid receipt for a file
///
/// For super_tree_size = 1: this is the first entry, genesis_super_root = super_root = root_hash
/// For super_tree_size > 1: genesis stays the same, super_root is different
fn generate_valid_receipt(
    file_path: &Path,
    receipt_path: &Path,
    genesis_super_root: &str,
    super_tree_size: u64,
) {
    let content = fs::read(file_path).expect("Failed to read file");
    let payload_hash: Hash = Sha256::digest(&content).into();

    // For entries without metadata, use empty JSON object
    let metadata = serde_json::json!({});
    let metadata_canonical = serde_json::to_vec(&metadata).expect("Failed to serialize metadata");
    let metadata_hash: Hash = Sha256::digest(&metadata_canonical).into();

    // Use atl-core for Merkle tree operations
    let root_hash = compute_single_entry_root(&payload_hash, &metadata_hash);

    // For first entry: genesis = super_root = root_hash
    // For subsequent entries: genesis stays fixed, super_root = root_hash
    let actual_genesis = if super_tree_size == 1 {
        format!("sha256:{}", hex::encode(root_hash))
    } else {
        genesis_super_root.to_string()
    };

    let receipt = serde_json::json!({
        "spec_version": "2.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "payload_hash": format!("sha256:{}", hex::encode(payload_hash)),
            "metadata_hash": format!("sha256:{}", hex::encode(metadata_hash)),
            "metadata": metadata
        },
        "proof": {
            "tree_size": 1,
            "root_hash": format!("sha256:{}", hex::encode(root_hash)),
            "inclusion_path": [],
            "leaf_index": 0,
            "checkpoint": {
                "origin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "tree_size": 1,
                "root_hash": format!("sha256:{}", hex::encode(root_hash)),
                "timestamp": 1767225600000000000_u64,
                "key_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "signature": "base64:AAAA..."
            }
        },
        "super_proof": {
            "genesis_super_root": actual_genesis,
            "data_tree_index": super_tree_size - 1,
            "super_tree_size": super_tree_size,
            "super_root": format!("sha256:{}", hex::encode(root_hash)),
            "inclusion": [],
            "consistency_to_origin": []
        },
        "anchors": []
    });

    fs::write(
        receipt_path,
        serde_json::to_string_pretty(&receipt).unwrap(),
    )
    .expect("Failed to write receipt");
}

fn main() {
    let test_data = Path::new("test_data");

    // Create directory structure
    fs::create_dir_all(test_data.join("files")).expect("Failed to create files dir");
    fs::create_dir_all(test_data.join("receipts/valid"))
        .expect("Failed to create valid receipts dir");
    fs::create_dir_all(test_data.join("receipts/invalid"))
        .expect("Failed to create invalid receipts dir");
    fs::create_dir_all(test_data.join("batch/consistent/files"))
        .expect("Failed to create batch dirs");
    fs::create_dir_all(test_data.join("batch/consistent/receipts"))
        .expect("Failed to create batch dirs");
    fs::create_dir_all(test_data.join("batch/inconsistent/files"))
        .expect("Failed to create batch dirs");
    fs::create_dir_all(test_data.join("batch/inconsistent/receipts"))
        .expect("Failed to create batch dirs");
    fs::create_dir_all(test_data.join("batch/partial/files")).expect("Failed to create batch dirs");
    fs::create_dir_all(test_data.join("batch/partial/receipts"))
        .expect("Failed to create batch dirs");

    // Generate single files
    generate_test_file(
        &test_data.join("files/document.pdf"),
        b"Test document content for verification",
    );
    generate_test_file(
        &test_data.join("files/contract.pdf"),
        b"Contract content for testing",
    );
    generate_test_file(
        &test_data.join("files/modified-document.pdf"),
        b"MODIFIED document content",
    );

    // Generate valid receipts (same genesis for consistency)
    let genesis = "sha256:aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
    generate_valid_receipt(
        &test_data.join("files/document.pdf"),
        &test_data.join("receipts/valid/document.pdf.atl"),
        genesis,
        1,
    );
    generate_valid_receipt(
        &test_data.join("files/contract.pdf"),
        &test_data.join("receipts/valid/contract.pdf.atl"),
        genesis,
        1, // Also first entry, independent receipt
    );

    // Generate batch/consistent test data (same content = same genesis for simplicity)
    // All files have identical content, so they'll have the same root_hash and genesis
    let consistent_content = b"Consistent batch document content";
    for i in 1..=3 {
        let filename = format!("doc{}.pdf", i);
        generate_test_file(
            &test_data.join(format!("batch/consistent/files/{}", filename)),
            consistent_content,
        );
        generate_valid_receipt(
            &test_data.join(format!("batch/consistent/files/{}", filename)),
            &test_data.join(format!("batch/consistent/receipts/{}.atl", filename)),
            genesis, // Unused for super_tree_size=1, but all will have same genesis anyway
            1,       // All are first entry, so genesis=super_root
        );
    }

    // Generate batch/inconsistent test data (different genesis = different logs)
    let genesis_a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let genesis_b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    generate_test_file(
        &test_data.join("batch/inconsistent/files/file-a.pdf"),
        b"File A content",
    );
    generate_test_file(
        &test_data.join("batch/inconsistent/files/file-b.pdf"),
        b"File B content",
    );
    generate_valid_receipt(
        &test_data.join("batch/inconsistent/files/file-a.pdf"),
        &test_data.join("batch/inconsistent/receipts/file-a.pdf.atl"),
        genesis_a,
        1,
    );
    generate_valid_receipt(
        &test_data.join("batch/inconsistent/files/file-b.pdf"),
        &test_data.join("batch/inconsistent/receipts/file-b.pdf.atl"),
        genesis_b,
        1,
    );

    // Generate batch/partial test data (mixed scenarios)
    generate_test_file(
        &test_data.join("batch/partial/files/good.pdf"),
        b"Good file content",
    );
    generate_test_file(
        &test_data.join("batch/partial/files/modified.pdf"),
        b"This content was modified after receipt creation",
    );
    generate_test_file(
        &test_data.join("batch/partial/files/orphan.pdf"),
        b"Orphan file with no receipt",
    );
    generate_valid_receipt(
        &test_data.join("batch/partial/files/good.pdf"),
        &test_data.join("batch/partial/receipts/good.pdf.atl"),
        genesis,
        1,
    );
    // Receipt for original content (will mismatch with modified.pdf)
    let original_modified_content = b"Original content before modification";
    let temp_path = test_data.join("batch/partial/files/.temp_modified.pdf");
    generate_test_file(&temp_path, original_modified_content);
    generate_valid_receipt(
        &temp_path,
        &test_data.join("batch/partial/receipts/modified.pdf.atl"),
        genesis,
        2,
    );
    fs::remove_file(&temp_path).expect("Failed to remove temp file");
    // Receipt with no corresponding source file
    generate_test_file(&temp_path, b"Missing file content");
    generate_valid_receipt(
        &temp_path,
        &test_data.join("batch/partial/receipts/missing-file.atl"),
        genesis,
        3,
    );
    fs::remove_file(&temp_path).expect("Failed to remove temp file");

    // Generate invalid receipts
    generate_invalid_receipts(test_data);

    println!("Test data generated successfully");
}

/// Generate invalid receipt test cases
fn generate_invalid_receipts(test_data: &Path) {
    // malformed_json.atl - not valid JSON
    fs::write(
        test_data.join("receipts/invalid/malformed_json.atl"),
        "{ invalid json content",
    )
    .expect("Failed to write malformed receipt");

    // missing_fields.atl - missing required fields
    fs::write(
        test_data.join("receipts/invalid/missing_fields.atl"),
        r#"{"spec_version": "2.0.0"}"#,
    )
    .expect("Failed to write missing fields receipt");

    // wrong_version.atl - unsupported spec version but valid structure
    let wrong_version = serde_json::json!({
        "spec_version": "99.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "metadata": {}
        },
        "proof": {
            "tree_size": 1,
            "root_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "inclusion_path": [],
            "leaf_index": 0,
            "checkpoint": {
                "origin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "tree_size": 1,
                "root_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": 1767225600000000000_u64,
                "key_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "signature": "base64:AAAA"
            }
        },
        "super_proof": {
            "genesis_super_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "data_tree_index": 0,
            "super_tree_size": 1,
            "super_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "inclusion": [],
            "consistency_to_origin": []
        },
        "anchors": []
    });
    fs::write(
        test_data.join("receipts/invalid/wrong_version.atl"),
        serde_json::to_string_pretty(&wrong_version).unwrap(),
    )
    .expect("Failed to write wrong version receipt");

    // tampered_proof.atl - valid structure but invalid proof
    let tampered = serde_json::json!({
        "spec_version": "2.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "metadata": {}
        },
        "proof": {
            "tree_size": 100,
            "root_hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "inclusion_path": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"],
            "leaf_index": 50,
            "checkpoint": {
                "origin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "tree_size": 100,
                "root_hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "timestamp": 1767225600000000000_u64,
                "key_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "signature": "base64:AAAA"
            }
        },
        "super_proof": {
            "genesis_super_root": "sha256:aabbccdd",
            "data_tree_index": 0,
            "super_tree_size": 1,
            "super_root": "sha256:aabbccdd",
            "inclusion": [],
            "consistency_to_origin": []
        },
        "anchors": []
    });
    fs::write(
        test_data.join("receipts/invalid/tampered_proof.atl"),
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .expect("Failed to write tampered proof receipt");

    // wrong_hash.atl - valid receipt but won't match any file
    let wrong_hash = serde_json::json!({
        "spec_version": "2.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "payload_hash": "sha256:1234567890123456789012345678901234567890123456789012345678901234",
            "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "metadata": {}
        },
        "proof": {
            "tree_size": 1,
            "root_hash": "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "inclusion_path": [],
            "leaf_index": 0,
            "checkpoint": {
                "origin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "tree_size": 1,
                "root_hash": "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
                "timestamp": 1767225600000000000_u64,
                "key_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "signature": "base64:AAAA"
            }
        },
        "super_proof": {
            "genesis_super_root": "sha256:aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd",
            "data_tree_index": 0,
            "super_tree_size": 1,
            "super_root": "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "inclusion": [],
            "consistency_to_origin": []
        },
        "anchors": []
    });
    fs::write(
        test_data.join("receipts/invalid/wrong_hash.atl"),
        serde_json::to_string_pretty(&wrong_hash).unwrap(),
    )
    .expect("Failed to write wrong hash receipt");
}
