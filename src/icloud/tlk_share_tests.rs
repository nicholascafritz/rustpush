//! Synthetic, offline CKKS fixtures. No account records or persisted key material.
use super::*;
use cloudkit_proto::record::{
    field::{value::Type as FieldType, Value as FieldValue},
    Field,
};

fn share() -> CuttlefishTlkShare {
    CuttlefishTlkShare {
        receiver: "receiver-fixture".into(),
        sender: "sender-fixture".into(),
        version: 1,
        curve: 2,
        epoch: -1,
        poisoned: 0,
        wrappedkey: base64_encode(&[1, 2, 3, 4]),
        ..Default::default()
    }
}

fn field(name: &str, value: FieldValue) -> Field {
    Field {
        identifier: Some(cloudkit_proto::record::field::Identifier {
            name: Some(name.into()),
            ..Default::default()
        }),
        value: Some(value),
        ..Default::default()
    }
}

fn bytes(name: &str, value: &[u8]) -> Field {
    field(
        name,
        FieldValue {
            r#type: Some(FieldType::BytesType as i32),
            bytes_value: Some(value.to_vec()),
            ..Default::default()
        },
    )
}

fn legacy_payload() -> Vec<u8> {
    [
        1i64.to_le_bytes().as_slice(),
        b"receiver-fixture",
        b"sender-fixture",
        &[1, 2, 3, 4],
        2i64.to_le_bytes().as_slice(),
        (-1i64).to_le_bytes().as_slice(),
        0i64.to_le_bytes().as_slice(),
    ]
    .concat()
}

// Follow the production verification call site; fixture expectations are unchanged.
fn payload(share: &CuttlefishTlkShare, fields: &[Field]) -> Vec<u8> {
    share.data_for_signing(fields)
}

fn trusted_peer() -> (EncodedPeer, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let info = PeerPermanentInfo {
        signing_key: Some(key.public_key_to_der().unwrap()),
        ..Default::default()
    }
    .encode_to_vec();
    let mut signer = Signer::new(MessageDigest::sha384(), &key).unwrap();
    signer.update(b"TPPB.PeerPermanentInfo").unwrap();
    signer.update(&info).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let hash = format!(
        "SHA256:{}",
        base64_encode(&sha256(&[info.as_slice(), signature.as_slice()].concat()))
    );
    (
        EncodedPeer(CuttlefishPeer {
            hash: Some(hash),
            permanent_info: Some(SignedInfo {
                info: Some(info),
                signature: Some(signature),
            }),
            ..Default::default()
        }),
        key,
    )
}

fn sign(key: &PKey<Private>, data: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

#[test]
fn tlk_legacy_payload_stays_byte_identical() {
    assert_eq!(payload(&share(), &[]), legacy_payload());
}

#[test]
fn tlk_ownership_proof_signed_payload_verifies() {
    let (peer, key) = trusted_peer();
    let proof = [0xa1, 0xb2, 0xc3, 0xd4];
    let expected = [legacy_payload(), proof.to_vec()].concat();
    let signature = sign(&key, &expected);
    assert!(
        peer.verify_signature_dig(
            MessageDigest::sha256(),
            &payload(&share(), &[bytes("tlkOwnershipProof", &proof)]),
            &signature
        )
        .is_ok(),
        "A valid Apple-style TLK share with tlkOwnershipProof must verify"
    );
}

#[test]
fn tlk_invalid_signature_is_rejected() {
    let (peer, _) = trusted_peer();
    let (_, wrong_key) = trusted_peer();
    let data = payload(&share(), &[]);
    assert!(peer
        .verify_signature_dig(MessageDigest::sha256(), &data, &sign(&wrong_key, &data))
        .is_err());
}

#[test]
fn tlk_extra_scalars_match_apple_canonical_bytes() {
    let fields = vec![
        bytes("wrappedKey", &[9]), // Unknown camel-case field: Apple does not exclude this alias.
        bytes("server_metadata", &[99]),
        field(
            "eDate",
            FieldValue {
                r#type: Some(FieldType::DateType as i32),
                date_value: Some(cloudkit_proto::Date {
                    time: Some(-978307200.5),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        field(
            "dDouble",
            FieldValue {
                r#type: Some(FieldType::DoubleType as i32),
                double_value: Some(32.75),
                ..Default::default()
            },
        ),
        field(
            "cInteger",
            FieldValue {
                r#type: Some(FieldType::Int64Type as i32),
                signed_value: Some(-2),
                ..Default::default()
            },
        ),
        field(
            "bString",
            FieldValue {
                r#type: Some(FieldType::StringType as i32),
                string_value: Some("fixture".into()),
                ..Default::default()
            },
        ),
        bytes("aBytes", &[7, 8]),
    ];
    let expected = [
        legacy_payload(),
        vec![7, 8],
        b"fixture".to_vec(),
        (-2i64).to_le_bytes().to_vec(),
        32u64.to_le_bytes().to_vec(),
        b"1969-12-31T23:59:59Z".to_vec(),
        vec![9],
    ]
    .concat();
    assert_eq!(payload(&share(), &fields), expected,
        "Extra fields must follow CKKSTLKShare sorted scalar serialization, including NSNumber doubles");
}

#[test]
fn tlk_changed_ownership_proof_is_rejected() {
    let (peer, key) = trusted_peer();
    let original = [legacy_payload(), vec![1, 2, 3]].concat();
    let signature = sign(&key, &original);
    assert!(peer
        .verify_signature_dig(
            MessageDigest::sha256(),
            &payload(&share(), &[bytes("tlkOwnershipProof", &[1, 2, 4])]),
            &signature
        )
        .is_err());
}

#[test]
fn tlk_missing_class_key_is_an_error_not_a_panic() {
    assert!(KeychainKeyStore(vec![])
        .require_key("synthetic-zone", "classA")
        .is_err());
}

#[test]
fn tlk_all_invalid_shares_cannot_look_successful() {
    assert!(finish_tlk_share_fetch(vec![], 1).is_err());
}

#[test]
fn tlk_valid_share_survives_other_invalid_shares() {
    let keys = vec![CuttlefishSerializedKey::default()];
    assert_eq!(finish_tlk_share_fetch(keys, 1).unwrap().len(), 1);
}
