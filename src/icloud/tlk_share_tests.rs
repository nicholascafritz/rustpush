//! Synthetic, offline CKKS fixtures. No account records or persisted key material.
use super::*;
use cloudkit_proto::record::{field::{Value as FieldValue, value::Type as FieldType}, Field};

fn share() -> CuttlefishTlkShare {
    CuttlefishTlkShare {
        receiver: "receiver-fixture".into(), sender: "sender-fixture".into(),
        version: 1, curve: 2, epoch: -1, poisoned: 0,
        wrappedkey: base64_encode(&[1, 2, 3, 4]), ..Default::default()
    }
}

fn field(name: &str, value: FieldValue) -> Field {
    Field { identifier: Some(cloudkit_proto::record::field::Identifier { name: Some(name.into()), ..Default::default() }),
        value: Some(value), ..Default::default() }
}

fn bytes(name: &str, value: &[u8]) -> Field {
    field(name, FieldValue { r#type: Some(FieldType::BytesType as i32),
        bytes_value: Some(value.to_vec()), ..Default::default() })
}

fn legacy_payload() -> Vec<u8> {
    [1i64.to_le_bytes().as_slice(), b"receiver-fixture", b"sender-fixture",
        &[1, 2, 3, 4], 2i64.to_le_bytes().as_slice(), (-1i64).to_le_bytes().as_slice(),
        0i64.to_le_bytes().as_slice()].concat()
}

// This adapter follows the production verification call site on the baseline.
// Only its API call changes when PR #34 adds the record-fields argument.
fn payload(share: &CuttlefishTlkShare, _fields: &[Field]) -> Vec<u8> {
    share.data_for_signing()
}

fn trusted_peer() -> (EncodedPeer, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let info = PeerPermanentInfo { signing_key: Some(key.public_key_to_der().unwrap()),
        ..Default::default() }.encode_to_vec();
    let mut signer = Signer::new(MessageDigest::sha384(), &key).unwrap();
    signer.update(b"TPPB.PeerPermanentInfo").unwrap();
    signer.update(&info).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let hash = format!("SHA256:{}", base64_encode(&sha256(&[info.as_slice(), signature.as_slice()].concat())));
    (EncodedPeer(CuttlefishPeer { hash: Some(hash),
        permanent_info: Some(SignedInfo { info: Some(info), signature: Some(signature) }),
        ..Default::default() }), key)
}

fn sign(key: &PKey<Private>, data: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(data).unwrap(); signer.sign_to_vec().unwrap()
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
    assert!(peer.verify_signature_dig(MessageDigest::sha256(),
        &payload(&share(), &[bytes("tlkOwnershipProof", &proof)]), &signature).is_ok(),
        "A valid Apple-style TLK share with tlkOwnershipProof must verify");
}

#[test]
fn tlk_invalid_signature_is_rejected() {
    let (peer, _) = trusted_peer();
    let (_, wrong_key) = trusted_peer();
    let data = payload(&share(), &[]);
    assert!(peer.verify_signature_dig(MessageDigest::sha256(), &data, &sign(&wrong_key, &data)).is_err());
}
