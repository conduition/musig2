// use bitcoin::key::TweakedPublicKey;
use bitcoin::{
    absolute::LockTime,
    sighash::{Prevouts, SighashCache, TapSighash, TapSighashType},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use musig2::{AggNonce, KeyAggContext, PartialSignature, SecNonce};
use secp::{Point, Scalar, G};

const PREVOUT_TX: &str = "02000000000101f285fc5b46fbbcc4e8e25bd30500196384bacdcfadc67fba53\
                          a4f39e622f96be0100000000fdffffff0210270000000000002251204c2dfc6c\
                          fa8454e1b260a5d34083fc0e993a233a2fc794977d87302e8e401586b5ea0100\
                          00000000160014c06885ae6fd959c8ad391a5215f479aea73882540247304402\
                          2009e4d15a83b84f86eed8aa624b8ce15bef48c1c6595cd97c89772ac615fc08\
                          ed02206b96bda72c65c2d43b23e4f06335625545e4ef8d8c0eecfae74745ba12\
                          74e26f0121024833e9f45d6bdfec69743f890f033eb83b3cabda31dbb7d5fa72\
                          270feb6eed6e951f0d00";

const PREVOUT_VOUT: u32 = 0;
const PREVOUT_VALUE: Amount = Amount::from_sat(10_000);

const EXPECTED_SPENDING_TX: &str = "020000000001016e6427e0edfdb793d5bc853597d20ce9229d128f\
                                    39181dfb009ebf1fa91f42bb000000000000000000012224000000\
                                    000000160014b1e6c11edebf01ec881bec426ecd8acc582d92f201\
                                    40817c605659a6fbcc416224b456b96c6e79d3ad9e14d4c43c0b2a\
                                    974d0040ae22b22d33ad68e9155b878afceda886b44c1e44f7e414\
                                    7fbed417fe721dfc445f4d00000000";

#[test]
fn sign_btc_tx() {
    let k1: Scalar = "d12bfbef9790c08b87ca6f8656e6a3660aad3db4698be7d4951d4a9e48c777a3"
        .parse()
        .unwrap();
    let k2: Scalar = "06a71b4ba66658e5c9ed311f4d90541bb95910b890b5f93f32b942e1c1e56c66"
        .parse()
        .unwrap();

    let pubkeys = [k1 * G, k2 * G];

    let key_agg_ctx = KeyAggContext::new(pubkeys)
        .unwrap()
        .with_unspendable_taproot_tweak()
        .unwrap();

    let agg_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    let agg_pubkey_xonly =
        bitcoin::XOnlyPublicKey::from_slice(&agg_pubkey.serialize_xonly()).unwrap();
    let tweaked_pubkey = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_pubkey_xonly);
    let prevout_spk = ScriptBuf::new_p2tr_tweaked(tweaked_pubkey);

    let prevout_tx_bytes: Vec<u8> = base16ct::mixed::decode_vec(PREVOUT_TX).unwrap();
    let prevout_tx: Transaction =
        bitcoin::consensus::encode::deserialize(&prevout_tx_bytes).unwrap();

    assert_eq!(
        prevout_tx.output[PREVOUT_VOUT as usize].script_pubkey, prevout_spk,
        "prevout SPK must match"
    );
    assert_eq!(
        prevout_tx.output[PREVOUT_VOUT as usize].value, PREVOUT_VALUE,
        "prevout value must match"
    );

    let dest_addr = "bc1qk8nvz8k7huq7ezqma3pxanv2e3vzmyhjgcztsz"
        .parse::<bitcoin::Address<_>>()
        .unwrap()
        .assume_checked();

    let mut spending_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            sequence: Sequence::ZERO,
            previous_output: OutPoint {
                txid: prevout_tx.compute_txid(),
                vout: PREVOUT_VOUT,
            },
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: PREVOUT_VALUE - Amount::from_sat(750),
            script_pubkey: dest_addr.script_pubkey(),
        }],
    };

    let sighash: TapSighash = SighashCache::new(&spending_tx)
        .taproot_key_spend_signature_hash(
            0, // vin
            &Prevouts::All(&[&prevout_tx.output[PREVOUT_VOUT as usize]]),
            TapSighashType::Default,
        )
        .unwrap();

    // Sign the sighash with musig
    let signature = sign_musig(&key_agg_ctx, (k1, k2), sighash);

    musig2::verify_single(agg_pubkey, signature, sighash)
        .expect("signature should be valid for aggregated key");

    // Append the signature to the TxIn witness.
    let serialized_sig: [u8; 64] = signature.serialize();
    spending_tx.input[0].witness.push(serialized_sig);

    assert_eq!(
        bitcoin::consensus::encode::serialize_hex(&spending_tx),
        EXPECTED_SPENDING_TX
    );

    // https://mempool.space/tx/d4601e5e4ed0ec9a2a012eea927d2954e499ce54e0ce5dd8ea59911cbeba4434
    assert_eq!(
        spending_tx.compute_txid().to_string(),
        "d4601e5e4ed0ec9a2a012eea927d2954e499ce54e0ce5dd8ea59911cbeba4434"
    );
}

fn sign_musig(
    key_agg_ctx: &KeyAggContext,
    (k1, k2): (Scalar, Scalar),
    message: impl AsRef<[u8]>,
) -> musig2::CompactSignature {
    let agg_pub: Point = key_agg_ctx.aggregated_pubkey();

    let r1 = SecNonce::build([0x11; 32]) // insecure, use an actual secret nonce seed
        .with_seckey(k1)
        .with_aggregated_pubkey(agg_pub)
        .with_message(&message)
        .build();
    let r2 = SecNonce::build([0x22; 32]) // insecure, use an actual secret nonce seed
        .with_seckey(k2)
        .with_aggregated_pubkey(agg_pub)
        .with_message(&message)
        .build();

    let pubnonce1 = r1.public_nonce();
    let pubnonce2 = r2.public_nonce();

    let aggnonce = AggNonce::sum([pubnonce1, pubnonce2]);

    let partial_sig1: PartialSignature =
        musig2::sign_partial(key_agg_ctx, k1, r1, &aggnonce, &message).unwrap();
    let partial_sig2: PartialSignature =
        musig2::sign_partial(key_agg_ctx, k2, r2, &aggnonce, &message).unwrap();

    let final_signature = musig2::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggnonce,
        [partial_sig1, partial_sig2],
        message,
    )
    .unwrap();

    final_signature
}
