use bitcoin::{
    key::{Secp256k1, TweakedPublicKey},
    ScriptBuf,
};
use musig2::KeyAggContext;
use secp::{Point, Scalar, G};

use std::error::Error;

// Demonstrates how our unspendable tweaking matches the `bitcoin` crate's tweaking.
#[test]
fn demo_unspendable_tweaks() -> Result<(), Box<dyn Error>> {
    let k1: Scalar = "d12bfbef9790c08b87ca6f8656e6a3660aad3db4698be7d4951d4a9e48c777a3"
        .parse()
        .unwrap();
    let k2: Scalar = "06a71b4ba66658e5c9ed311f4d90541bb95910b890b5f93f32b942e1c1e56c65"
        .parse()
        .unwrap();

    let pubkeys = [k1 * G, k2 * G];

    let key_agg_ctx = KeyAggContext::new(pubkeys)?.with_unspendable_taproot_tweak()?;

    // Untweaked (internal) key
    let untweaked_pubkey_point: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    let untweaked_pubkey_xonly =
        bitcoin::XOnlyPublicKey::from_slice(&untweaked_pubkey_point.serialize_xonly()).unwrap();
    assert_eq!(
        untweaked_pubkey_point.to_string(),
        "03656d72bc43082f28d32360f2cf02d78574386d3bbeb8f944112f061edf0a8c47"
    );
    assert_eq!(
        untweaked_pubkey_xonly.to_string(),
        "656d72bc43082f28d32360f2cf02d78574386d3bbeb8f944112f061edf0a8c47"
    );

    // Tweaked (output) key
    let tweaked_pubkey_point: Point = key_agg_ctx.aggregated_pubkey();
    let tweaked_pubkey_xonly =
        bitcoin::XOnlyPublicKey::from_slice(&tweaked_pubkey_point.serialize_xonly()).unwrap();
    assert_eq!(
        tweaked_pubkey_point.to_string(),
        "02a84db1877f2101c0ac472915c0bc63c4a1af8accbff2dd0b6944c70dbcf9f017"
    );
    assert_eq!(
        tweaked_pubkey_xonly.to_string(),
        "a84db1877f2101c0ac472915c0bc63c4a1af8accbff2dd0b6944c70dbcf9f017"
    );

    // Our crate should ensure the tweaked KeyAggContext results in properly tweaked aggregated pubkey.
    let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(tweaked_pubkey_xonly);
    let spk1 = ScriptBuf::new_p2tr_tweaked(tweaked_pubkey);
    let spk2 = ScriptBuf::new_p2tr(&Secp256k1::new(), untweaked_pubkey_xonly, None);

    assert_eq!(spk1, spk2);

    Ok(())
}
