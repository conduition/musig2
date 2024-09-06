use rand::Rng;
use secp::{Point, Scalar};

use musig2::{AggNonce, KeyAggContext, PartialSignature, SecNonce, SCHNORR_SIGNATURE_SIZE};

fn run_reference_code(code: &str) -> Vec<u8> {
    let script = [
        "import reference",
        "from binascii import hexlify, unhexlify",
        "from sys import stdout\n\n",
    ]
    .join("\n")
        + code;

    let error_message = format!("failed to run reference code:\n{}", code);

    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect(&error_message);

    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(
        output.status.success(),
        "{}\nstderr: {}",
        error_message,
        stderr
    );

    output.stdout
}

#[test]
fn test_python_interop() {
    let output = String::from_utf8(run_reference_code("print('hello world')")).unwrap();
    assert_eq!(output, "hello world\n");
}

fn random_sample_indexes<R: Rng>(
    rng: &mut R,
    iterations: usize,
    max_count: usize,
    index_ceil: usize,
) -> Vec<Vec<usize>> {
    (0..iterations)
        .map(|_| {
            let count = rng.gen_range(1..max_count);
            (0..count)
                .map(|_| rng.gen_range(0..index_ceil))
                .collect::<Vec<usize>>()
        })
        .collect()
}

/// Runs our key aggregation code against the reference implementation using randomly
/// chosen pubkey inputs.
#[test]
fn test_key_aggregation() {
    let mut rng = rand::thread_rng();

    // Initialize a random array of pubkeys.
    let mut all_pubkeys = [Point::generator(); 6];
    for pubkey in &mut all_pubkeys {
        *pubkey *= Scalar::random(&mut rng);
    }

    const ITERATIONS: usize = 5;
    const MAX_PUBKEYS: usize = 8;

    // randomly sample indexes into that array, with at least length 1
    let generated_indexes: Vec<Vec<usize>> =
        random_sample_indexes(&mut rng, ITERATIONS, MAX_PUBKEYS, all_pubkeys.len());

    let all_pubkeys_json = serde_json::to_string(&all_pubkeys).unwrap();
    let generated_indexes_json = serde_json::to_string(&generated_indexes).unwrap();

    let reference_code_output = run_reference_code(&format!(
        r#"
all_pubkeys = [unhexlify(key) for key in {all_pubkeys_json}]
generated_indexes = {generated_indexes_json}

for indexes in generated_indexes:
    pubkeys = [all_pubkeys[i] for i in indexes]
    Q = reference.key_agg(pubkeys)[0]
    stdout.buffer.write(reference.cbytes(Q))
"#
    ));
    assert_eq!(
        reference_code_output.len(),
        ITERATIONS * 33,
        "expected to receive exactly {} * 33 bytes back from reference impl",
        ITERATIONS
    );

    for i in 0..ITERATIONS {
        let pubkeys: Vec<Point> = generated_indexes[i]
            .iter()
            .map(|&j| all_pubkeys[j])
            .collect();

        let expected_pubkey_bytes = &reference_code_output[(i * 33)..(i * 33 + 33)];
        let expected_pubkey = Point::from_slice(expected_pubkey_bytes).unwrap_or_else(|_| {
            panic!(
                "error decoding aggregated public key from reference implementation: {}",
                base16ct::lower::encode_string(expected_pubkey_bytes)
            )
        });

        let pubkeys_json = serde_json::to_string(&pubkeys).unwrap();

        let our_pubkey: Point = KeyAggContext::new(pubkeys)
            .unwrap_or_else(|_| panic!("failed to aggregate pubkeys: {}", pubkeys_json))
            .aggregated_pubkey();

        assert_eq!(
            our_pubkey, expected_pubkey,
            "aggregated pubkey does not match reference impl for inputs: {}",
            pubkeys_json
        );
    }
}

/// Runs our partial signing and signature aggregation code against
/// the reference implementation.
#[test]
fn test_signing() {
    let mut rng = rand::thread_rng();

    let mut all_seckeys = [Scalar::one(); 4];
    for seckey in &mut all_seckeys {
        *seckey = Scalar::random(&mut rng);
    }

    let all_pubkeys = all_seckeys
        .into_iter()
        .map(|sk| sk.base_point_mul())
        .collect::<Vec<Point>>();

    let all_nonce_seeds = (0..all_seckeys.len())
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();

    let message = "Welcome to MuSig";

    const ITERATIONS: usize = 5;
    const MAX_SIGNERS: usize = 5;

    let all_key_indexes =
        random_sample_indexes(&mut rng, ITERATIONS, MAX_SIGNERS, all_seckeys.len());

    let all_aggregated_pubkeys = (0..ITERATIONS)
        .map(|i| {
            let pubkeys = all_key_indexes[i].iter().map(|&j| all_pubkeys[j]);
            KeyAggContext::new(pubkeys).unwrap().aggregated_pubkey()
        })
        .collect::<Vec<Point>>();

    let all_seckeys_json = serde_json::to_string(&all_seckeys).unwrap();
    let all_pubkeys_json = serde_json::to_string(&all_pubkeys).unwrap();
    let all_nonce_seeds_json = serde_json::to_string(&all_nonce_seeds).unwrap();
    let all_key_indexes_json = serde_json::to_string(&all_key_indexes).unwrap();
    let all_aggregated_pubkeys_json = serde_json::to_string(&all_aggregated_pubkeys).unwrap();

    let reference_code_output = run_reference_code(&format!(
        r#"
all_seckeys = [unhexlify(key) for key in {all_seckeys_json}]
all_pubkeys = [unhexlify(key) for key in {all_pubkeys_json}]
all_nonce_seeds = [unhexlify(seed) for seed in {all_nonce_seeds_json}]
all_key_indexes = {all_key_indexes_json}
all_aggregated_pubkeys = [unhexlify(b) for b in {all_aggregated_pubkeys_json}]

message = b"{message}"

for i in range({ITERATIONS}):
    aggregated_pubkey = all_aggregated_pubkeys[i]
    key_indexes = all_key_indexes[i]
    seckeys = [all_seckeys[j] for j in key_indexes]
    pubkeys = [all_pubkeys[j] for j in key_indexes]
    nonce_seeds = [all_nonce_seeds[j] for j in key_indexes]

    nonces = [
        reference.nonce_gen_internal(
            nonce_seeds[k],
            seckeys[k],
            pubkeys[k],
            aggregated_pubkey[1:],
            message,
            k.to_bytes(4, 'big')
        )
        for k in range(len(key_indexes))
    ]

    aggnonce = reference.nonce_agg([pubnonce for (_, pubnonce) in nonces])
    session_ctx = (aggnonce, pubkeys, [], [], message)

    partial_signatures = []
    for ((secnonce, _), seckey) in zip(nonces, seckeys):
        partial_signature = reference.sign(secnonce, seckey, session_ctx)
        stdout.buffer.write(partial_signature)
        partial_signatures.append(partial_signature)

    final_signature = reference.partial_sig_agg(partial_signatures, session_ctx)
    stdout.buffer.write(final_signature)
"#
    ));

    let n_partial_signatures = all_key_indexes
        .iter()
        .map(|indexes| indexes.len())
        .sum::<usize>();

    assert_eq!(
        reference_code_output.len(),
        n_partial_signatures * 32 + SCHNORR_SIGNATURE_SIZE * ITERATIONS,
        "expected {} partial signatures and {} aggregated signatures from reference \
         implementation, got {} bytes",
        n_partial_signatures,
        ITERATIONS,
        reference_code_output.len()
    );

    let mut cursor = 0usize;

    for i in 0..ITERATIONS {
        let key_indexes = all_key_indexes[i].clone();
        let seckeys = key_indexes
            .iter()
            .map(|&j| all_seckeys[j])
            .collect::<Vec<Scalar>>();
        let pubkeys = key_indexes
            .iter()
            .map(|&j| all_pubkeys[j])
            .collect::<Vec<Point>>();
        let nonce_seeds = key_indexes
            .iter()
            .map(|&j| all_nonce_seeds[j])
            .collect::<Vec<Scalar>>();

        let debug_json = serde_json::to_string(&serde_json::json!({
            "seckeys": &seckeys,
            "nonce_seeds": &nonce_seeds,
        }))
        .unwrap();

        let aggregated_pubkey = all_aggregated_pubkeys[i];
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        assert_eq!(key_agg_ctx.aggregated_pubkey::<Point>(), aggregated_pubkey);

        let secnonces: Vec<SecNonce> = nonce_seeds
            .into_iter()
            .enumerate()
            .map(|(k, seed)| {
                SecNonce::generate(
                    seed.serialize(),
                    seckeys[k],
                    aggregated_pubkey,
                    message,
                    (k as u32).to_be_bytes(),
                )
            })
            .collect();

        let aggnonce = secnonces
            .iter()
            .map(|secnonce| secnonce.public_nonce())
            .sum::<AggNonce>();

        let mut partial_signatures = Vec::with_capacity(seckeys.len());
        for k in 0..seckeys.len() {
            let our_partial_signature: PartialSignature = musig2::sign_partial(
                &key_agg_ctx,
                seckeys[k],
                secnonces[k].clone(),
                &aggnonce,
                message,
            )
            .unwrap_or_else(|_| {
                panic!(
                    "failed to sign with randomly chosen keys and nonces: {}",
                    debug_json
                )
            });

            let expected_partial_signature_bytes = &reference_code_output[cursor..cursor + 32];
            cursor += 32;

            assert_eq!(
                &our_partial_signature.serialize(),
                expected_partial_signature_bytes,
                "incorrect partial signature for signer index {} using keys and nonces: {}",
                k,
                debug_json,
            );

            partial_signatures.push(our_partial_signature);
        }
        let expected_signature_bytes =
            &reference_code_output[cursor..cursor + SCHNORR_SIGNATURE_SIZE];
        cursor += SCHNORR_SIGNATURE_SIZE;

        let our_signature: [u8; SCHNORR_SIGNATURE_SIZE] = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &aggnonce,
            partial_signatures,
            message,
        )
        .expect("error aggregating partial signatures");

        assert_eq!(
            &our_signature, expected_signature_bytes,
            "incorrect aggregated signature using keys and nonces: {}",
            debug_json
        );
    }
}
