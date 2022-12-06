use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion};
use rabin_williams::generate_private_key;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn sign(c: &mut Criterion) {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(seed.as_secs());

    let private_key = generate_private_key(&mut rng, 512).unwrap();
    let msg: &[u8] = &rng.gen::<[u8; 32]>();

    c.bench_function("Rabin-Williams signing", |b| {
        b.iter(|| private_key.sign(msg))
    });
}

fn verify(c: &mut Criterion) {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(seed.as_secs());

    let private_key = generate_private_key(&mut rng, 512).unwrap();
    let msg: &[u8] = &rng.gen::<[u8; 32]>();
    let signature = private_key.sign(msg).unwrap();
    let pub_key = private_key.to_public_key();
    c.bench_function("Rabin-Williams verification", |b| {
        b.iter(|| pub_key.verify(msg, signature.clone()))
    });
}

criterion_group! {
    name = rabin_william_benches;
    config = Criterion::default();
    targets =
        sign,
        verify,
}

criterion_main!(rabin_william_benches);
