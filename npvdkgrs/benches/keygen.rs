use std::{collections::BTreeMap, time::Duration};

use ark_std::rand::{self, SeedableRng};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use npvdkgrs::{maps::SharesMap, Address, Keypair, PublicKey};

fn bench_keygen(n: u16, t: u16) -> Duration {
    let mut rng = &mut rand::rngs::StdRng::seed_from_u64(u64::from(n + 1));
    let keypairs = (0..n).map(|_| Keypair::rand(&mut rng)).collect::<Vec<_>>();
    let participants: BTreeMap<_, _> = keypairs.iter().map(|k| (k.address().unwrap(), k.pk())).collect();

    struct Party {
        shares: SharesMap,
        keypair: Keypair,
        participants: BTreeMap<Address, PublicKey>,
    }

    let mut parties = (0..n)
        .map(|i| Party {
            shares: SharesMap::new(n as usize),
            keypair: keypairs[usize::from(i)].clone(),
            participants: participants.clone(),
        })
        .collect::<Vec<_>>();

    let mut bulltin_board = BTreeMap::new();

    // Generate shares
    let share_gen_time = (0..n)
        .map(|i| {
            let rng = &mut rand::rngs::StdRng::seed_from_u64(u64::from(i + 1));
            let now = std::time::Instant::now();
            let private_poly = npvdkgrs::party::random_polynomial(rng, t, None);
            let shares =
                npvdkgrs::party::generate_shares(rng, &parties[usize::from(i)].participants, &private_poly).unwrap();
            let elapsed = now.elapsed();
            // insert shares into the bulletin board
            bulltin_board.insert(parties[usize::from(i)].keypair.address().unwrap(), shares);
            elapsed
        })
        .sum::<core::time::Duration>();

    parties.iter_mut().for_each(|party| {
        for (address, share_vec) in bulltin_board.iter() {
            let _ = party.shares.insert(*address, share_vec.clone());
        }
    });

    // Verify and recover keys
    let recover_time = parties
        .iter()
        .map(|party| {
            let now = std::time::Instant::now();
            party
                .shares
                .clone()
                .recover_keys(&party.keypair.address().unwrap(), party.keypair.sk(), &party.participants)
                .unwrap();
            now.elapsed()
        })
        .sum::<core::time::Duration>();
    let total_time = share_gen_time + recover_time;
    let avg_time = total_time / u32::from(n);
    avg_time
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    for n in [3u16, 5, 8, 10, 12, 15, 18] {
        let t = n * 2 / 3;
        group
            .throughput(Throughput::Elements(n as u64))
            .sampling_mode(criterion::SamplingMode::Flat)
            .sample_size(15)
            .bench_with_input(format!("{t}-of-{n}"), &(n, t), |b, &(n, t)| {
                b.iter_custom(|iters| {
                    let mut total_time = core::time::Duration::ZERO;
                    for _ in 0..iters {
                        total_time += bench_keygen(n, t);
                    }
                    total_time
                });
            });
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
