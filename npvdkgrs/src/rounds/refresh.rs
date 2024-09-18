use ark_std::rand;
use round_based::Mpc;

use crate::{
    keys::{Keypair, PublicKey},
    party::KeysharePackage,
    trace::Tracer,
};

use super::keygen::{Error, Msg};

/// Run Non Interactive Keyrefresh protocol.
pub async fn run<R, M>(
    rng: &mut R,
    tracer: Option<&mut dyn Tracer>,
    keypair: &Keypair,
    old_package: &KeysharePackage,
    new_participants: &[PublicKey],
    t: u16,
    party: M,
) -> Result<KeysharePackage, Error>
where
    R: rand::RngCore + rand::CryptoRng,
    M: Mpc<ProtocolMessage = Msg>,
{
    super::keygen::run_with_old_package(rng, tracer, keypair, old_package, new_participants, t, party).await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use rand::{rngs::StdRng, SeedableRng};
    use round_based::simulation::Simulation;

    use crate::{
        addr::Address,
        rounds::{
            keygen::run as keygen,
            sign::{run as sign, Msg as SigningMsg},
        },
        sig::Signature,
        trace::PerfProfiler,
    };

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn it_works() {
        let n = 5;
        let t = n * 2 / 3;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();
        let outputs = run_keygen(t, &keypairs).await;
        let pkg = &outputs[&keypairs[0].address().unwrap()];

        // Sigin a message with the old keyshare and verify it.
        let msg = b"message to be signed";
        let sig = run_singing(&keypairs, &outputs, msg).await;
        assert!(sig.verify(msg, &pkg.global_verification_key()));

        // Run the refresh protocol without changing the participants.
        eprintln!("Running {t}-out-of-{n} Keyrefresh");
        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[usize::from(i)].clone();
            let address = keypair.address().unwrap();
            let old_package = outputs[&address].clone();
            let participants = participants.clone();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 2));
                let output = run(rng, None, &keypair, &old_package, &participants, t, party).await.unwrap();
                (keypair, output)
            });
            tasks.push(output);
        }

        let mut outputs2 = BTreeMap::new();
        for task in tasks {
            let (keypair, output) = task.await.unwrap();
            outputs2.insert(keypair.address().unwrap(), output);
        }

        // Assert that all parties outputed the same public key
        let first = keypairs[0].address().unwrap();
        let pkg_refresh = &outputs2[&first];
        for i in 1..n {
            let address = keypairs[usize::from(i)].address().unwrap();
            let pkg_refresh2 = &outputs2[&address];
            assert_eq!(pkg_refresh.global_verification_key(), pkg_refresh2.global_verification_key());
        }
        eprintln!("Refreshed Group PublicKey: {}", pkg_refresh.global_verification_key());
        assert_eq!(pkg.global_verification_key(), pkg_refresh.global_verification_key());

        // Sigin a message with the new keyshares and verify it.
        let msg = b"message to be signed";
        let sig = run_singing(&keypairs, &outputs2, msg).await;
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ncrease_n() {
        let n = 5;
        let t = n * 2 / 3;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();
        let outputs = run_keygen(t, &keypairs).await;
        let pkg = &outputs[&keypairs[0].address().unwrap()];
        let gvk = pkg.global_verification_key();

        // Run the refresh protocol with adding a new participant.
        let n = n + 1;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        eprintln!("Running {t}-out-of-{n} Keyrefresh");

        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[usize::from(i)].clone();
            let address = keypair.address().unwrap();
            let old_package = outputs.get(&address).cloned().unwrap_or(KeysharePackage {
                n,
                t,
                i,
                share_keypair: Keypair::from_sk(Fr::zero().into()),
                gvk_poly: vec![gvk.into()],
            });
            let participants = participants.clone();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 2));
                let mut tracer = PerfProfiler::new();
                let output = run(rng, Some(&mut tracer), &keypair, &old_package, &participants, t, party)
                    .await
                    .unwrap();
                eprintln!("Party {i} => {}", tracer.get_report().unwrap());
                (keypair, output)
            });
            tasks.push(output);
        }

        let mut outputs2 = BTreeMap::new();
        for task in tasks {
            let (keypair, output) = task.await.unwrap();
            outputs2.insert(keypair.address().unwrap(), output);
        }

        // Assert that all parties outputed the same public key
        let first = keypairs[0].address().unwrap();
        let pkg_refresh = &outputs2[&first];
        for i in 1..n {
            let address = keypairs[usize::from(i)].address().unwrap();
            let pkg_refresh2 = &outputs2[&address];
            assert_eq!(pkg_refresh.global_verification_key(), pkg_refresh2.global_verification_key());
        }
        eprintln!("Refreshed Group PublicKey: {}", pkg_refresh.global_verification_key());
        assert_eq!(pkg.global_verification_key(), pkg_refresh.global_verification_key());

        // Sigin a message with the new keyshares and verify it.
        let msg = b"message to be signed";
        let sig = run_singing(&keypairs, &outputs2, msg).await;
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn decrease_n() {
        let n = 5;
        let t = n * 2 / 3;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();
        let outputs = run_keygen(t, &keypairs).await;
        let pkg = &outputs[&keypairs[0].address().unwrap()];
        let gvk = pkg.global_verification_key();

        // Run the refresh protocol with removing a participant.
        let n = n - 1;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        eprintln!("Running {t}-out-of-{n} Keyrefresh");

        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[usize::from(i)].clone();
            let address = keypair.address().unwrap();
            let old_package = outputs.get(&address).cloned().unwrap_or(KeysharePackage {
                n,
                t,
                i,
                share_keypair: Keypair::from_sk(Fr::zero().into()),
                gvk_poly: vec![gvk.into()],
            });
            let participants = participants.clone();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 2));
                let mut tracer = PerfProfiler::new();
                let output = run(rng, Some(&mut tracer), &keypair, &old_package, &participants, t, party)
                    .await
                    .unwrap();
                eprintln!("Party {i} => {}", tracer.get_report().unwrap());
                (keypair, output)
            });
            tasks.push(output);
        }

        let mut outputs2 = BTreeMap::new();
        for task in tasks {
            let (keypair, output) = task.await.unwrap();
            outputs2.insert(keypair.address().unwrap(), output);
        }

        // Assert that all parties outputed the same public key
        let first = keypairs[0].address().unwrap();
        let pkg_refresh = &outputs2[&first];
        for i in 1..n {
            let address = keypairs[usize::from(i)].address().unwrap();
            let pkg_refresh2 = &outputs2[&address];
            assert_eq!(pkg_refresh.global_verification_key(), pkg_refresh2.global_verification_key());
        }
        eprintln!("Refreshed Group PublicKey: {}", pkg_refresh.global_verification_key());
        assert_eq!(pkg.global_verification_key(), pkg_refresh.global_verification_key());

        // Sigin a message with the new keyshares and verify it.
        let msg = b"message to be signed";
        let sig = run_singing(&keypairs, &outputs2, msg).await;
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn increase_n_t() {
        let n = 3;
        let t = n * 2 / 3;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();
        let outputs = run_keygen(t, &keypairs).await;
        let pkg = &outputs[&keypairs[0].address().unwrap()];
        let gvk = pkg.global_verification_key();

        // Run the refresh protocol with adding a more participant.
        let t = t + 1;
        let n = n + 3;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        eprintln!("Running {t}-out-of-{n} Keyrefresh");

        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[usize::from(i)].clone();
            let address = keypair.address().unwrap();
            let old_package = outputs.get(&address).cloned().unwrap_or(KeysharePackage {
                n,
                t,
                i,
                share_keypair: Keypair::from_sk(Fr::zero().into()),
                gvk_poly: vec![gvk.into()],
            });
            let participants = participants.clone();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 2));
                let mut tracer = PerfProfiler::new();
                let output = run(rng, Some(&mut tracer), &keypair, &old_package, &participants, t, party)
                    .await
                    .unwrap();
                eprintln!("Party {i} => {}", tracer.get_report().unwrap());
                (keypair, output)
            });
            tasks.push(output);
        }

        let mut outputs2 = BTreeMap::new();
        for task in tasks {
            let (keypair, output) = task.await.unwrap();
            outputs2.insert(keypair.address().unwrap(), output);
        }

        // Assert that all parties outputed the same public key
        let first = keypairs[0].address().unwrap();
        let pkg_refresh = &outputs2[&first];
        for i in 1..n {
            let address = keypairs[usize::from(i)].address().unwrap();
            let pkg_refresh2 = &outputs2[&address];
            assert_eq!(pkg_refresh.global_verification_key(), pkg_refresh2.global_verification_key());
        }
        eprintln!("Refreshed Group PublicKey: {}", pkg_refresh.global_verification_key());
        assert_eq!(pkg.global_verification_key(), pkg_refresh.global_verification_key());

        // Sigin a message with the new keyshares and verify it.
        let msg = b"message to be signed";
        let sig = run_singing(&keypairs, &outputs2, msg).await;
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    fn generate_keypairs(n: u16) -> Vec<Keypair> {
        let mut keypairs = Vec::new();
        for i in 0..n {
            let rng = &mut StdRng::seed_from_u64(0xdead + u64::from(i + 1));
            let keypair = Keypair::rand(rng);
            keypairs.push(keypair);
        }
        keypairs.sort_unstable_by(|a, b| a.pk().cmp(&b.pk()));
        keypairs
    }

    async fn run_keygen(t: u16, keypairs: &[Keypair]) -> BTreeMap<Address, KeysharePackage> {
        let n = keypairs.len() as u16;
        eprintln!("Running {t}-out-of-{n} Keygen");
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[usize::from(i)].clone();
            let participants = participants.clone();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 1));
                let output = keygen(rng, None, &keypair, &participants, t, party).await.unwrap();
                (keypair, output)
            });
            tasks.push(output);
        }

        let mut outputs = BTreeMap::new();
        for task in tasks {
            let (keypair, output) = task.await.unwrap();
            outputs.insert(keypair.address().unwrap(), output);
        }

        let first = keypairs[0].address().unwrap();
        let pkg = &outputs[&first];
        eprintln!("Group PublicKey: {}", pkg.global_verification_key());
        outputs
    }

    async fn run_singing(keypairs: &[Keypair], pkgs: &BTreeMap<Address, KeysharePackage>, msg: &[u8]) -> Signature {
        let n = keypairs.len() as u16;
        let t = pkgs.values().next().unwrap().t;
        eprintln!("Running {t}-out-of-{n} Signing");
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        let mut simulation = Simulation::<SigningMsg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[usize::from(i)].clone();
            let participants = participants.clone();
            let pkg = pkgs.get(&keypair.address().unwrap()).cloned().unwrap();
            let my_msg = msg.to_vec();
            let output = tokio::spawn(async move {
                let output = sign(None, &pkg, &participants, &my_msg, party).await.unwrap();
                (keypair, output)
            });
            tasks.push(output);
        }

        let mut outputs = BTreeMap::new();
        for task in tasks {
            let (keypair, output) = task.await.unwrap();
            outputs.insert(keypair.address().unwrap(), output);
        }

        outputs.values().next().unwrap().clone()
    }
}
