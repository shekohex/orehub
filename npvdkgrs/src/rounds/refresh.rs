use ark_serialize::SerializationError;
use ark_std::{collections::BTreeMap, rand, vec::Vec};
use round_based::{
    rounds_router::RoundsRouter, runtime::AsyncRuntime, Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage, SinkExt,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    addr::Address,
    keys::{Keypair, PublicKey},
    maps::{Error as SharesError, SharesMap},
    params::Parameters,
    party::KeysharePackage,
    share::PublicShare,
    trace::Tracer,
};

use super::{store::ThresholdRoundInput, IoError};

/// Protocol message
#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    /// Round 1
    Reshare(ReshareMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReshareMsg {
    /// New shares to other parties
    ///
    /// Could be empty, if we are a new party.
    pub shares: Option<Vec<PublicShare>>,
    /// Sender's public key
    pub sender: PublicKey,
}

/// Keyrefresh protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("keyrefresh protocol is failed to complete")]
pub struct Error(#[cfg_attr(feature = "std", source)] Reason);

/// Keygen protocol abort reason
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Reason {
    /// Protocol was maliciously aborted by another party
    Aborted(#[cfg_attr(feature = "std", source)] KeyrefreshAborted),
    /// IO error
    IoError(#[cfg_attr(feature = "std", source)] super::IoError),
    /// Bug occurred
    Bug(Bug),
}

super::impl_from! {
    impl From for Error {
        err: KeyrefreshAborted => Error(Reason::Aborted(err)),
        err: super::IoError => Error(Reason::IoError(err)),
        err: Bug => Error(Reason::Bug(err)),
    }
}

impl From<KeyrefreshAborted> for Reason {
    fn from(err: KeyrefreshAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KeyrefreshAborted {
    /// Not enough shares were collected, expected {0} at least.
    NotEnoughShares(u16),
    /// Fewer than `n` shares were collected, expected {0} at least.
    // TODO: blames
    FewerThanNShares(u16),
    /// Share is already provided. This could be a malicious attempt to provide a share twice.
    // TODO: blames
    ShareAlreadyProvided(u16),
    /// Invalid share was provided. This could be a malicious attempt to provide an invalid share.
    // TODO: blames
    InvalidShare(u16),
    /// Global Verification Key has been changed where it should not.
    GlobalVerificationKeyChanged,
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Bug {
    /// unexpected zero value
    NonZeroScalar,
    /// key share of one of the signers is zero - probability of that is negligible
    ZeroShare,
    /// shared public key is zero - probability of that is negligible"
    ZeroPk,
    /// Invalid Local Keyshare
    InvalidLocalKeyshare,
    /// Invalid number of participants, does not fit in a `u16`
    InvalidNumberOfParticipants,
    /// Invalid Protocol Parameters: {0}
    Parameters(#[cfg_attr(feature = "std", source)] crate::params::Error),
    /// Could not find public key in the list of participants.
    NotAParticipant,
    /// Participant at index {0} is out of bounds for the list of participants.
    ParticipantIndexOutOfBounds(usize),
    /// Serialization error: {0}
    Serialization(#[cfg_attr(feature = "std", source)] SerializationError),
    /// Error during working with the shares: {0}
    Share(#[cfg_attr(feature = "std", source)] crate::share::Error),
    /// Error during Signing the shares: {0}
    Signing(#[cfg_attr(feature = "std", source)] crate::keys::Error),
    /// Error during decryption: {0}
    Cipher(#[cfg_attr(feature = "std", source)] crate::cipher::Error),
    /// Error during Lagrange interpolation: {0}
    Interpolation(#[cfg_attr(feature = "std", source)] crate::poly::InterpolationError),
}

/// Run Non Interactive Keyrefresh Protocol
pub async fn run<R, M>(
    rng: &mut R,
    mut tracer: Option<&mut dyn Tracer>,
    keypair: &Keypair,
    pkg: &KeysharePackage,
    participants: &[PublicKey],
    t: u16,
    party: M,
) -> Result<KeysharePackage, Error>
where
    R: rand::RngCore + rand::CryptoRng,
    M: Mpc<ProtocolMessage = Msg>,
{
    tracer.protocol_begins();

    let n = u16::try_from(participants.len()).map_err(|_| Bug::InvalidNumberOfParticipants)?;
    let params = Parameters::new(n, t);
    params.validate().map_err(Bug::Parameters)?;

    let i = participants
        .iter()
        .position(|pk| pk == &keypair.pk())
        .ok_or(Bug::NotAParticipant)
        .and_then(|i| u16::try_from(i).map_err(|_| Bug::InvalidNumberOfParticipants))?;

    tracer.stage("Setup networking");

    let MpcParty { delivery, runtime, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg>::builder();
    let round1 = rounds.add_round(ThresholdRoundInput::<ReshareMsg>::broadcast(i, n, n));
    let mut rounds = rounds.listen(incomings);
    // Round 1
    tracer.round_begins();

    let participants_map = participants
        .iter()
        .map(|p| Result::<_, SerializationError>::Ok((Address::try_from(p)?, *p)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(Bug::Serialization)?;

    assert!(participants_map.len() == participants.len(), "Duplicate participants");

    let maybe_msg = if pkg.is_non_zero() {
        tracer.stage("Generate Own shares");
        let old_secret = Some(pkg.share_keypair.sk().expose_secret());
        let mut poly = crate::party::random_polynomial(rng, t, old_secret);

        let shares = crate::party::generate_shares(rng, &participants_map, &poly).map_err(Bug::Share)?;
        runtime.yield_now().await;
        // Zeroize the polynomial
        poly.coeffs.zeroize();

        let shares = Some(shares);
        let msg = ReshareMsg { shares, sender: keypair.pk() };

        tracer.stage("Broadcast shares");
        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::Reshare(msg.clone())))
            .await
            .map_err(|e| IoError::send_message(e))?;
        tracer.msg_sent();
        Some(msg)
    } else {
        tracer.stage("Sign empty shares");
        let shares = None;
        let msg = ReshareMsg { shares, sender: keypair.pk() };

        tracer.stage("Broadcast empty shares");
        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::Reshare(msg.clone())))
            .await
            .map_err(|e| IoError::send_message(e))?;
        tracer.msg_sent();
        None
    };

    tracer.receive_msgs();
    let other_shares = rounds.complete(round1).await.map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Collect shares");
    let msgs = if let Some(my_msg) = maybe_msg {
        other_shares.into_vec_including_me(my_msg)
    } else {
        other_shares.into_vec_without_me()
    };
    // Expects at least t+1 shares to be collected
    if msgs.len() < usize::from(t + 1) {
        return Err(KeyrefreshAborted::NotEnoughShares(t + 1).into());
    }

    let mut shares_map = SharesMap::new(usize::from(n));
    for (j, msg) in msgs.into_iter().enumerate() {
        let Some(ReshareMsg { shares, sender, .. }) = msg else {
            continue;
        };
        let shares = match shares {
            Some(shares) => shares,
            None => {
                // If the sender is not providing shares, they must be a new participant.
                // We ignore them, as they are not supposed to send shares.
                // TODO: verify that the sender is actually a new participant.
                continue;
            },
        };
        // The sender here must be an old participant, as the new participants are not supposed to send shares.
        let sender_addr = Address::try_from(sender).map_err(Bug::Serialization)?;
        if shares.len() != usize::from(n) {
            eprint!("expected {} shares, got {}", n, shares.len());
            return Err(KeyrefreshAborted::FewerThanNShares(n).into());
        }
        let result = shares_map.insert(sender_addr, shares);
        let j_u16 = u16::try_from(j).map_err(|_| Bug::InvalidNumberOfParticipants)?;
        match result {
            Ok(()) => {},
            // If the shares map is full, we could simply ignore the share
            Err(SharesError::SharesMapFull) => continue,
            Err(SharesError::SharesAlreadyProvided(_from)) => {
                return Err(KeyrefreshAborted::ShareAlreadyProvided(j_u16).into())
            },
            Err(SharesError::InvalidShareVectorLength(_)) => return Err(KeyrefreshAborted::FewerThanNShares(n).into()),
            _ => unreachable!(),
        }
    }

    tracer.stage("Verify and Recover Keys");
    let self_address = keypair.address().map_err(Bug::Serialization)?;
    let result = shares_map.clone().recover_keys(&self_address, keypair.sk(), &participants_map);
    match result {
        Ok((gvk_poly, share_keypair)) => {
            let new_pkg = KeysharePackage { n, t, i, share_keypair, gvk_poly };
            let curr_gvk = pkg.global_verification_key();
            let new_gvk = new_pkg.global_verification_key();
            if curr_gvk != new_gvk {
                return Err(KeyrefreshAborted::GlobalVerificationKeyChanged.into());
            }
            tracer.protocol_ends();
            Ok(new_pkg)
        },
        Err(SharesError::InvalidShareVectorLength(_)) => Err(KeyrefreshAborted::FewerThanNShares(n).into()),
        Err(SharesError::InvalidShares(who)) => {
            let pk = participants_map.get(&who).ok_or(Bug::NotAParticipant)?;
            let idx = participants.iter().position(|p| p == pk).ok_or(Bug::NotAParticipant)?;
            let j = u16::try_from(idx).map_err(|_| Bug::InvalidNumberOfParticipants)?;
            Err(KeyrefreshAborted::InvalidShare(j).into())
        },
        Err(SharesError::OurIndexNotFound) => Err(Bug::NotAParticipant.into()),
        // unlikely to happen
        Err(SharesError::Interpolation(e)) => Err(Bug::Interpolation(e).into()),
        // unlikely to happen
        Err(SharesError::Cipher(e)) => Err(Bug::Cipher(e).into()),
        Err(SharesError::InvalidShareKeypair) => Err(Bug::InvalidLocalKeyshare.into()),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use proptest::prelude::*;
    use rand::{rngs::StdRng, seq::IteratorRandom, SeedableRng};
    use round_based::simulation::Simulation;
    use test_strategy::proptest;
    use test_strategy::Arbitrary;

    use crate::{
        addr::Address,
        rounds::{
            keygen::{run as keygen, Msg as KeygenMsg},
            sign::{run as sign, Msg as SigningMsg},
        },
        sig::Signature,
    };

    use super::*;

    #[derive(Arbitrary, Debug)]
    struct TestInput {
        #[strategy(2..12u16)]
        n: u16,
        #[strategy(1..#n)]
        t: u16,
        #[strategy(0..(#n - #t) as usize)]
        remove: usize,
        #[strategy(0..#t)]
        add: u16,
    }

    #[proptest(async = "tokio", cases = 15, fork = true)]
    async fn it_works(input: TestInput) {
        let n = input.n;
        let t = input.t;

        let keypairs = generate_keypairs(n);
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let keygen_results = run_keygen(t, &keypairs).await;
        assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();
        let msg = b"Hello, World!";
        let sig = run_singing(&keypairs, &keygen_results, msg).await;
        // Verify the signature.
        prop_assert!(sig.verify(msg, &pkg.global_verification_key()));

        // Do a keyshare with the same participants.
        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = Vec::with_capacity(usize::from(n));
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[i as usize].clone();
            let address = keypair.address().unwrap();
            let pkg = keygen_results[&address].clone();
            let participants = participants.clone();
            let task = tokio::spawn(async move {
                let mut rng = StdRng::seed_from_u64(0x000fff + u64::from(i + 1));
                let out = run(&mut rng, None, &keypair, &pkg, &participants, t, party).await;
                (i, out)
            });
            tasks.push(task);
        }

        let mut refresh_results = BTreeMap::new();
        for task in tasks {
            let (i, out) = task.await.unwrap();
            let address = keypairs[i as usize].address().unwrap();
            let pkg = keygen_results[&address].clone();
            let refresh_pkg = out.unwrap();
            prop_assert_eq!(
                refresh_pkg.global_verification_key(),
                pkg.global_verification_key(),
                "Party {}'s GVK changed",
                i
            );
            prop_assert_eq!(refresh_pkg.n, pkg.n, "Party {}'s n changed", i);
            prop_assert_eq!(refresh_pkg.t, pkg.t, "Party {}'s t changed", i);
            prop_assert_eq!(refresh_pkg.i, i, "Party {}'s i changed", i);
            prop_assert_eq!(refresh_pkg.gvk_poly.len(), pkg.gvk_poly.len(), "Party {}'s GVK poly changed", i);
            refresh_results.insert(address, refresh_pkg);
        }

        let msg = b"Hello, World!";
        let sig = run_singing(&keypairs, &refresh_results, msg).await;
        // Verify the signature.
        prop_assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[proptest(async = "tokio", cases = 15, fork = true)]
    async fn remove_party(input: TestInput) {
        let n = input.n;
        let t = input.t;

        let keypairs = generate_keypairs(n);
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let keygen_results = run_keygen(t, &keypairs).await;
        prop_assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();

        // Do a keyshare but remove some parties.
        let mut rng = StdRng::seed_from_u64(0xdead);
        let mut keypairs = keypairs.clone();
        let mut participants = participants.clone();
        let mut removed_parties = BTreeSet::new();
        while removed_parties.len() < input.remove {
            let n = participants.len();
            let idx_to_remove = (0..n).choose(&mut rng).unwrap();
            if !removed_parties.contains(&idx_to_remove) {
                participants.remove(idx_to_remove as usize);
                keypairs.remove(idx_to_remove as usize);
                removed_parties.insert(idx_to_remove);
                eprintln!("Removed party {idx_to_remove}");
            }
        }

        let n = participants.len() as u16;
        let t = n * 2 / 3;

        eprintln!("Running Keyrefresh with {t} out of {n} parties");
        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = Vec::with_capacity(usize::from(n));
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[i as usize].clone();
            let address = keypair.address().unwrap();
            let pkg = keygen_results[&address].clone();
            let participants = participants.clone();
            let task = tokio::spawn(async move {
                let mut rng = StdRng::seed_from_u64(0x000fff + u64::from(i + 1));
                let out = run(&mut rng, None, &keypair, &pkg, &participants, t, party).await;
                (i, out)
            });
            tasks.push(task);
        }

        let mut refresh_results = BTreeMap::new();
        for task in tasks {
            let (i, out) = task.await.unwrap();
            let address = keypairs[i as usize].address().unwrap();
            let pkg = keygen_results[&address].clone();
            let refresh_pkg = out.unwrap();
            prop_assert_eq!(
                refresh_pkg.global_verification_key(),
                pkg.global_verification_key(),
                "Party {}'s GVK changed",
                i
            );
            refresh_results.insert(address, refresh_pkg);
        }

        let msg = b"Hello, World!";
        let sig = run_singing(&keypairs, &refresh_results, msg).await;
        // Verify the signature.
        prop_assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[proptest(async = "tokio", cases = 15, fork = true)]
    async fn add_party(input: TestInput) {
        let n = input.n;
        let t = input.t;

        prop_assume!(t < n);
        prop_assume!(input.add > 0 && input.add < t);

        let keypairs = generate_keypairs(n);
        let keygen_results = run_keygen(t, &keypairs).await;
        prop_assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();
        let gvk = pkg.global_verification_key().clone();
        // Do a keyshare but add more parties.
        let new_keypairs = (0..input.add).map(|i| generate_keypair(n + i));
        let keypairs = keypairs.into_iter().chain(new_keypairs).collect::<Vec<_>>();
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let n = participants.len() as u16;
        let t = n * 2 / 3;

        prop_assume!(t < n);

        eprintln!("Running Keyrefresh with {t} out of {n} parties");
        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = Vec::with_capacity(usize::from(n));
        for i in 0..n {
            let party = simulation.add_party();
            let keypair = keypairs[i as usize].clone();
            let address = keypair.address().unwrap();
            let pkg = keygen_results
                .get(&address)
                .cloned()
                .unwrap_or_else(|| KeysharePackage::new_zero(t, n, i, gvk));
            let participants = participants.clone();
            let task = tokio::spawn(async move {
                let mut rng = StdRng::seed_from_u64(0x000fff + u64::from(i + 1));
                let out = run(&mut rng, None, &keypair, &pkg, &participants, t, party).await;
                (i, out)
            });
            tasks.push(task);
        }

        let mut refresh_results = BTreeMap::new();
        for task in tasks {
            let (i, out) = task.await.unwrap();
            let address = keypairs[i as usize].address().unwrap();
            let refresh_pkg = out.unwrap();
            refresh_results.insert(address, refresh_pkg);
        }

        let msg = b"Hello, World!";
        let sig = run_singing(&keypairs, &refresh_results, msg).await;
        // Verify the signature.
        prop_assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    fn generate_keypairs(n: u16) -> Vec<Keypair> {
        let mut keypairs = Vec::new();
        for i in 0..n {
            keypairs.push(generate_keypair(i));
        }
        keypairs.sort_unstable_by(|a, b| a.pk().cmp(&b.pk()));
        keypairs
    }

    fn generate_keypair(i: u16) -> Keypair {
        let rng = &mut StdRng::seed_from_u64(0xdead + u64::from(i + 1));
        Keypair::rand(rng)
    }

    async fn run_keygen(t: u16, keypairs: &[Keypair]) -> BTreeMap<Address, KeysharePackage> {
        let n = keypairs.len() as u16;
        eprintln!("Running {t}-out-of-{n} Keygen");
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        let mut simulation = Simulation::<KeygenMsg>::with_capacity(usize::from(n));
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
        let mut simulation = Simulation::<SigningMsg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let me = keypairs[usize::from(i)].clone();
            let address = me.address().unwrap();
            let pkg = pkgs.get(&address).cloned().unwrap();
            assert_eq!(pkg.i, i);
            let msg_to_be_signed = msg.to_vec();
            let all_participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
            let output = tokio::spawn(async move {
                let output = sign(None, &me, &pkg, &all_participants, &msg_to_be_signed, party).await;
                (me, output)
            });
            tasks.push(output);
        }

        let mut outputs = BTreeMap::new();
        for task in tasks {
            let (k, output) = task.await.unwrap();
            match output {
                Ok(sig) => outputs.insert(k.address().unwrap(), sig),
                Err(e) => {
                    eprintln!("{} => Error: {e}", k.pk());
                    continue;
                },
            };
        }

        outputs.values().next().unwrap().clone()
    }
}
