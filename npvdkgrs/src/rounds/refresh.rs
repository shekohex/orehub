use ark_serialize::{CanonicalSerialize, SerializationError};
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
    sig::Signature,
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
    /// Signature of us to prove that we are the owner of the shares.
    /// This is a signature of all of the above.
    /// sig = sign(shares, sender)
    pub signature: Signature,
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
        .and_then(|i| u16::try_from(i).map_err(|_| Bug::ParticipantIndexOutOfBounds(i)))?;

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

    let maybe_msg = if pkg.is_non_zero() {
        tracer.stage("Generate Own shares");
        let old_secret = Some(pkg.share_keypair.sk().expose_secret());
        let mut poly = crate::party::random_polynomial(rng, t, old_secret);

        let shares = crate::party::generate_shares(rng, &participants_map, &poly).map_err(Bug::Share)?;
        runtime.yield_now().await;
        // Zeroize the polynomial
        poly.coeffs.zeroize();

        tracer.stage("Sign shares");
        let mut msg_to_sign = Vec::new();
        keypair
            .pk()
            .serialize_compressed(&mut msg_to_sign)
            .map_err(Bug::Serialization)?;
        shares.serialize_compressed(&mut msg_to_sign).map_err(Bug::Serialization)?;
        let signature = keypair.sign(&msg_to_sign).map_err(Bug::Signing)?;
        let msg = ReshareMsg { shares: Some(shares), sender: keypair.pk(), signature };

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
        let mut msg_to_sign = Vec::new();
        keypair
            .pk()
            .serialize_compressed(&mut msg_to_sign)
            .map_err(Bug::Serialization)?;
        shares.serialize_compressed(&mut msg_to_sign).map_err(Bug::Serialization)?;
        let signature = keypair.sign(&msg_to_sign).map_err(Bug::Signing)?;
        let msg = ReshareMsg { shares, sender: keypair.pk(), signature };

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

    tracer.stage("Verify Shares Signatures");
    let signatures = other_shares
        .iter()
        .flat_map(|msg| msg.as_ref().map(|msg| msg.signature.into_projective()))
        .collect::<Vec<_>>();
    let public_keys = other_shares
        .iter()
        .flat_map(|msg| msg.as_ref().map(|msg| msg.sender.into_projective()))
        .collect::<Vec<_>>();
    let messages = other_shares
        .iter()
        .flat_map(|msg| {
            msg.as_ref().map(|msg| {
                let mut msg_to_sign = Vec::new();
                msg.sender.serialize_compressed(&mut msg_to_sign).unwrap();
                msg.shares.serialize_compressed(&mut msg_to_sign).unwrap();
                msg_to_sign
            })
        })
        .collect::<Vec<_>>();
    let is_valid = crate::sig::batch_verify(&signatures, &public_keys, &messages);
    if !is_valid {
        // TODO: do the heavy lifting of finding the invalid signature, and then blame them.
    }

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
                eprintln!("[#{i}] Global verification key changed. {curr_gvk} => {new_gvk}");
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

    use rand::{rngs::StdRng, seq::IteratorRandom, SeedableRng};
    use round_based::simulation::Simulation;

    use crate::{
        addr::Address,
        rounds::{
            keygen::{run as keygen, Msg as KeygenMsg},
            sign::{run as sign, Msg as SigningMsg},
        },
        sig::Signature,
    };

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn it_works() {
        let n = 5;
        let t = n * 2 / 3;

        let keypairs = generate_keypairs(n);
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let keygen_results = run_keygen(t, &keypairs).await;
        assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();
        let msg = b"Hello, World!";
        let sig = run_singing(&participants, &keygen_results, msg).await;
        // Verify the signature.
        assert!(sig.verify(msg, &pkg.global_verification_key()));

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
            assert_eq!(refresh_pkg.global_verification_key(), pkg.global_verification_key(), "Party {i}'s GVK changed");
            assert_eq!(refresh_pkg.n, pkg.n, "Party {i}'s n changed");
            assert_eq!(refresh_pkg.t, pkg.t, "Party {i}'s t changed");
            assert_eq!(refresh_pkg.i, i, "Party {i}'s i changed");
            assert_eq!(refresh_pkg.gvk_poly.len(), pkg.gvk_poly.len(), "Party {i}'s GVK poly changed");
            refresh_results.insert(address, refresh_pkg);
        }

        let msg = b"Hello, World!";
        let sig = run_singing(&participants, &refresh_results, msg).await;
        // Verify the signature.
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remove_party() {
        let n = 5;
        let t = n * 2 / 3;

        let keypairs = generate_keypairs(n);
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let keygen_results = run_keygen(t, &keypairs).await;
        assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();

        // Do a keyshare but remove one party.
        let mut rng = StdRng::seed_from_u64(0xc0de);
        let idx_to_remove = (0..n).choose(&mut rng).unwrap();
        let mut keypairs = keypairs.clone();
        let mut participants = participants.clone();
        participants.remove(idx_to_remove as usize);
        keypairs.remove(idx_to_remove as usize);
        eprintln!("Removed party {idx_to_remove}");

        let n = participants.len() as u16;
        eprintln!("Running Keyrefresh with {n} parties");
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
            assert_eq!(refresh_pkg.global_verification_key(), pkg.global_verification_key(), "Party {i}'s GVK changed");
            refresh_results.insert(address, refresh_pkg);
        }

        let msg = b"Hello, World!";
        let sig = run_singing(&participants, &refresh_results, msg).await;
        // Verify the signature.
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn with_just_t_parties() {
        let n = 5;
        let t = n * 2 / 3;

        let keypairs = generate_keypairs(n);
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let keygen_results = run_keygen(t, &keypairs).await;
        assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();

        // Do a keyshare but remove one party.
        let mut rng = StdRng::seed_from_u64(0xdead);
        let mut keypairs = keypairs.clone();
        let mut participants = participants.clone();
        let mut removed_parties = BTreeSet::new();
        // keep at least t parties in the participants list
        while removed_parties.len() < usize::from(n - t) {
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
        eprintln!("Running Keyrefresh with {t}-out-of-{n} parties");
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
            assert_eq!(refresh_pkg.global_verification_key(), pkg.global_verification_key(), "Party {i}'s GVK changed");
            refresh_results.insert(address, refresh_pkg);
        }

        let msg = b"Hello, World!";
        let sig = run_singing(&participants, &refresh_results, msg).await;
        // Verify the signature.
        assert!(sig.verify(msg, &pkg.global_verification_key()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_party() {
        let n = 5;
        let t = n * 2 / 3;

        let keypairs = generate_keypairs(n);
        let participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        let keygen_results = run_keygen(t, &keypairs).await;
        assert_eq!(keygen_results.len(), n as usize);
        let pkg = &keygen_results.values().next().cloned().unwrap();
        let gvk = pkg.global_verification_key().clone();

        // Do a keyshare but add one party.
        let keypair = generate_keypair(n + 1);
        let mut keypairs = keypairs.clone();
        let mut participants = participants.clone();
        keypairs.push(keypair.clone());
        participants.push(keypair.pk());
        let n = participants.len() as u16;

        eprintln!("Running Keyrefresh with {n} parties");
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
        let sig = run_singing(&participants, &refresh_results, msg).await;
        // Verify the signature.
        assert!(sig.verify(msg, &pkg.global_verification_key()));
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

    async fn run_singing(
        participants: &[PublicKey],
        pkgs: &BTreeMap<Address, KeysharePackage>,
        msg: &[u8],
    ) -> Signature {
        let n = participants.len() as u16;
        let t = pkgs.values().next().unwrap().t;
        eprintln!("Running {t}-out-of-{n} Signing");
        let mut simulation = Simulation::<SigningMsg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let me = participants[usize::from(i)];
            let address = Address::try_from(me).unwrap();
            let pkg = pkgs.get(&address).cloned().unwrap();
            assert_eq!(pkg.i, i);
            let msg_to_be_signed = msg.to_vec();
            let all_participants = participants.to_vec().clone();
            let output = tokio::spawn(async move {
                let output = sign(None, &pkg, &all_participants, &msg_to_be_signed, party).await;
                (me, output)
            });
            tasks.push(output);
        }

        let mut outputs = BTreeMap::new();
        for task in tasks {
            let (pk, output) = task.await.unwrap();
            match output {
                Ok(sig) => outputs.insert(Address::try_from(pk).unwrap(), sig),
                Err(e) => {
                    eprintln!("{pk} => Error: {e}");
                    continue;
                },
            };
        }

        outputs.values().next().unwrap().clone()
    }
}
