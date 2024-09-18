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
    PublishShares(MaybePublicSharesMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MaybePublicSharesMsg {
    /// Has Shares to share with other parties
    HasShares(Vec<PublicShare>),
    /// I'm a new participant and I do not has any shares.
    NewParticipant,
}

/// Keygen protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("keygen protocol is failed to complete")]
pub struct Error(#[cfg_attr(feature = "std", source)] Reason);

/// Keygen protocol abort reason
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Reason {
    /// Protocol was maliciously aborted by another party
    Aborted(#[cfg_attr(feature = "std", source)] KeygenAborted),
    /// IO error
    IoError(#[cfg_attr(feature = "std", source)] super::IoError),
    /// Bug occurred
    Bug(Bug),
}

super::impl_from! {
    impl From for Error {
        err: KeygenAborted => Error(Reason::Aborted(err)),
        err: super::IoError => Error(Reason::IoError(err)),
        err: Bug => Error(Reason::Bug(err)),
    }
}

impl From<KeygenAborted> for Reason {
    fn from(err: KeygenAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KeygenAborted {
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
    /// Global Public Key has been changed after doing the refresh.
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

/// Run Non Interactive Keygen Protocol
pub async fn run<R, M>(
    rng: &mut R,
    tracer: Option<&mut dyn Tracer>,
    keypair: &Keypair,
    participants: &[PublicKey],
    t: u16,
    party: M,
) -> Result<KeysharePackage, Error>
where
    R: rand::RngCore + rand::CryptoRng,
    M: Mpc<ProtocolMessage = Msg>,
{
    _run(rng, tracer, keypair, None, participants, t, party).await
}

/// Run Non Interactive Keygen Protocol with old package (aka refresh)
pub(crate) async fn run_with_old_package<R, M>(
    rng: &mut R,
    tracer: Option<&mut dyn Tracer>,
    keypair: &Keypair,
    old_package: &KeysharePackage,
    participants: &[PublicKey],
    t: u16,
    party: M,
) -> Result<KeysharePackage, Error>
where
    R: rand::RngCore + rand::CryptoRng,
    M: Mpc<ProtocolMessage = Msg>,
{
    _run(rng, tracer, keypair, Some(old_package), participants, t, party).await
}

async fn _run<R, M>(
    rng: &mut R,
    mut tracer: Option<&mut dyn Tracer>,
    keypair: &Keypair,
    old_package: Option<&KeysharePackage>,
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
    let round1 = rounds.add_round(ThresholdRoundInput::<MaybePublicSharesMsg>::broadcast(i, n, n));
    let mut rounds = rounds.listen(incomings);
    // Round 1
    tracer.round_begins();
    let participants_map = participants
        .iter()
        .map(|p| Result::<_, SerializationError>::Ok((Address::try_from(p)?, *p)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(Bug::Serialization)?;
    // We do not need to generate our own shares if we are refreshing and we are a new participant.
    let is_new_participant = old_package.map(|pkg| pkg.is_zero()).unwrap_or(false);
    let msg = if is_new_participant {
        MaybePublicSharesMsg::NewParticipant
    } else {
        tracer.stage("Generate Own shares");
        let old_secret = old_package.map(|pkg| pkg.share_keypair.sk().expose_secret());
        let mut private_poly = crate::party::random_polynomial(rng, t, old_secret);

        let shares = crate::party::generate_shares(rng, &participants_map, &private_poly).map_err(Bug::Share)?;
        runtime.yield_now().await;
        // Zeroize the polynomial
        private_poly.coeffs.zeroize();
        MaybePublicSharesMsg::HasShares(shares)
    };

    if old_package.is_some() && !is_new_participant {
        tracer.stage("Broadcast new shares");
    } else if is_new_participant {
        tracer.stage("Broadcast No shares");
    } else {
        tracer.stage("Broadcast shares");
    }
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::PublishShares(msg.clone())))
        .await
        .map_err(|e| IoError::send_message(e))?;

    tracer.msg_sent();

    tracer.receive_msgs();
    let other_shares = rounds.complete(round1).await.map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Collect shares");
    let msgs = other_shares.into_vec_including_me(msg);
    // Expects at least t+1 shares to be collected
    if msgs.len() < usize::from(t + 1) {
        return Err(KeygenAborted::NotEnoughShares(t + 1).into());
    }

    let mut shares_map = SharesMap::new(participants.len());
    for (j, msg) in msgs.into_iter().enumerate() {
        let Some(MaybePublicSharesMsg::HasShares(shares)) = msg else {
            continue;
        };
        let sender = participants.get(j).ok_or(Bug::ParticipantIndexOutOfBounds(j))?;
        let sender_addr = Address::try_from(sender).map_err(Bug::Serialization)?;
        if shares.len() != participants.len() {
            return Err(KeygenAborted::FewerThanNShares(n).into());
        }
        let result = shares_map.insert(sender_addr, shares);
        let j_u16 = u16::try_from(j).map_err(|_| Bug::InvalidNumberOfParticipants)?;
        match result {
            Ok(()) => {},
            // If the shares map is full, we could simply ignore the share
            Err(SharesError::SharesMapFull) => continue,
            Err(SharesError::SharesAlreadyProvided(_from)) => {
                return Err(KeygenAborted::ShareAlreadyProvided(j_u16).into())
            },
            Err(SharesError::InvalidShareVectorLength(_)) => return Err(KeygenAborted::FewerThanNShares(n).into()),
            _ => unreachable!(),
        }
    }

    tracer.stage("Verify and Recover Keys");
    let self_address = keypair.address().map_err(Bug::Serialization)?;
    let result = shares_map.clone().recover_keys(&self_address, keypair.sk(), &participants_map);
    match result {
        Ok((gvk_poly, share_keypair)) => {
            let pkg = KeysharePackage { n, t, i, share_keypair, gvk_poly };
            if let Some(old_pkg) = old_package {
                let old_gvk = old_pkg.global_verification_key();
                let new_gvk = pkg.global_verification_key();
                if old_gvk != new_gvk {
                    return Err(KeygenAborted::GlobalVerificationKeyChanged.into());
                }
            }
            tracer.protocol_ends();
            Ok(pkg)
        },
        Err(SharesError::InvalidShareVectorLength(_)) => Err(KeygenAborted::FewerThanNShares(n).into()),
        Err(SharesError::InvalidShares(who)) => {
            let pk = participants_map.get(&who).ok_or(Bug::NotAParticipant)?;
            let idx = participants.iter().position(|p| p == pk).ok_or(Bug::NotAParticipant)?;
            let j = u16::try_from(idx).map_err(|_| Bug::InvalidNumberOfParticipants)?;
            Err(KeygenAborted::InvalidShare(j).into())
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
    use core::borrow::BorrowMut;

    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use round_based::simulation::Simulation;

    use super::*;

    #[test]
    fn keygen_without_round_based() {
        let n = 5;
        let t = n * 2 / 3;
        let keypairs = generate_keypairs(n);
        let participants: BTreeMap<_, _> = keypairs.iter().map(|k| (k.address().unwrap(), k.pk())).collect();

        struct Party {
            shares: SharesMap,
            keypair: Keypair,
            participants: BTreeMap<Address, PublicKey>,
        }

        let mut parties = vec![];
        for i in 0..n {
            let keypair = keypairs[usize::from(i)].clone();
            let participants = participants.clone();
            let party = Party { shares: SharesMap::new(n as usize), keypair, participants };
            parties.push(party);
        }

        // Generate shares
        for i in 0..n {
            let party = &mut parties[usize::from(i)];
            let rng = &mut StdRng::seed_from_u64(u64::from(i + 1));
            let private_poly = crate::party::random_polynomial(rng, t, None);
            let shares = crate::party::generate_shares(rng, &party.participants, &private_poly).unwrap();
            party.shares.insert(party.keypair.address().unwrap(), shares.clone()).unwrap();
        }

        // Broadcast shares
        // for each party, send shares to all other parties.
        // publish and collect shares
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let addr = parties[usize::from(j)].keypair.address().unwrap();
                    if let Some(share) = parties[usize::from(j)].shares.map().get(&addr) {
                        let share = share.clone();
                        parties[usize::from(i)].shares.insert(addr, share).unwrap();
                    }
                }
            }
        }
        // Everyone has all shares
        for party in parties.iter() {
            assert_eq!(party.shares.map().len(), n as usize);
        }

        // Verify and recover keys
        let pkgs = parties
            .iter()
            .map(|party| {
                party
                    .shares
                    .clone()
                    .recover_keys(&party.keypair.address().unwrap(), party.keypair.sk(), &party.participants)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        // Everyone has the same key
        for (gvk, _) in pkgs.iter() {
            assert_eq!(gvk, &pkgs[0].0);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keygen_works() {
        let n = 5;
        let t = n * 2 / 3;
        eprintln!("Running {t}-out-of-{n} Keygen");
        let keypairs = generate_keypairs(n);
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
                let mut tracer = crate::trace::PerfProfiler::new();
                let output = run(rng, Some(tracer.borrow_mut()), &keypair, &participants, t, party)
                    .await
                    .unwrap();
                let report = tracer.get_report().unwrap();
                eprintln!("Party {} report: {}\n", i, report);
                output
            });
            tasks.push(output);
        }

        let mut outputs = Vec::with_capacity(tasks.len());
        for task in tasks {
            outputs.push(task.await.unwrap());
        }

        // Assert that all parties outputed the same public key
        let pkg = &outputs[0];
        for i in 1..n {
            let pkg2 = &outputs[usize::from(i)];

            let expected = pkg.global_verification_key();
            let actual = pkg2.global_verification_key();
            assert_eq!(expected, actual, "Party {i} failed, expected 0x{expected} but got 0x{actual}",);
        }

        eprintln!("Group PublicKey: {}", pkg.global_verification_key());
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
}
