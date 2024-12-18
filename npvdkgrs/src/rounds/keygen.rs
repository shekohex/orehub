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
    PublishShares(PublicSharesMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicSharesMsg {
    /// Shares to other parties
    pub shares: Vec<PublicShare>,
    /// Sender's public key
    pub sender: PublicKey,
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
    /// Protocol was maliciously aborted by another party: {0}
    Aborted(#[cfg_attr(feature = "std", source)] KeygenAborted),
    /// IO error: {0}
    IoError(#[cfg_attr(feature = "std", source)] super::IoError),
    /// Bug occurred: {0}
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
    mut tracer: Option<&mut dyn Tracer>,
    keypair: &Keypair,
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
    let round1 = rounds.add_round(ThresholdRoundInput::<PublicSharesMsg>::broadcast(i, n, n));
    let mut rounds = rounds.listen(incomings);
    // Round 1
    tracer.round_begins();
    let participants_map = participants
        .iter()
        .map(|p| Result::<_, SerializationError>::Ok((Address::try_from(p)?, *p)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(Bug::Serialization)?;
    tracer.stage("Generate Own shares");
    let old_secret = None;
    let mut private_poly = crate::party::random_polynomial(rng, t, old_secret);

    let shares = crate::party::generate_shares(rng, &participants_map, &private_poly).map_err(Bug::Share)?;
    runtime.yield_now().await;
    // Zeroize the polynomial
    private_poly.coeffs.zeroize();

    let msg = PublicSharesMsg { shares, sender: keypair.pk() };
    tracer.stage("Broadcast shares");
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

    let mut shares_map = SharesMap::new(participants.len());
    for (j, msg) in msgs.into_iter().enumerate() {
        let Some(PublicSharesMsg { shares, sender, .. }) = msg else {
            // TODO: blame missing shares
            continue;
        };
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

    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use round_based::{simulation::Simulation, Incoming, MessageDestination, MessageType};
    use test_strategy::proptest;
    use test_strategy::Arbitrary;

    use super::*;

    #[test]
    fn without_round_based() {
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

    #[test]
    fn state_machine() {
        use round_based::state_machine::*;
        let n = 2;
        let t = 1;
        let keypairs = generate_keypairs(n);
        let mut participants = keypairs.iter().map(|k| k.pk()).collect::<Vec<_>>();
        participants.sort_unstable();

        let mut party0 = wrap_protocol(|party| async {
            let mut rng = StdRng::seed_from_u64(0xdec0de + 1);
            run(&mut rng, None, &keypairs[0], &participants, t, party).await
        });

        let mut party1 = wrap_protocol(|party| async {
            let mut rng = StdRng::seed_from_u64(0xdec0de + 2);
            run(&mut rng, None, &keypairs[1], &participants, t, party).await
        });

        let ProceedResult::Yielded = party0.proceed() else {
            panic!("Expected Yielded");
        };

        let ProceedResult::Yielded = party1.proceed() else {
            panic!("Expected Yielded");
        };

        let ProceedResult::SendMsg(Outgoing {
            msg: Msg::PublishShares(party0_shares),
            recipient: MessageDestination::AllParties,
        }) = party0.proceed()
        else {
            panic!("Expected PublishShares");
        };

        // we now expects to receive the shares
        let ProceedResult::NeedsOneMoreMessage = party0.proceed() else {
            panic!("Expected NeedsOneMoreMessage");
        };

        let ProceedResult::SendMsg(Outgoing {
            msg: Msg::PublishShares(party1_shares),
            recipient: MessageDestination::AllParties,
        }) = party1.proceed()
        else {
            panic!("Expected PublishShares");
        };

        // we now expects to receive the shares
        let ProceedResult::NeedsOneMoreMessage = party1.proceed() else {
            panic!("Expected NeedsOneMoreMessage");
        };
        // Deliver the shares
        party0
            .received_msg(Incoming {
                id: 0,
                sender: 1,
                msg_type: MessageType::Broadcast,
                msg: Msg::PublishShares(party1_shares),
            })
            .unwrap();
        party1
            .received_msg(Incoming {
                id: 0,
                sender: 0,
                msg_type: MessageType::Broadcast,
                msg: Msg::PublishShares(party0_shares),
            })
            .unwrap();

        // each party should now have all shares and complete the protocol
        let ProceedResult::Output(Ok(party0_pkg)) = party0.proceed() else {
            panic!("Expected Output");
        };
        let ProceedResult::Output(Ok(party1_pkg)) = party1.proceed() else {
            panic!("Expected Output");
        };

        assert_eq!(party0_pkg.global_verification_key(), party1_pkg.global_verification_key());
    }

    #[derive(Arbitrary, Debug)]
    struct TestInput {
        #[strategy(2..12u16)]
        n: u16,
        #[strategy(1..#n)]
        t: u16,
    }

    #[proptest(async = "tokio", cases = 20, fork = true)]
    async fn it_works(input: TestInput) {
        let n = input.n;
        let t = input.t;
        prop_assume!(t < n);
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
            prop_assert_eq!(expected, actual, "Party {} failed, expected 0x{} but got 0x{}", i, expected, actual);
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
