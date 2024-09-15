use ark_serialize::SerializationError;
use ark_std::vec::Vec;
use round_based::{rounds_router::RoundsRouter, Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage, SinkExt};
use serde::{Deserialize, Serialize};

use crate::{addr::Address, keys::PublicKey, party::KeysharePackage, sig::Signature, trace::Tracer};

use super::{store::ThresholdRoundInput, IoError};

/// Protocol message
#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    /// Round 1
    PublishPartialSignature(PartialSignatureMsg),
}

/// A Partial Signature Message
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartialSignatureMsg {
    /// A Partial Signature signed by the party
    pub signature: Signature,
}

/// Signing protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("signing protocol is failed to complete")]
pub struct Error(#[cfg_attr(feature = "std", source)] Reason);

/// signing protocol abort reason
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Reason {
    /// Protocol was maliciously aborted by another party
    Aborted(#[cfg_attr(feature = "std", source)] SigningAborted),
    /// IO error
    IoError(#[cfg_attr(feature = "std", source)] super::IoError),
    /// Bug occurred
    Bug(Bug),
}

super::impl_from! {
    impl From for Error {
        err: SigningAborted => Error(Reason::Aborted(err)),
        err: super::IoError => Error(Reason::IoError(err)),
        err: Bug => Error(Reason::Bug(err)),
    }
}

impl From<SigningAborted> for Reason {
    fn from(err: SigningAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SigningAborted {
    /// Not enough shares were collected, expected {0} at least.
    NotEnoughShares(u16),
    /// Invalid Global Signature after aggregation
    InvalidGlobalSignature,
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Bug {
    /// Invalid number of participants, does not fit in a `u16`
    InvalidNumberOfParticipants,
    /// Participant at index {0} is out of bounds for the list of participants.
    ParticipantIndexOutOfBounds(usize),
    /// Serialization error: {0}
    Serialization(#[cfg_attr(feature = "std", source)] SerializationError),
    /// Error during Signing the shares: {0}
    Signing(#[cfg_attr(feature = "std", source)] crate::keys::Error),
    /// Error during Lagrange interpolation: {0}
    Interpolation(#[cfg_attr(feature = "std", source)] crate::poly::InterpolationError),
}

pub async fn run<M>(
    mut tracer: Option<&mut dyn Tracer>,
    pkg: &KeysharePackage,
    all_participants: &[PublicKey],
    msg_to_be_signed: &[u8],
    party: M,
) -> Result<Signature, Error>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    tracer.protocol_begins();
    let t = pkg.t;
    let n = pkg.n;
    let i = pkg.i;

    if all_participants.len() != n as usize {
        return Err(Bug::InvalidNumberOfParticipants.into());
    }

    tracer.stage("Setup networking");

    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg>::builder();
    let round1 = rounds.add_round(ThresholdRoundInput::<PartialSignatureMsg>::broadcast(i, t, n));
    let mut rounds = rounds.listen(incomings);
    // Round 1
    tracer.round_begins();
    tracer.stage("Generate Own Signature");
    let signature = pkg.partial_sign(msg_to_be_signed).map_err(Bug::Signing)?;
    tracer.stage("Broadcast Partial Signature");
    tracer.send_msg();
    let msg = PartialSignatureMsg { signature };
    outgoings
        .send(Outgoing::broadcast(Msg::PublishPartialSignature(msg.clone())))
        .await
        .map_err(|e| IoError::send_message(e))?;

    tracer.msg_sent();

    tracer.receive_msgs();
    let other_partial_signatures = rounds.complete(round1).await.map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Collect Partial Signatures");
    let msgs = other_partial_signatures.into_vec_including_me(msg);
    // Expects at least t+1 shares to be collected
    if msgs.len() < usize::from(t + 1) {
        return Err(SigningAborted::NotEnoughShares(t + 1).into());
    }

    let mut sig_points = Vec::with_capacity(msgs.len());
    let mut addrs_scalars = Vec::with_capacity(msgs.len());

    for (j, msg) in msgs.into_iter().enumerate() {
        let Some(PartialSignatureMsg { signature }) = msg else {
            // absent participant
            continue;
        };
        let sender = all_participants.get(j).ok_or(Bug::ParticipantIndexOutOfBounds(j))?;
        let sender_addr = Address::try_from(sender).map_err(Bug::Serialization)?;
        addrs_scalars.push(sender_addr.as_scalar());
        sig_points.push(signature.into_projective());
        // TODO: check if the signature is valid?
    }

    tracer.stage("Combine Partial Signatures");
    let global_sig_poly = crate::poly::interpolate(&addrs_scalars, &sig_points).map_err(Bug::Interpolation)?;
    let global_sig = Signature::from(global_sig_poly[0]);
    tracer.stage("Verify Combined Signature");
    let valid = global_sig.verify(msg_to_be_signed, &pkg.gvk);
    if !valid {
        return Err(SigningAborted::InvalidGlobalSignature.into());
    }
    tracer.protocol_ends();
    Ok(global_sig)
}

#[cfg(test)]
mod tests {
    use core::borrow::BorrowMut;

    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use round_based::simulation::Simulation;

    use crate::keys::Keypair;
    use crate::rounds::keygen::{run as keygen, Msg as KeygenMsg};

    use super::*;

    #[tokio::test]
    async fn signing_works() {
        let n = 5;
        let t = n * 2 / 3;
        eprintln!("Running {t}-out-of-{n} Keygen");
        let keypairs = generate_keypairs(n);
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
                let mut tracer = crate::trace::PerfProfiler::new();
                let output = keygen(rng, Some(tracer.borrow_mut()), &keypair, &participants, t, party)
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

            let expected = pkg.gvk;
            let actual = pkg2.gvk;
            assert_eq!(expected, actual, "Party {i} failed, expected 0x{expected} but got 0x{actual}",);
        }

        eprintln!("Group PublicKey: {}", pkg.gvk);

        eprintln!("Running {t}-out-of-{n} Signing");
        // Now we can test the signing
        let msg = b"Hello, World!";
        let mut simulation = Simulation::<Msg>::with_capacity(usize::from(n));
        let mut tasks = vec![];
        let mut sig_outputs = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let pkg = outputs[usize::from(i)].clone();
            let participants = participants.clone();
            let output = tokio::spawn(async move {
                let mut tracer = crate::trace::PerfProfiler::new();
                let output = run(Some(tracer.borrow_mut()), &pkg, &participants, msg, party).await.unwrap();
                let report = tracer.get_report().unwrap();
                eprintln!("Party {} report: {}\n", i, report);
                output
            });
            tasks.push(output);
        }

        // Wait for the first t parties to finish
        for task in tasks {
            sig_outputs.push(task.await.unwrap());
        }

        // Verify the signature
        for sig in sig_outputs.iter() {
            let valid = sig.verify(msg, &pkg.gvk);
            assert!(valid, "Signature is invalid");
        }
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
