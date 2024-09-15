//! Simple implementation of `MessagesStore`

use ark_std::{vec, vec::Vec};
use core::iter;

use round_based::{Incoming, MessageType, MsgId, PartyIndex};

use round_based::rounds_router::MessagesStore;

/// Simple implementation of [MessagesStore] that waits for all parties to send a message
///
/// Round is considered complete when the store received a message from every party. Note that the
/// store will ignore all the messages such as `msg.sender == local_party_index`.
///
/// Once round is complete, it outputs [`RoundMsgs`].
///
/// this store has a similar API to the [`round_based::rounds_router::simple_store::RoundInput`] implementation.
#[derive(Debug, Clone)]
pub struct ThresholdRoundInput<M> {
    i: PartyIndex,
    n: u16,
    messages_ids: Vec<MsgId>,
    messages: Vec<Option<M>>,
    left_messages: u16,
    expected_msg_type: MessageType,
}

/// List of received messages
#[derive(Debug, Clone)]
pub struct RoundMsgs<M> {
    i: PartyIndex,
    ids: Vec<MsgId>,
    messages: Vec<Option<M>>,
}

impl<M> ThresholdRoundInput<M> {
    /// Constructs new messages store
    ///
    /// Takes index of local party `i` and amount of parties `n`
    ///
    /// ## Panics
    /// Panics if `n` is less than 2 or `i` is not in the range `[0; n)`.
    pub fn new(i: PartyIndex, t: u16, n: u16, msg_type: MessageType) -> Self {
        assert!(n >= 2);
        assert!(i < n);
        assert!(t <= n);

        Self {
            i,
            n,
            messages_ids: vec![0; usize::from(n) - 1],
            messages: iter::repeat_with(|| None).take(usize::from(n) - 1).collect(),
            left_messages: t - 1,
            expected_msg_type: msg_type,
        }
    }

    /// Construct a new store for broadcast messages
    ///
    /// The same as `RoundInput::new(i, t, n, MessageType::Broadcast)`
    pub fn broadcast(i: PartyIndex, t: u16, n: u16) -> Self {
        Self::new(i, t, n, MessageType::Broadcast)
    }

    /// Construct a new store for p2p messages
    ///
    /// The same as `RoundInput::new(i, t, n, MessageType::P2P)`
    pub fn p2p(i: PartyIndex, t: u16, n: u16) -> Self {
        Self::new(i, t, n, MessageType::P2P)
    }

    fn is_expected_type_of_msg(&self, msg_type: MessageType) -> bool {
        self.expected_msg_type == msg_type
    }
}

impl<M> MessagesStore for ThresholdRoundInput<M>
where
    M: 'static,
{
    type Msg = M;
    type Output = RoundMsgs<M>;
    type Error = RoundInputError;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if !self.is_expected_type_of_msg(msg.msg_type) {
            return Err(RoundInputError::MismatchedMessageType {
                msg_id: msg.id,
                expected: self.expected_msg_type,
                actual: msg.msg_type,
            });
        }
        if msg.sender == self.i {
            // Ignore own messages
            return Ok(());
        }

        let index = usize::from(if msg.sender < self.i { msg.sender } else { msg.sender - 1 });

        match self.messages.get_mut(index) {
            Some(vacant @ None) => {
                *vacant = Some(msg.msg);
                self.messages_ids[index] = msg.id;
                self.left_messages = self.left_messages.saturating_sub(1);
                Ok(())
            },
            Some(Some(_)) => Err(RoundInputError::AttemptToOverwriteReceivedMsg {
                msgs_ids: [self.messages_ids[index], msg.id],
                sender: msg.sender,
            }),
            None => Err(RoundInputError::SenderIndexOutOfRange { msg_id: msg.id, sender: msg.sender, n: self.n }),
        }
    }

    fn wants_more(&self) -> bool {
        self.left_messages > 0
    }

    fn output(self) -> Result<Self::Output, Self> {
        if self.left_messages > 0 {
            Err(self)
        } else {
            Ok(RoundMsgs { i: self.i, ids: self.messages_ids, messages: self.messages })
        }
    }
}

impl<M> RoundMsgs<M> {
    /// Returns vec of `n-1` received messages
    ///
    /// Messages appear in the list in ascending order of sender index. E.g. for n=4 and local party index i=2,
    /// the list would look like: `[{msg from i=0}, {msg from i=1}, {msg from i=3}]`.
    pub fn into_vec_without_me(self) -> Vec<Option<M>> {
        self.messages
    }

    /// Returns vec of received messages plus party's own message
    ///
    /// Similar to `into_vec_without_me`, but inserts `my_msg` at position `i` in resulting list. Thus, i-th
    /// message in the list was received from i-th party.
    pub fn into_vec_including_me(mut self, my_msg: M) -> Vec<Option<M>> {
        self.messages.insert(usize::from(self.i), Some(my_msg));
        self.messages
    }

    /// Returns iterator over messages
    pub fn iter(&self) -> impl Iterator<Item = &Option<M>> {
        self.messages.iter()
    }

    pub fn i(&self) -> PartyIndex {
        self.i
    }

    pub fn ids(&self) -> &[MsgId] {
        &self.ids
    }
}

/// Error explaining why `RoundInput` wasn't able to process a message
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum RoundInputError {
    /// Party sent two messages in one round
    ///
    /// `msgs_ids` are ids of conflicting messages
    #[displaydoc("party {sender} tried to overwrite message")]
    AttemptToOverwriteReceivedMsg {
        /// IDs of conflicting messages
        msgs_ids: [MsgId; 2],
        /// Index of party who sent two messages in one round
        sender: PartyIndex,
    },
    /// Unknown sender
    ///
    /// This error is thrown when index of sender is not in `[0; n)` where `n` is number of
    /// parties involved in the protocol (provided in [`RoundInput::new`])
    #[displaydoc("sender index is out of range: sender={sender}, n={n}")]
    SenderIndexOutOfRange {
        /// Message ID
        msg_id: MsgId,
        /// Sender index
        sender: PartyIndex,
        /// Number of parties
        n: u16,
    },
    /// Received message type doesn't match expectations
    ///
    /// For instance, this error is returned when it's expected to receive broadcast message,
    /// but party sent p2p message instead (which is rough protocol violation).
    #[displaydoc("expected message {expected:?}, got {actual:?}")]
    MismatchedMessageType {
        /// Message ID
        msg_id: MsgId,
        /// Expected type of message
        expected: MessageType,
        /// Actual type of message
        actual: MessageType,
    },
}

#[cfg(test)]
mod tests {
    use ark_std::vec::Vec;

    use round_based::rounds_router::MessagesStore;
    use round_based::{Incoming, MessageType};

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    pub struct Msg(u16);

    macro_rules! assert_matches {
        ($left: expr, $right:pat $(if $guard:expr)? $(,)?) => {
            #[allow(unused)]
            {
                assert!(matches!($left, $right));
            }
        };
    }

    #[test]
    fn store_outputs_received_messages() {
        let mut store = ThresholdRoundInput::<Msg>::new(3, 5, 5, MessageType::P2P);

        let msgs = (0..5)
            .map(|s| Incoming { id: s.into(), sender: s, msg_type: MessageType::P2P, msg: Msg(10 + s) })
            .filter(|incoming| incoming.sender != 3)
            .collect::<Vec<_>>();

        for msg in &msgs {
            assert!(store.wants_more());
            store.add_message(msg.clone()).unwrap();
        }

        assert!(!store.wants_more());
        let received = store.output().unwrap();

        // without me
        let msgs: Vec<_> = msgs.into_iter().map(|msg| Some(msg.msg)).collect();
        assert_eq!(received.clone().into_vec_without_me(), msgs);
    }

    #[test]
    fn store_returns_error_if_sender_index_is_out_of_range() {
        let mut store = ThresholdRoundInput::new(3, 5, 5, MessageType::P2P);
        let error = store
            .add_message(Incoming { id: 0, sender: 5, msg_type: MessageType::P2P, msg: Msg(123) })
            .unwrap_err();
        assert_matches!(
            error,
            RoundInputError::SenderIndexOutOfRange { msg_id, sender, n } if msg_id == 0 && sender == 5 && n == 5
        );
    }

    #[test]
    fn store_returns_error_if_incoming_msg_overwrites_already_received_one() {
        let mut store = ThresholdRoundInput::new(0, 3, 3, MessageType::P2P);
        store
            .add_message(Incoming { id: 0, sender: 1, msg_type: MessageType::P2P, msg: Msg(11) })
            .unwrap();
        let error = store
            .add_message(Incoming { id: 1, sender: 1, msg_type: MessageType::P2P, msg: Msg(112) })
            .unwrap_err();
        assert_matches!(error, RoundInputError::AttemptToOverwriteReceivedMsg { msgs_ids, sender } if msgs_ids[0] == 0 && msgs_ids[1] == 1 && sender == 1);
        store
            .add_message(Incoming { id: 2, sender: 2, msg_type: MessageType::P2P, msg: Msg(22) })
            .unwrap();

        let output = store.output().unwrap().into_vec_without_me();
        assert_eq!(output, [Some(Msg(11)), Some(Msg(22))]);
    }

    #[test]
    fn store_returns_error_if_tried_to_output_before_receiving_enough_messages() {
        let mut store = ThresholdRoundInput::<Msg>::new(3, 5, 5, MessageType::P2P);

        let msgs = (0..5)
            .map(|s| Incoming { id: s.into(), sender: s, msg_type: MessageType::P2P, msg: Msg(10 + s) })
            .filter(|incoming| incoming.sender != 3);

        for msg in msgs {
            assert!(store.wants_more());
            store = store.output().unwrap_err();

            store.add_message(msg).unwrap();
        }

        let _ = store.output().unwrap();
    }

    #[test]
    fn store_returns_error_if_message_type_mismatched() {
        let mut store = ThresholdRoundInput::<Msg>::p2p(3, 5, 5);
        let err = store
            .add_message(Incoming { id: 0, sender: 0, msg_type: MessageType::Broadcast, msg: Msg(1) })
            .unwrap_err();
        assert_matches!(
            err,
            RoundInputError::MismatchedMessageType {
                msg_id: 0,
                expected: MessageType::P2P,
                actual: MessageType::Broadcast
            }
        );

        let mut store = ThresholdRoundInput::<Msg>::broadcast(3, 5, 5);
        let err = store
            .add_message(Incoming { id: 0, sender: 0, msg_type: MessageType::P2P, msg: Msg(1) })
            .unwrap_err();
        assert_matches!(
            err,
            RoundInputError::MismatchedMessageType {
                msg_id: 0,
                expected: MessageType::Broadcast,
                actual: MessageType::P2P,
            }
        );
        for sender in 0u16..5 {
            store
                .add_message(Incoming { id: 0, sender, msg_type: MessageType::Broadcast, msg: Msg(1) })
                .unwrap();
        }

        let mut store = ThresholdRoundInput::<Msg>::broadcast(3, 5, 5);
        let err = store
            .add_message(Incoming { id: 0, sender: 0, msg_type: MessageType::P2P, msg: Msg(1) })
            .unwrap_err();
        assert_matches!(
            err,
            RoundInputError::MismatchedMessageType {
                msg_id: 0,
                expected: MessageType::Broadcast,
                actual,
            } if actual == MessageType::P2P
        );
        store
            .add_message(Incoming { id: 0, sender: 0, msg_type: MessageType::Broadcast, msg: Msg(1) })
            .unwrap();
    }
}
