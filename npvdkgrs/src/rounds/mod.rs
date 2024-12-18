use core::convert::Infallible;

use ark_std::boxed::Box;

use round_based::rounds_router::{errors as router_error, CompleteRoundError};

/// Non-interactive publicly verifiable distributed key generation protocol.
pub mod keygen;
/// Non-interactive publicly verifiable Distributed Key Refresh protocol.
pub mod refresh;
/// Non-interactive publicly verifiable Threshold Signature protocol.
pub mod sign;

/// Custom Store Implementations for Round Based Protocols.
pub mod store;

mod std_error {
    #[cfg(feature = "std")]
    pub use std::error::Error as StdError;

    #[cfg(not(feature = "std"))]
    pub trait StdError: core::fmt::Display + core::fmt::Debug {}
    #[cfg(not(feature = "std"))]
    impl<E: core::fmt::Display + core::fmt::Debug> StdError for E {}
}
pub use std_error::StdError;
pub type BoxedError = Box<dyn StdError + Send + Sync>;

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum IoError {
    /// send message: {0}
    SendMessage(#[cfg_attr(feature = "std", source)] BoxedError),
    /// receive message: {0}
    ReceiveMessage(#[cfg_attr(feature = "std", source)] BoxedError),
    /// got eof while recieving messages
    ReceiveMessageEof,
    /// route received message (possibly malicious behavior): {0}
    RouteReceivedError(
        #[cfg_attr(feature = "std", source)] router_error::CompleteRoundError<store::RoundInputError, Infallible>,
    ),
}

impl IoError {
    pub fn send_message<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self::SendMessage(Box::new(err))
    }

    pub fn receive_message<E: StdError + Send + Sync + 'static>(
        err: CompleteRoundError<store::RoundInputError, E>,
    ) -> Self {
        match err {
            CompleteRoundError::Io(router_error::IoError::Io(e)) => Self::ReceiveMessage(Box::new(e)),
            CompleteRoundError::Io(router_error::IoError::UnexpectedEof) => Self::ReceiveMessageEof,

            CompleteRoundError::ProcessMessage(e) => Self::RouteReceivedError(CompleteRoundError::ProcessMessage(e)),
            CompleteRoundError::Other(e) => Self::RouteReceivedError(CompleteRoundError::Other(e)),
        }
    }
}

macro_rules! impl_from {
    (impl From for $target:ty {
        $($var:ident: $ty:ty => $new:expr),+,
    }) => {$(
        impl From<$ty> for $target {
            fn from($var: $ty) -> Self {
                $new
            }
        }
    )+}
}

pub(crate) use impl_from;
