/// Represents the parameters of the t-of-n threshold scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    /// Number of parties
    pub n: u16,
    /// Threshold
    pub t: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// Number of parties is invalid
    InvalidNumberOfParties,
    /// Threshold is invalid
    InvalidThreshold,
    /// Threshold is greater than the number of parties
    ThresholdGreaterThanParties,
}

impl Parameters {
    /// Create a new set of parameters
    pub fn new(n: u16, t: u16) -> Self {
        debug_assert!(n > 0, "Number of parties must be greater than 0");
        debug_assert!(t > 0, "Threshold must be greater than 0");
        debug_assert!(t <= n, "Threshold must be less than or equal to the number of parties");
        Self { n, t }
    }

    /// Validate the parameters
    pub fn validate(&self) -> Result<(), Error> {
        if self.n == 0 {
            return Err(Error::InvalidNumberOfParties);
        }
        if self.t == 0 {
            return Err(Error::InvalidThreshold);
        }
        if self.t > self.n {
            return Err(Error::ThresholdGreaterThanParties);
        }
        Ok(())
    }
}
