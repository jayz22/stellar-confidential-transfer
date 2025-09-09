#![cfg_attr(not(feature = "demo"), no_std)]

pub mod contract;
mod test;
#[cfg(any(test, feature = "testutils"))]
pub mod testutil;
pub mod utils;

#[cfg(feature = "demo")]
pub mod demo;

pub use crate::contract::ConfidentialTokenClient;
