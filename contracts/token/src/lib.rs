#![cfg_attr(not(feature = "demo"), no_std)]

mod contract;
mod test;
mod utils;

#[cfg(feature = "demo")]
pub mod demo;

pub use crate::contract::ConfidentialTokenClient;
