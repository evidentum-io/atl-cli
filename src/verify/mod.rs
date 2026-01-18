//! Verification logic

pub mod batch;
pub mod consistency;
pub mod file;
pub mod single;

#[cfg(feature = "online")]
pub mod online;
