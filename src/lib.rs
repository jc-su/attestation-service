#![warn(clippy::all)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod error;
pub mod policy;
pub mod policy_action_store;
pub mod policy_sync;
pub mod quote;
pub mod quote_backend;
pub mod refstore;
pub mod service;
pub mod token;
pub mod verifier;

pub mod proto {
    tonic::include_proto!("attestation.v1");
}
