//! An SMTP library for [Tokio](https://tokio.rs/).
//!
//! Currently, just the client is implemented. Documentation can be found in
//! [the client module](client/).

// FIXME: Add server protocol

extern crate emailaddress;
extern crate futures;
extern crate native_tls;
#[macro_use]
extern crate nom;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_tls;

pub mod client;
pub mod request;
pub mod response;
mod util;
