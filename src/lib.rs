//! An SMTP library for [Tokio].
//!
//! The toplevel module exports a basic interface to send mail, through the
//! `Mailer` type. This interface is hopefully sufficient for the common use
//! case where mail just needs to be delivered to a trusted local mail server
//! or remote mail service.
//!
//! A low-level client implementation on top of [tokio-proto] is available in
//! [the client module](client/). The server-side is not yet implemented.
//!
//!  [Tokio]: https://tokio.rs/
//!  [tokio-proto]: https://docs.rs/tokio-proto/
//!
//! # Example
//!
//! ```no_run
//! extern crate tokio_core;
//! extern crate tokio_smtp;
//!
//! use tokio_core::reactor::{Core};
//! use tokio_smtp::{Mailer};
//!
//! // In this example, we grab the mail body from a fixture.
//! const TEST_EML: &'static str = include_str!("fixtures/test.eml");
//!
//! fn main() {
//!     // Create the event loop that will drive this server.
//!     let mut core = Core::new().unwrap();
//!     let handle = core.handle();
//!
//!     // Create a mailer that delivers to `localhost:25`.
//!     let mailer = Mailer::local();
//!
//!     // Send an email. The `send` method returns an empty future (`()`).
//!     let return_path = "john@example.test".parse().unwrap();
//!     let recipient = "alice@example.test".parse().unwrap();
//!     let body = TEST_EML.to_string();
//!     let f = mailer.send(return_path, vec![recipient], body, &handle);
//!
//!     // Start the client on the event loop.
//!     core.run(f).unwrap();
//! }
//! ```

// FIXME: Add server protocol

extern crate emailaddress;
extern crate futures;
extern crate native_tls;
#[macro_use]
extern crate nom;
extern crate bytes;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_io;
extern crate tokio_tls;

pub mod client;
pub mod request;
pub mod response;
mod util;

use client::{ClientParams, ClientProto, ClientSecurity, ClientTlsParams};
use futures::future;
use futures::{Future, Sink};
use native_tls::{TlsConnector};
use request::{ClientId, Mailbox, Request as SmtpRequest};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc};
use tokio_core::reactor::{Handle};
use tokio_proto::{TcpClient as TokioTcpClient};
use tokio_proto::streaming::{Body, Message};
use tokio_service::{Service};

pub type MailBody = Body<Vec<u8>, IoError>;


struct MailerParams {
    addrs: Vec<SocketAddr>,
    params: Arc<ClientParams>,
}


/// Object used to send mail to a specific server.
///
/// A `Mailer` is created using a `MailerBuilder`.
pub struct Mailer(Arc<MailerParams>);

impl Mailer {
    /// Alias for `MailerBuilder::new(server)`.
    pub fn builder(server: String) -> MailerBuilder {
        MailerBuilder::new(server)
    }

    /// Alias for `MailerBuilder::local().build()`.
    pub fn local() -> Self {
        MailerBuilder::local().build()
            .expect("failed to build mailer for local delivery")
    }

    /// Send an email.
    pub fn send<B: IntoMailBody>(&self, return_path: Mailbox, recipients: Vec<Mailbox>, body: B, handle: &Handle)
            -> Box<Future<Item = (), Error = IoError>> {
        self.send_raw(return_path, recipients, body.into_mail_body(handle), handle)
    }

    fn send_raw(&self, return_path: Mailbox, recipients: Vec<Mailbox>, body: MailBody, handle: &Handle)
            -> Box<Future<Item = (), Error = IoError>> {
        // FIXME: Iterate addrs.
        Box::new(TokioTcpClient::new(ClientProto(self.0.params.clone()))
            .connect(&self.0.addrs[0], handle)
            .and_then(move |service| {
                let mut reqs = Vec::with_capacity(4);
                reqs.push(service.call(
                    Message::WithoutBody(SmtpRequest::Mail {
                        from: return_path,
                        params: vec![],
                    })
                ));
                for recipient in recipients {
                    reqs.push(service.call(
                        Message::WithoutBody(SmtpRequest::Rcpt {
                            to: recipient,
                            params: vec![],
                        })
                    ));
                }
                reqs.push(service.call(
                    Message::WithBody(SmtpRequest::Data, body)
                ));
                reqs.push(service.call(
                    Message::WithoutBody(SmtpRequest::Quit)
                ));
                future::join_all(reqs)
            })
            .and_then(|responses| {
                for response in responses {
                    let response = response.into_inner();
                    if !response.code.severity.is_positive() {
                        return future::err(IoError::new(IoErrorKind::Other,
                            format!("bad smtp response {}", response.code)))
                    }
                }
                future::ok(())
            }))
    }
}


/// Builder for a `Mailer` instance.
pub struct MailerBuilder {
    server: String,
    client_id: ClientId,
    tls_connector: Option<TlsConnector>,
}

impl MailerBuilder {
    /// Create a builder.
    pub fn new(server: String) -> Self {
        MailerBuilder {
            server: server,
            client_id: ClientId::Domain("localhost".to_string()),
            tls_connector: None,
        }
    }

    /// Create a builder setup for connecting to `localhost:25` with no TLS.
    pub fn local() -> MailerBuilder {
        Self::new("localhost:25".to_string())
    }

    /// Set the `EHLO` identifier to send.
    ///
    /// By default, this is `localhost`.
    pub fn set_client_id(mut self, client_id: ClientId) -> Self {
        self.client_id = client_id;
        self
    }

    /// Enable TLS using the `STARTTLS` command, and use the given connector.
    ///
    /// By default, connections do not use TLS.
    pub fn set_tls_connector(mut self, tls_connector: TlsConnector) -> Self {
        self.tls_connector = Some(tls_connector);
        self
    }

    /// Transform this builder into a `Mailer`.
    pub fn build(self) -> IoResult<Mailer> {
        let addrs = self.server.to_socket_addrs()?.collect();
        Ok(Mailer(Arc::new(MailerParams {
            addrs: addrs,
            params: Arc::new(ClientParams {
                id: self.client_id,
                security: match self.tls_connector {
                    None => ClientSecurity::None,
                    Some(connector) => ClientSecurity::Required(ClientTlsParams {
                        connector: connector,
                        sni_domain: self.server.rsplitn(2, ':')
                            .nth(1).unwrap().to_string(),
                    }),
                },
            }),
        })))
    }
}


/// A trait for objects that can be converted to a `MailBody`.
///
/// When sending mail using `Mailer::send`, any object that implements this
/// trait can be passed as the body.
pub trait IntoMailBody {
    /// Converts this object to a `MailBody`.
    ///
    /// The handle can optionally be used to write the body.
    fn into_mail_body(self, &Handle) -> MailBody;
}

impl IntoMailBody for MailBody {
    fn into_mail_body(self, _: &Handle) -> MailBody {
        self
    }
}

impl IntoMailBody for Vec<u8> {
    fn into_mail_body(self, handle: &Handle) -> MailBody {
        let (sender, body) = MailBody::pair();
        handle.spawn(
            sender.send(Ok(self))
                .and_then(|_| future::ok(()))
                .or_else(|_| future::ok(()))
        );
        body
    }
}

impl IntoMailBody for String {
    fn into_mail_body(self, handle: &Handle) -> MailBody {
        self.into_bytes().into_mail_body(handle)
    }
}
