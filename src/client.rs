//! The SMTP client implementation.
//!
//! The client is implemented as a [tokio-proto] streaming pipeline protocol.
//!
//!  [tokio-proto]: https://docs.rs/tokio-proto/
//!
//! # Example
//!
//! ```no_run
//! extern crate futures;
//! extern crate tokio_core;
//! extern crate tokio_proto;
//! extern crate tokio_service;
//! extern crate tokio_smtp;
//!
//! use futures::future;
//! use futures::{Future, Sink};
//! use std::net::{ToSocketAddrs};
//! use tokio_core::reactor::{Core};
//! use tokio_proto::streaming::{Body, Message};
//! use tokio_service::{Service};
//! use tokio_smtp::request::{Request as SmtpRequest};
//! use tokio_smtp::client::{Client as SmtpClient};
//!
//! // In this example, we grab the mail body from a fixture.
//! const TEST_EML: &'static str = include_str!("src/fixtures/test.eml");
//!
//! fn main() {
//!     // Create the event loop that will drive this server.
//!     let mut core = Core::new().unwrap();
//!     let handle = core.handle();
//!
//!     // Create a client. `Client` parameters are used in the SMTP and TLS
//!     // handshake, but do not set the address and port to connect to.
//!     let client = SmtpClient::localhost();
//!
//!     // Make a connection to an SMTP server. Here, we use the default address
//!     // that MailHog listens on. This also takes care of TLS, if set in the
//!     // `Client` parameters, and sends the `EHLO` command.
//!     let addr = "localhost:1025".to_socket_addrs().unwrap().next().unwrap();
//!     let f = client.connect(&addr, &handle)
//!
//!         // The future results in a service instance.
//!         .and_then(|service| {
//!
//!             // Create a body sink and stream. The stream is consumed when the
//!             // `DATA` command is sent. We asynchronously write the mail body
//!             // to the stream by spawning another future on the core.
//!             let (body_sender, body) = Body::pair();
//!             handle.spawn(
//!                 body_sender.send(Ok((TEST_EML.as_ref() as &[u8]).to_vec()))
//!                     .map_err(|e| panic!("body send error: {:?}", e))
//!                     .and_then(|_| future::ok(()))
//!             );
//!
//!             // Following the `EHLO` handshake, send `MAIL FROM`, `RCPT TO`,
//!             // and `DATA` with the body, then finally `QUIT`.
//!             future::join_all(vec![
//!                 service.call(Message::WithoutBody(SmtpRequest::Mail {
//!                     from: "john@example.test".parse().unwrap(),
//!                     params: vec![],
//!                 })),
//!                 service.call(Message::WithoutBody(SmtpRequest::Rcpt {
//!                     to: "alice@example.test".parse().unwrap(),
//!                     params: vec![],
//!                 })),
//!                 service.call(Message::WithBody(SmtpRequest::Data, body)),
//!                 service.call(Message::WithoutBody(SmtpRequest::Quit)),
//!             ])
//!
//!         })
//!
//!         // This future results in a `Vec` of messages. Responses from
//!         // the server are always `Message::WithoutBody`.
//!         .and_then(|responses| {
//!
//!             // Grab the `Response` from the `Message`, and print it.
//!             for response in responses {
//!                 println!("{:?}", response.into_inner());
//!             }
//!
//!             future::ok(())
//!
//!         });
//!
//!     // Start the client on the event loop.
//!     core.run(f).unwrap();
//! }
//! ```

use futures::{future, Future, Stream, Sink, Poll};
use native_tls::{Result as TlsResult, TlsConnector};
use nom::{IResult as NomResult};
use request::{ClientId, Request};
use response::{Response, Severity};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Read, Write};
use std::sync::{Arc};
use bytes::{BufMut, BytesMut};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Encoder, Decoder, Framed};
use tokio_proto::{TcpClient as TokioTcpClient};
use tokio_proto::streaming::{Body};
use tokio_proto::streaming::pipeline::{ClientProto as TokioClientProto, Frame, StreamingPipeline};
use tokio_tls::{TlsConnectorExt, TlsStream};

// FIXME: `<T: Io + 'static>`, but E0122
pub type ClientTransport<T> = Framed<ClientIo<T>, ClientCodec>;
pub type ClientBindTransport<T> = Box<Future<Item = ClientTransport<T>, Error = IoError>>;
pub type TcpClient = TokioTcpClient<StreamingPipeline<Body<Vec<u8>, IoError>>, ClientProto>;


/// Parameters to use for secure clients
pub struct ClientTlsParams {
    /// A connector from `native-tls`
    pub connector: TlsConnector,
    /// The domain to send during the TLS handshake
    pub sni_domain: String,
}


/// How to apply TLS to a client connection
pub enum ClientSecurity {
    /// Insecure connection
    None,
    /// Use `STARTTLS`, allow rejection
    Optional(ClientTlsParams),
    /// Use `STARTTLS`, fail on rejection
    Required(ClientTlsParams),
    /// Use TLS without negotation
    Immediate(ClientTlsParams),
}


/// Parameters to use during the client handshake
pub struct ClientParams {
    /// Client identifier, the parameter to `EHLO`
    pub id: ClientId,
    /// Whether to use a secure connection, and how
    pub security: ClientSecurity,
}


/// The codec used to encode client requests and decode server responses
#[derive(Default)]
pub struct ClientCodec {
    escape_count: u8,
}

impl ClientCodec {
    pub fn new() -> Self {
        ClientCodec::default()
    }
}

impl Encoder for ClientCodec {
    type Item = Frame<Request, Vec<u8>, IoError>;
    type Error = IoError;

    fn encode(&mut self, frame: Self::Item, buf: &mut BytesMut) -> IoResult<()> {
        match frame {
            Frame::Message { message, .. } => {
                buf.put_slice(message.to_string().as_bytes());
            },
            Frame::Body { chunk: Some(chunk) } => {
                // Escape lines starting with a '.'
                // FIXME: additional encoding for non-ASCII?
                let mut start = 0;
                for (idx, byte) in chunk.iter().enumerate() {
                    match self.escape_count {
                        0 => self.escape_count = if *byte == b'\r' { 1 } else { 0 },
                        1 => self.escape_count = if *byte == b'\n' { 2 } else { 0 },
                        2 => self.escape_count = if *byte == b'.'  { 3 } else { 0 },
                        _ => unreachable!(),
                    }
                    if self.escape_count == 3 {
                        self.escape_count = 0;
                        buf.put_slice(&chunk[start..idx]);
                        buf.put_slice(b".");
                        start = idx;
                    }
                }
                buf.put_slice(&chunk[start..]);
            },
            Frame::Body { chunk: None } => {
                match self.escape_count {
                    0 => buf.put_slice(b"\r\n.\r\n"),
                    1 => buf.put_slice(b"\n.\r\n"),
                    2 => buf.put_slice(b".\r\n"),
                    _ => unreachable!(),
                }
                self.escape_count = 0;
            },
            Frame::Error { error } => {
                panic!("unimplemented error handling: {:?}", error);
            },
        }
        Ok(())
    }
}

impl Decoder for ClientCodec {
    type Item = Frame<Response, (), IoError>;
    type Error = IoError;
    
    fn decode(&mut self, buf: &mut BytesMut) -> IoResult<Option<Self::Item>> {
        let mut bytes: usize = 0;

        let res = match Response::parse(buf.as_ref()) {
            NomResult::Done(rest, res) => {
                // Calculate how much data to drain.
                bytes = buf.len() - rest.len();

                // Drop intermediate messages (e.g. DATA 354)
                if res.code.severity == Severity::PositiveIntermediate {
                    Ok(None)
                } else {
                    Ok(Some(Frame::Message { message: res, body: false }))
                }
            },
            NomResult::Incomplete(_) => {
                Ok(None)
            },
            NomResult::Error(_) => {
                Err(IoError::new(IoErrorKind::InvalidData, "malformed response"))
            },
        };

        // Drain parsed data.
        if bytes != 0 {
            buf.split_to(bytes);

            // If we dropped the message, try to parse the remaining data.
            if let Ok(None) = res {
                return self.decode(buf);
            }
        }

        res
    }
}


/// An `Io` implementation that wraps a secure or insecure transport into a
/// single type.
pub enum ClientIo<T> {
    /// Insecure transport
    Plain(T),
    /// Secure transport
    Secure(TlsStream<T>),
}

impl<T> ClientIo<T> {
    fn unwrap_plain(self) -> T {
        if let ClientIo::Plain(io) = self {
            io
        } else {
            panic!("called unwrap_plain on non-plain stream")
        }
    }
}

impl<T: AsyncRead + 'static> Read for ClientIo<T> where TlsStream<T>: Read {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match *self {
            ClientIo::Plain(ref mut stream) => stream.read(buf),
            ClientIo::Secure(ref mut stream) => stream.read(buf),
        }
    }
}

impl<T: AsyncWrite + 'static> Write for ClientIo<T> where TlsStream<T>: Write {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match *self {
            ClientIo::Plain(ref mut stream) => stream.write(buf),
            ClientIo::Secure(ref mut stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match *self {
            ClientIo::Plain(ref mut stream) => stream.flush(),
            ClientIo::Secure(ref mut stream) => stream.flush(),
        }
    }
}

impl<T: AsyncRead + 'static> AsyncRead for ClientIo<T> where TlsStream<T>: AsyncRead + Read {}
impl<T: AsyncWrite + 'static> AsyncWrite for ClientIo<T> where TlsStream<T>: AsyncWrite + Write {
    fn shutdown(&mut self) -> Poll<(), IoError> {
        match self {
            &mut ClientIo::Plain(ref mut t) => t.shutdown(),
            &mut ClientIo::Secure(ref mut t) => t.shutdown(),
        }
    }
}

/// The Tokio client protocol implementation
///
/// Implements an SMTP client using a streaming pipeline protocol.
pub struct ClientProto(pub Arc<ClientParams>);

// FIXME: Can we do this with a regular function?
// FIXME: Return opening and ehlo responses.
macro_rules! handshake {
    ( $io:expr , $params:expr , | $stream:ident | $after_send:block ) => ({
        // Start codec.
        $io.framed(ClientCodec::new())
            // Send EHLO.
            .send(Request::Ehlo($params.id.clone()).into())
            // Pipeline additional messages.
            .and_then(|$stream| $after_send)
            // Receive server opening.
            .and_then(|stream| {
                stream.into_future()
                    .map_err(|(err, _)| err)
            })
            .and_then(|(response, stream)| {
                // Fail if closed.
                let response = match response {
                    Some(Frame::Message { message, .. }) => message,
                    None => return future::err(IoError::new(
                        IoErrorKind::InvalidData, "connection closed before handshake")),
                    _ => unreachable!(),
                };

                // Ensure it likes us, and supports ESMTP.
                let esmtp = response.text.get(0)
                    .and_then(|line| line.split_whitespace().nth(1));
                if !response.code.severity.is_positive() || esmtp != Some("ESMTP") {
                    return future::err(IoError::new(
                        IoErrorKind::InvalidData, "invalid handshake"));
                }

                future::ok(stream)
            })
            // Receive EHLO response.
            .and_then(|stream| {
                stream.into_future()
                    .map_err(|(err, _)| err)
            })
            .and_then(|(response, stream)| {
                // Fail if closed.
                if response.is_none() {
                    return future::err(IoError::new(
                        IoErrorKind::InvalidData, "connection closed during handshake"))
                }

                future::ok(stream)
            })
    })
}

impl ClientProto {
    fn connect<T: AsyncRead + AsyncWrite + 'static>(io: T, params: Arc<ClientParams>) -> ClientBindTransport<T> {
        match params.security {
            ClientSecurity::None => {
                Self::connect_plain(io, params)
            },
            ClientSecurity::Optional(_) | ClientSecurity::Required(_) => {
                Self::connect_starttls(io, params)
            },
            ClientSecurity::Immediate(_) => {
                Self::connect_immediate_tls(io, params)
            },
        }
    }

    fn connect_plain<T: AsyncRead + AsyncWrite + 'static>(io: T, params: Arc<ClientParams>) -> ClientBindTransport<T> {
        // Perform the handshake.
        Box::new(handshake!(ClientIo::Plain(io), params, |stream| {
            future::ok(stream)
        }))
    }

    fn connect_starttls<T: AsyncRead + AsyncWrite + 'static>(io: T, params: Arc<ClientParams>) -> ClientBindTransport<T> {
        let is_required =
            if let ClientSecurity::Required(_) = params.security { true } else { false };
        // Perform the handshake, and send STARTTLS.
        Box::new(handshake!(ClientIo::Plain(io), params, |stream| {
            stream.send(Request::StartTls.into())
        })
            // Receive STARTTLS response.
            .and_then(|stream| {
                stream.into_future()
                    .map_err(|(err, _)| err)
            })
            .and_then(move |(response, stream)| {
                // Fail if closed.
                let response = match response {
                    Some(Frame::Message { message, .. }) => message,
                    None => return future::err(IoError::new(
                        IoErrorKind::InvalidData, "connection closed before starttls")),
                    _ => unreachable!(),
                };

                // Handle rejection.
                if !response.code.severity.is_positive() && is_required {
                    return future::err(IoError::new(
                        IoErrorKind::InvalidData, "starttls rejected"));
                }

                future::ok(stream)
            })
            .and_then(move |stream| {
                // Get the inner `Io` back, then start TLS on it.
                // The block is to ensure the lifetime of `params.
                {
                    let io = stream.into_inner().unwrap_plain();
                    let tls_params = match params.security {
                        ClientSecurity::Optional(ref tls_params) |
                                ClientSecurity::Required(ref tls_params) => tls_params,
                        _ => panic!("bad params to connect_starttls"),
                    };
                    tls_params.connector.connect_async(&tls_params.sni_domain, io)
                        .map_err(|err| IoError::new(IoErrorKind::Other, err))
                }
                    .and_then(move |io| {
                        // Re-do the handshake.
                        handshake!(ClientIo::Secure(io), params, |stream| {
                            future::ok(stream)
                        })
                    })
            }))
    }

    fn connect_immediate_tls<T: AsyncRead + AsyncWrite + 'static>(io: T, params: Arc<ClientParams>) -> ClientBindTransport<T> {
        // Start TLS on the `Io` first.
        // The block is to ensure the lifetime of `params.
        Box::new({
            let tls_params = match params.security {
                ClientSecurity::Immediate(ref tls_params) => tls_params,
                _ => panic!("bad params to connect_immediate_tls"),
            };
            tls_params.connector.connect_async(&tls_params.sni_domain, io)
                .map_err(|err| IoError::new(IoErrorKind::Other, err))
        }
            .and_then(move |io| {
                // Perform the handshake.
                handshake!(ClientIo::Secure(io), params, |stream| {
                    future::ok(stream)
                })
            }))
    }
}

impl<T: AsyncRead + AsyncWrite + 'static> TokioClientProto<T> for ClientProto {
    type Request = Request;
    type RequestBody = Vec<u8>;
    type Response = Response;
    type ResponseBody = ();
    type Error = IoError;
    type Transport = ClientTransport<T>;
    type BindTransport = ClientBindTransport<T>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Self::connect(io, self.0.clone())
    }
}


/// Utility for creating a `TcpClient`
///
/// This unit struct itself serves no real purpose, but contains constructor
/// methods for creating a `TcpClient` set up with the SMTP protocol.
pub struct Client;

impl Client {
    /// Setup a client for connecting to the local server
    pub fn localhost() -> TcpClient {
        Self::insecure(ClientId::Domain("localhost".to_string()))
    }

    /// Setup a client for connecting without TLS
    pub fn insecure(id: ClientId) -> TcpClient {
        Self::with_params(ClientParams {
            security: ClientSecurity::None,
            id: id,
        })
    }

    /// Setup a client for connecting with TLS using STARTTLS
    pub fn secure(id: ClientId, sni_domain: String) -> TlsResult<TcpClient> {
        Ok(Self::with_params(ClientParams {
            security: ClientSecurity::Required(ClientTlsParams {
                connector: TlsConnector::builder()
                    .and_then(|builder| builder.build())?,
                sni_domain: sni_domain,
            }),
            id: id,
        }))
    }

    /// Setup a client for connecting with TLS on a secure port
    pub fn secure_port(id: ClientId, sni_domain: String) -> TlsResult<TcpClient> {
        Ok(Self::with_params(ClientParams {
            security: ClientSecurity::Immediate(ClientTlsParams {
                connector: TlsConnector::builder()
                    .and_then(|builder| builder.build())?,
                sni_domain: sni_domain,
            }),
            id: id,
        }))
    }

    /// Setup a client using custom parameters
    pub fn with_params(params: ClientParams) -> TcpClient {
        TokioTcpClient::new(ClientProto(Arc::new(params)))
    }
}
