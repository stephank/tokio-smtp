//! SMTP client connection support

use futures::{future, Future, Stream, Sink};
use native_tls::{Result as TlsResult, TlsConnector};
use nom::{IResult as NomResult};
use request::{ClientId, Request};
use response::{Response, Severity};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Read, Write};
use std::sync::{Arc};
use tokio_core::io::{Codec, EasyBuf, Framed, Io};
use tokio_proto::{TcpClient};
use tokio_proto::streaming::{Body};
use tokio_proto::streaming::pipeline::{ClientProto, Frame, StreamingPipeline};
use tokio_tls::{TlsConnectorExt, TlsStream};

// FIXME: `<T: Io + 'static>`, but E0122
pub type SmtpClientTransport<T> = Framed<SmtpClientIo<T>, SmtpClientCodec>;
pub type SmtpClientBindTransport<T> = Box<Future<Item = SmtpClientTransport<T>, Error = IoError>>;
pub type SmtpTcpClient = TcpClient<StreamingPipeline<Body<Vec<u8>, IoError>>, SmtpClientProto>;


/// TLS parameters used by secure clients
pub struct SmtpClientTlsParams {
    pub connector: TlsConnector,
    pub sni_domain: String,
}


/// How to apply TLS to the connection
pub enum SmtpClientSecurity {
    /// Insecure connection
    None,
    /// Use STARTTLS, allow rejection
    Optional(SmtpClientTlsParams),
    /// Use STARTTLS, fail on rejection
    Required(SmtpClientTlsParams),
    /// Use TLS without negotation
    Immediate(SmtpClientTlsParams),
}


/// SMTP client parameters
pub struct SmtpClientParams {
    pub id: ClientId,
    pub security: SmtpClientSecurity,
}


/// SMTP codec for encoding client requests and decoding server responses
pub struct SmtpClientCodec {
    escape_count: u8,
}

impl SmtpClientCodec {
    pub fn new() -> Self {
        SmtpClientCodec { escape_count: 0 }
    }
}

impl Codec for SmtpClientCodec {
    type Out = Frame<Request, Vec<u8>, IoError>;
    type In = Frame<Response, (), IoError>;

    fn encode(&mut self, frame: Self::Out, buf: &mut Vec<u8>) -> IoResult<()> {
        match frame {
            Frame::Message { message, .. } => {
                buf.write_all(message.to_string().as_bytes())
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
                        buf.write_all(&chunk[start..idx])?;
                        buf.write_all(b".")?;
                        start = idx;
                    }
                }
                buf.write_all(&chunk[start..])
            },
            Frame::Body { chunk: None } => {
                self.escape_count = 0;
                buf.write_all(b".\r\n")
            },
            Frame::Error { error } => {
                panic!("unimplemented error handling: {:?}", error);
            },
        }
    }

    fn decode(&mut self, buf: &mut EasyBuf) -> IoResult<Option<Self::In>> {
        let mut bytes: usize = 0;

        let res = match Response::parse(buf.as_slice()) {
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
            buf.drain_to(bytes);

            // If we dropped the message, try to parse the remaining data.
            if let Ok(None) = res {
                return self.decode(buf);
            }
        }

        res
    }
}


/// An Io implementation that allows to wrap secure and insecure transports
/// into a single type.
pub enum SmtpClientIo<T: Io + 'static> {
    Plain(T),
    Secure(TlsStream<T>),
}

impl<T: Io + 'static> SmtpClientIo<T> {
    fn unwrap_plain(self) -> T {
        if let SmtpClientIo::Plain(io) = self {
            io
        } else {
            panic!("called unwrap_plain on non-plain stream")
        }
    }
}

impl<T: Io + 'static> Read for SmtpClientIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match *self {
            SmtpClientIo::Plain(ref mut stream) => stream.read(buf),
            SmtpClientIo::Secure(ref mut stream) => stream.read(buf),
        }
    }
}

impl<T: Io + 'static> Write for SmtpClientIo<T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match *self {
            SmtpClientIo::Plain(ref mut stream) => stream.write(buf),
            SmtpClientIo::Secure(ref mut stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match *self {
            SmtpClientIo::Plain(ref mut stream) => stream.flush(),
            SmtpClientIo::Secure(ref mut stream) => stream.flush(),
        }
    }
}

impl<T: Io + 'static> Io for SmtpClientIo<T> {}


/// SMTP client protocol implementation
pub struct SmtpClientProto(pub Arc<SmtpClientParams>);

// FIXME: Can we do this with a regular function?
// FIXME: Return opening and ehlo responses.
macro_rules! handshake {
    ( $io:expr , $params:expr , | $stream:ident | $after_send:block ) => ({
        // Start codec.
        $io.framed(SmtpClientCodec::new())
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
                let esmtp = response.message.get(0)
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

impl SmtpClientProto {
    fn connect<T: Io + 'static>(io: T, params: Arc<SmtpClientParams>) -> SmtpClientBindTransport<T> {
        match params.security {
            SmtpClientSecurity::None => {
                Self::connect_plain(io, params)
            },
            SmtpClientSecurity::Optional(_) |
                    SmtpClientSecurity::Required(_) => {
                Self::connect_starttls(io, params)
            },
            SmtpClientSecurity::Immediate(_) => {
                Self::connect_immediate_tls(io, params)
            },
        }
    }

    fn connect_plain<T: Io + 'static>(io: T, params: Arc<SmtpClientParams>) -> SmtpClientBindTransport<T> {
        // Perform the handshake.
        Box::new(handshake!(SmtpClientIo::Plain(io), params, |stream| {
            future::ok(stream)
        }))
    }

    fn connect_starttls<T: Io + 'static>(io: T, params: Arc<SmtpClientParams>) -> SmtpClientBindTransport<T> {
        let is_required =
            if let SmtpClientSecurity::Required(_) = params.security { true } else { false };
        // Perform the handshake, and send STARTTLS.
        Box::new(handshake!(SmtpClientIo::Plain(io), params, |stream| {
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
                        SmtpClientSecurity::Optional(ref tls_params) |
                                SmtpClientSecurity::Required(ref tls_params) => tls_params,
                        _ => panic!("bad params to connect_starttls"),
                    };
                    tls_params.connector.connect_async(&tls_params.sni_domain, io)
                        .map_err(|err| IoError::new(IoErrorKind::Other, err))
                }
                    .and_then(move |io| {
                        // Re-do the handshake.
                        handshake!(SmtpClientIo::Secure(io), params, |stream| {
                            future::ok(stream)
                        })
                    })
            }))
    }

    fn connect_immediate_tls<T: Io + 'static>(io: T, params: Arc<SmtpClientParams>) -> SmtpClientBindTransport<T> {
        // Start TLS on the `Io` first.
        // The block is to ensure the lifetime of `params.
        Box::new({
            let tls_params = match params.security {
                SmtpClientSecurity::Immediate(ref tls_params) => tls_params,
                _ => panic!("bad params to connect_immediate_tls"),
            };
            tls_params.connector.connect_async(&tls_params.sni_domain, io)
                .map_err(|err| IoError::new(IoErrorKind::Other, err))
        }
            .and_then(move |io| {
                // Perform the handshake.
                handshake!(SmtpClientIo::Secure(io), params, |stream| {
                    future::ok(stream)
                })
            }))
    }
}

impl<T: Io + 'static> ClientProto<T> for SmtpClientProto {
    type Request = Request;
    type RequestBody = Vec<u8>;
    type Response = Response;
    type ResponseBody = ();
    type Error = IoError;
    type Transport = SmtpClientTransport<T>;
    type BindTransport = SmtpClientBindTransport<T>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Self::connect(io, self.0.clone())
    }
}


/// SMTP client connector
pub struct SmtpClient;

impl SmtpClient {
    /// Setup a client for connecting to the local server
    pub fn localhost() -> SmtpTcpClient {
        Self::insecure(ClientId::Domain("localhost".to_string()))
    }

    /// Setup a client for connecting without TLS
    pub fn insecure(id: ClientId) -> SmtpTcpClient {
        Self::new(SmtpClientParams {
            security: SmtpClientSecurity::None,
            id: id,
        })
    }

    /// Setup a client for connecting with TLS using STARTTLS
    pub fn secure(id: ClientId, sni_domain: String) -> TlsResult<SmtpTcpClient> {
        Ok(Self::new(SmtpClientParams {
            security: SmtpClientSecurity::Required(SmtpClientTlsParams {
                connector: TlsConnector::builder()
                    .and_then(|builder| builder.build())?,
                sni_domain: sni_domain,
            }),
            id: id,
        }))
    }

    /// Setup a client for connecting with TLS on a secure port
    pub fn secure_port(id: ClientId, sni_domain: String) -> TlsResult<SmtpTcpClient> {
        Ok(Self::new(SmtpClientParams {
            security: SmtpClientSecurity::Immediate(SmtpClientTlsParams {
                connector: TlsConnector::builder()
                    .and_then(|builder| builder.build())?,
                sni_domain: sni_domain,
            }),
            id: id,
        }))
    }

    /// Setup a client using custom parameters
    pub fn new(params: SmtpClientParams) -> SmtpTcpClient {
        TcpClient::new(SmtpClientProto(Arc::new(params)))
    }
}


#[cfg(test)]
mod tests {
    use ::{SmtpClient};
    use futures::future;
    use futures::{Future, Sink};
    use request::{Request};
    use std::net::{ToSocketAddrs};
    use tokio_core::reactor::{Core};
    use tokio_proto::streaming::{Body, Message};
    use tokio_service::{Service};

    const TEST_EML: &'static str = include_str!("fixtures/test.eml");

    #[test]
    #[ignore]
    fn test() {
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let addr = "localhost:1025".to_socket_addrs().unwrap().next().unwrap();
        let f = SmtpClient::localhost()
            .connect(&addr, &handle)
            .and_then(|service| {
                let (body_sender, body) = Body::pair();
                handle.spawn(
                    body_sender.send(Ok((TEST_EML.as_ref() as &[u8]).to_vec()))
                        .map_err(|e| panic!("body send error: {:?}", e))
                        .and_then(|_| future::ok(()))
                );

                future::join_all(vec![
                    service.call(Message::WithoutBody(Request::Mail {
                        from: "john@example.test".parse().unwrap(),
                        params: vec![],
                    })),
                    service.call(Message::WithoutBody(Request::Rcpt {
                        to: "alice@example.test".parse().unwrap(),
                        params: vec![],
                    })),
                    service.call(Message::WithBody(Request::Data.into(), body)),
                ])
                .and_then(move |responses| {
                    for response in responses {
                        println!("{:?}", response.into_inner());
                    }
                    service.call(Message::WithoutBody(Request::Quit))
                })
                .and_then(|response| {
                    println!("{:?}", response.into_inner());
                    future::ok(())
                })
            });

        core.run(f).unwrap();
    }
}