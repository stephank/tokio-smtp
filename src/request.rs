//! SMTP request, containing one of several commands, and arguments

// FIXME: Add parsing.

use emailaddress::{EmailAddress, AddrError};
use std::io::{Error as IoError};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{FromStr};
use tokio_proto::streaming::pipeline::{Frame};
use util::{XText};


/// Client identifier, as sent in `EHLO`.
#[derive(PartialEq,Eq,Clone,Debug)]
pub enum ClientId {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Other { tag: String, value: String },
}

impl Display for ClientId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            ClientId::Domain(ref value) => f.write_str(value),
            ClientId::Ipv4(ref value) => write!(f, "{}", value),
            ClientId::Ipv6(ref value) => write!(f, "IPv6:{}", value),
            ClientId::Other { ref tag, ref value } => write!(f, "{}:{}", tag, value),
        }
    }
}


/// A mailbox specified in `MAIL FROM` or `RCPT TO`.
#[derive(PartialEq,Clone,Debug)]
pub struct Mailbox(pub Option<EmailAddress>);

impl From<EmailAddress> for Mailbox {
    fn from(addr: EmailAddress) -> Self {
        Mailbox(Some(addr))
    }
}

impl FromStr for Mailbox {
    type Err = AddrError;

    fn from_str(string: &str) -> Result<Mailbox, AddrError> {
        if string.is_empty() {
            Ok(Mailbox(None))
        } else {
            Ok(EmailAddress::new(string)?.into())
        }
    }
}

impl Display for Mailbox {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self.0 {
            Some(ref email) => write!(f, "<{}>", email),
            None => f.write_str("<>"),
        }
    }
}


/// A `MAIL FROM` extension parameter.
#[derive(PartialEq,Eq,Clone,Debug)]
pub enum MailParam {
    Body(MailBodyParam),
    Size(usize),
    Other { keyword: String, value: Option<String> },
}

impl Display for MailParam {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            MailParam::Body(ref value) => write!(f, "BODY={}", value),
            MailParam::Size(size) => write!(f, "SIZE={}", size),
            MailParam::Other { ref keyword, value: Some(ref value) } => {
                write!(f, "{}={}", keyword, XText(value))
            },
            MailParam::Other { ref keyword, value: None } => {
                f.write_str(keyword)
            },
        }
    }
}


/// Values for the `BODY` parameter to `MAIL FROM`.
#[derive(PartialEq,Eq,Clone,Debug)]
pub enum MailBodyParam {
    SevenBit,
    EightBitMime,
}

impl Display for MailBodyParam {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            MailBodyParam::SevenBit => f.write_str("7BIT"),
            MailBodyParam::EightBitMime => f.write_str("8BITMIME"),
        }
    }
}


/// A `RCPT TO` extension parameter.
#[derive(PartialEq,Eq,Clone,Debug)]
pub enum RcptParam {
    Other { keyword: String, value: Option<String> },
}

impl Display for RcptParam {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            RcptParam::Other { ref keyword, value: Some(ref value) } => {
                write!(f, "{}={}", keyword, XText(value))
            },
            RcptParam::Other { ref keyword, value: None } => {
                f.write_str(keyword)
            },
        }
    }
}


/// A complete SMTP request.
#[derive(PartialEq,Clone,Debug)]
pub enum Request {
    Ehlo(ClientId),
    StartTls,
    Mail { from: Mailbox, params: Vec<MailParam> },
    Rcpt { to: Mailbox, params: Vec<RcptParam> },
    Data,
    Quit,
}

impl Display for Request {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            Request::Ehlo(ref id) => write!(f, "EHLO {}\r\n", id),
            Request::StartTls => write!(f, "STARTTLS\r\n"),
            Request::Mail { ref from, ref params } => {
                write!(f, "MAIL FROM:{}", from)?;
                for param in params {
                    write!(f, " {}", param)?;
                }
                f.write_str("\r\n")
            },
            Request::Rcpt { ref to, ref params } => {
                write!(f, "RCPT TO:{}", to)?;
                for param in params {
                    write!(f, " {}", param)?;
                }
                f.write_str("\r\n")
            },
            Request::Data => {
                f.write_str("DATA\r\n")
            },
            Request::Quit => {
                f.write_str("QUIT\r\n")
            },
        }
    }
}

impl From<Request> for Frame<Request, Vec<u8>, IoError> {
    fn from(request: Request) -> Self {
        let has_body = request == Request::Data;
        Frame::Message {
            message: request,
            body: has_body,
        }
    }
}


#[cfg(test)]
mod tests {
    use ::{ClientId, MailBodyParam, MailParam, RcptParam, Request};

    #[test]
    fn test() {
        for (input, expect) in vec![
            (
                Request::Ehlo(
                    ClientId::Domain("foobar.example".to_string())
                ),
                "EHLO foobar.example\r\n",
            ),
            (
                Request::Ehlo(
                    ClientId::Ipv4("127.0.0.1".parse().unwrap())
                ),
                "EHLO 127.0.0.1\r\n",
            ),
            (
                Request::StartTls,
                "STARTTLS\r\n",
            ),
            (
                Request::Mail {
                    from: "".parse().unwrap(),
                    params: vec![],
                },
                "MAIL FROM:<>\r\n",
            ),
            (
                Request::Mail {
                    from: "".parse().unwrap(),
                    params: vec![
                        MailParam::Body(MailBodyParam::EightBitMime),
                        MailParam::Size(1024),
                        MailParam::Other {
                            keyword: "X-FLAG".to_string(),
                            value: None,
                        },
                        MailParam::Other {
                            keyword: "X-VALUE".to_string(),
                            value: Some("+".to_string()),
                        },
                    ],
                },
                "MAIL FROM:<> BODY=8BITMIME SIZE=1024 X-FLAG X-VALUE=+2B\r\n",
            ),
            (
                Request::Mail {
                    from: "john@example.test".parse().unwrap(),
                    params: vec![],
                },
                "MAIL FROM:<john@example.test>\r\n",
            ),
            (
                Request::Rcpt {
                    to: "".parse().unwrap(),
                    params: vec![],
                },
                "RCPT TO:<>\r\n",
            ),
            (
                Request::Rcpt {
                    to: "".parse().unwrap(),
                    params: vec![
                        RcptParam::Other {
                            keyword: "X-FLAG".to_string(),
                            value: None,
                        },
                        RcptParam::Other {
                            keyword: "X-VALUE".to_string(),
                            value: Some("+".to_string()),
                        },
                    ],
                },
                "RCPT TO:<> X-FLAG X-VALUE=+2B\r\n",
            ),
            (
                Request::Rcpt {
                    to: "alice@example.test".parse().unwrap(),
                    params: vec![],
                },
                "RCPT TO:<alice@example.test>\r\n",
            ),
            (
                Request::Data,
                "DATA\r\n",
            ),
            (
                Request::Quit,
                "QUIT\r\n",
            ),
        ] {
            assert_eq!(input.to_string(), expect);
        }
    }
}
