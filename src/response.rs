//! Structures that model an SMTP response.
//!
//! An SMTP response consists of a status code, and zero or more lines of text.
//! This module does not derive any meaning from the response text.

use nom::{crlf, ErrorKind as NomErrorKind, IResult as NomResult, Needed};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::{FromStr, from_utf8};


/// First digit indicates severity
#[derive(PartialEq,Eq,Copy,Clone,Debug)]
pub enum Severity {
    /// 2yx
    PositiveCompletion,
    /// 3yz
    PositiveIntermediate,
    /// 4yz
    TransientNegativeCompletion,
    /// 5yz
    PermanentNegativeCompletion,
}

impl Severity {
    pub fn parse(input: &[u8]) -> NomResult<&[u8], Severity> {
        parse_severity(input)
    }

    pub fn numeric(&self) -> u8 {
        match *self {
           Severity::PositiveCompletion => 2,
           Severity::PositiveIntermediate => 3,
           Severity::TransientNegativeCompletion => 4,
           Severity::PermanentNegativeCompletion => 5,
        }
    }

    /// Tells if the response is positive
    pub fn is_positive(&self) -> bool {
        match *self {
            Severity::PositiveCompletion | Severity::PositiveIntermediate => true,
            _ => false,
        }
    }
}

impl FromStr for Severity {
    type Err = ();

    fn from_str(s: &str) -> Result<Severity, ()> {
        match Severity::parse(s.as_bytes()) {
            NomResult::Done(_, res) => Ok(res),
            _ => Err(()),
        }
    }
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.numeric())
    }
}


/// Second digit indicates category
#[derive(PartialEq,Eq,Copy,Clone,Debug)]
pub enum Category {
    /// x0z
    Syntax,
    /// x1z
    Information,
    /// x2z
    Connections,
    /// x3z
    Unspecified3,
    /// x4z
    Unspecified4,
    /// x5z
    MailSystem,
}

impl Category {
    pub fn parse(input: &[u8]) -> NomResult<&[u8], Category> {
        parse_category(input)
    }

    pub fn numeric(&self) -> u8 {
        match *self {
           Category::Syntax => 0,
           Category::Information => 1,
           Category::Connections => 2,
           Category::Unspecified3 => 3,
           Category::Unspecified4 => 4,
           Category::MailSystem => 5,
        }
    }
}

impl FromStr for Category {
    type Err = ();

    fn from_str(s: &str) -> Result<Category, ()> {
        match Category::parse(s.as_bytes()) {
            NomResult::Done(_, res) => Ok(res),
            _ => Err(()),
        }
    }
}

impl Display for Category {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.numeric())
    }
}


/// Third digit indicates detail
#[derive(PartialEq,Eq,Clone,Debug)]
pub struct Detail(pub u8);

impl Detail {
    pub fn parse(input: &[u8]) -> NomResult<&[u8], Detail> {
        parse_detail(input)
    }
}

impl FromStr for Detail {
    type Err = ();

    fn from_str(s: &str) -> Result<Detail, ()> {
        match Detail::parse(s.as_bytes()) {
            NomResult::Done(_, res) => Ok(res),
            _ => Err(()),
        }
    }
}

impl Display for Detail {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}


/// Represents a 3 digit SMTP response code
#[derive(PartialEq,Eq,Clone,Debug)]
pub struct Code {
    /// First digit of the response code
    pub severity: Severity,
    /// Second digit of the response code
    pub category: Category,
    /// Third digit of the response code
    pub detail: Detail,
}

impl Code {
    pub fn parse(input: &[u8]) -> NomResult<&[u8], Code> {
        parse_code(input)
    }
}

impl FromStr for Code {
    type Err = ();

    fn from_str(s: &str) -> Result<Code, ()> {
        match Code::parse(s.as_bytes()) {
            NomResult::Done(_, res) => Ok(res),
            _ => Err(()),
        }
    }
}

impl Display for Code {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}{}{}", self.severity, self.category, self.detail)
    }
}


/// An SMTP reply, with separate code and message
///
/// The text message is optional, and may be empty
#[derive(PartialEq,Eq,Clone,Debug)]
pub struct Response {
    /// Response code
    pub code: Code,
    /// Server response text
    pub message: Vec<String>,
}

impl Response {
    pub fn parse(input: &[u8]) -> NomResult<&[u8], Response> {
        parse_response(input)
    }

    /// Returns only the first word of the message if possible
    pub fn first_word(&self) -> Option<&str> {
        self.message.get(0).and_then(|line| line.split_whitespace().next())
    }
}

impl FromStr for Response {
    type Err = ();

    fn from_str(s: &str) -> Result<Response, ()> {
        match Response::parse(s.as_bytes()) {
            NomResult::Done(_, res) => Ok(res),
            _ => Err(()),
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let last_idx = self.message.len() - 1;
        for (i, line) in self.message.iter().enumerate() {
            let delim = if i == last_idx { ' ' } else { '-' };
            write!(f, "{}{}{}\r\n", &self.code, delim, line)?
        }
        Ok(())
    }
}


// Parsers.
//
// FIXME: These are here, because we can't reference e.g. `Code::parse` from
// within the nom macros. But perhaps this is a bug?

fn parse_severity(input: &[u8]) -> NomResult<&[u8], Severity> {
    if input.len() == 0 {
        return NomResult::Incomplete(Needed::Size(1));
    }

    let severity = match input[0] {
        b'2' => Severity::PositiveCompletion,
        b'3' => Severity::PositiveIntermediate,
        b'4' => Severity::TransientNegativeCompletion,
        b'5' => Severity::PermanentNegativeCompletion,
        _ => return NomResult::Error(NomErrorKind::Custom(0)),
    };

    NomResult::Done(&input[1..], severity)
}

fn parse_category(input: &[u8]) -> NomResult<&[u8], Category> {
    if input.len() == 0 {
        return NomResult::Incomplete(Needed::Size(1));
    }

    let category = match input[0] {
        b'0' => Category::Syntax,
        b'1' => Category::Information,
        b'2' => Category::Connections,
        b'3' => Category::Unspecified3,
        b'4' => Category::Unspecified4,
        b'5' => Category::MailSystem,
        _ => return NomResult::Error(NomErrorKind::Custom(0)),
    };

    NomResult::Done(&input[1..], category)
}

fn parse_detail(input: &[u8]) -> NomResult<&[u8], Detail> {
    if input.len() == 0 {
        return NomResult::Incomplete(Needed::Size(1));
    }

    let detail = match input[0] {
        c @ b'0' ... b'9' => Detail(c - b'0'),
        _ => return NomResult::Error(NomErrorKind::Custom(0)),
    };

    NomResult::Done(&input[1..], detail)
}

named!(parse_code<Code>,
    map!(
        tuple!(parse_severity, parse_category, parse_detail),
        |(severity, category, detail)| {
            Code {
                severity: severity,
                category: category,
                detail: detail,
            }
        }
    )
);

named!(parse_response<Response>,
    map_res!(
        tuple!(
            // Parse any number of continuation lines.
            many0!(
                tuple!(
                    parse_code,
                    preceded!(
                        char!(b'-'),
                        take_until_and_consume!(b"\r\n".as_ref())
                    )
                )
            ),
            // Parse the final line.
            tuple!(
                parse_code,
                terminated!(
                    opt!(
                        preceded!(
                            char!(b' '),
                            take_until!(b"\r\n".as_ref())
                        )
                    ),
                    crlf
                )
            )
        ),
        |(lines, (last_code, last_line)): (Vec<_>, _)| {
            // Check that all codes are equal.
            if !lines.iter().all(|&(ref code, _)| *code == last_code) {
                return Err(());
            }

            // Extract text from lines, and append last line.
            let mut lines = lines.into_iter()
                .map(|(_, text)| text)
                .collect::<Vec<_>>();
            if let Some(text) = last_line {
                lines.push(text);
            }

            Ok(Response {
                code: last_code,
                message: lines.into_iter()
                    .map(|line| from_utf8(line).map(|s| s.to_string()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ())?,
            })
        }
    )
);


#[cfg(test)]
mod tests {
    use ::{Category, Code, Detail, Response, Severity};

    #[test]
    fn test() {
        for (input, normalized, expect) in vec![
            (
                "421-First line\r\n421-Second line\r\n421 Third line\r\n",
                "421-First line\r\n421-Second line\r\n421 Third line\r\n",
                Response {
                    code: Code {
                        severity: Severity::TransientNegativeCompletion,
                        category: Category::Connections,
                        detail: Detail(1),
                    },
                    message: vec![
                        "First line".to_string(),
                        "Second line".to_string(),
                        "Third line".to_string(),
                    ],
                },
            ),
            (
                "210 Only line\r\n",
                "210 Only line\r\n",
                    Response {
                    code: Code {
                        severity: Severity::PositiveCompletion,
                        category: Category::Information,
                        detail: Detail(0),
                    },
                    message: vec![
                        "Only line".to_string(),
                    ],
                },
            ),
            (
                "229-Only line\r\n229\r\n",
                "229 Only line\r\n",
                Response {
                    code: Code {
                        severity: Severity::PositiveCompletion,
                        category: Category::Connections,
                        detail: Detail(9),
                    },
                    message: vec![
                        "Only line".to_string(),
                    ],
                },
            ),
        ] {
            let (rest, sub) = Response::parse(input.as_bytes()).unwrap();
            assert_eq!(rest.len(), 0);
            assert_eq!(sub, expect);
            assert_eq!(expect.to_string(), normalized);
        }

        for (word, input) in vec![
            (Some("me".as_ref()), vec!["me", "8BITMIME", "SIZE 42"]),
            (Some("me".as_ref()), vec!["me mo", "8BITMIME", "SIZE 42"]),
            (None, vec![]),
            (None, vec![" "]),
            (None, vec!["  "]),
            (None, vec![""]),
        ] {
            let sub = Response {
                code: Code {
                    severity: Severity::TransientNegativeCompletion,
                    category: Category::Connections,
                    detail: Detail(1),
                },
                message: input.into_iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            assert_eq!(sub.first_word(), word);
        }
    }
}
