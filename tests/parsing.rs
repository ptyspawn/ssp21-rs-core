extern crate ssp21ws;

use ssp21ws::cursor::Region;
use ssp21ws::enums::*;
use ssp21ws::error::{ParseError, Position};
use ssp21ws::message::*;
use ssp21ws::parse::{parse_message, ParseCallbacks};
use std::collections::VecDeque;

#[derive(Debug, Copy, Clone)]
enum ParseEvent {
    OnStartStruct(&'static str),
    Enum(&'static str, Region, &'static str),
    Bytes(&'static str, Region, &'static [u8]),
    U16(&'static str, Region, u16),
    U32(&'static str, Region, u32),
    OnEndStruct(Region),
    Error(ParseError),
}

struct Callbacks {
    pub events: VecDeque<ParseEvent>,
}

impl Callbacks {
    pub fn expect(events: &[ParseEvent]) -> Callbacks {
        Self {
            events: VecDeque::from(events.to_vec()),
        }
    }
}

impl ParseCallbacks for Callbacks {
    fn on_start_struct(&mut self, name: &'static str) {
        match self
            .events
            .pop_front()
            .expect("on_start_struct: no more events")
        {
            ParseEvent::OnStartStruct(n) => {
                assert_eq!(name, n);
            }
            x => panic!("expected {:?}, but received on_start_struct({})", x, name),
        }
    }

    fn on_field(&mut self, name: &'static str, region: Region, field: Field) {
        match self.events.pop_front().expect("on_field: no more events") {
            ParseEvent::Bytes(ex_name, ex_region, ex_value) => {
                assert_eq!(name, ex_name);
                assert_eq!(region, ex_region);
                match field {
                    Field::Bytes(value) => assert_eq!(value, ex_value),
                    _ => panic!("expected bytes, but received: {:?}", field),
                }
            }
            ParseEvent::U16(ex_name, ex_region, ex_value) => {
                assert_eq!(name, ex_name);
                assert_eq!(region, ex_region);
                match field {
                    Field::U16(value) => assert_eq!(value, ex_value),
                    _ => panic!("expected u16, but received: {:?}", field),
                }
            }
            ParseEvent::U32(ex_name, ex_region, ex_value) => {
                assert_eq!(name, ex_name);
                assert_eq!(region, ex_region);
                match field {
                    Field::DurationMilliseconds(value) => assert_eq!(value, ex_value),
                    _ => panic!("expected u32, but received: {:?}", field),
                }
            }
            ParseEvent::Enum(ex_name, ex_region, ex_value) => {
                assert_eq!(name, ex_name);
                assert_eq!(region, ex_region);
                match field {
                    Field::Enum(display, raw) => assert_eq!((display.render)(raw), ex_value),
                    _ => panic!("expected enum, but received: {:?}", field),
                }
            }
            x => panic!("expected {:?}, but received {:?}", x, field),
        }
    }

    fn on_end_struct(&mut self, region: Region) {
        match self
            .events
            .pop_front()
            .expect("on_end_struct: no more events")
        {
            ParseEvent::OnEndStruct(ex_region) => {
                assert_eq!(region, ex_region);
            }
            x => panic!("expected {:?}, but received on_end_struct({:?})", x, region),
        }
    }

    fn on_error(&mut self, err: ParseError) {
        match self.events.pop_front().expect("on_error: no more events") {
            ParseEvent::Error(ex_err) => {
                assert_eq!(err, ex_err);
            }
            x => panic!("expected {:?}, but received on_error({:?})", x, err),
        }
    }
}

const RHB: &[u8] = &[
    // function
    0x00, // version
    0xAA, 0xBB, // crypto spec
    0x00, 0x00, 0x00, 0x00, 0x00, // max nonce
    0xCA, 0xFE, // max session duration
    0x01, 0x02, 0x03, 0x04, // handshake mode
    0x00, // mode ephemeral
    0x04, 0xAA, 0xBB, 0xCC, 0xDD, // mode data
    0x02, 0xFF, 0xFF,
];

#[test]
fn returns_insufficient_bytes_on_empty_input() {
    let expected_error = ParseError::EndOfStream(Position::new(0), 1);

    let mut callbacks = Callbacks::expect(&[ParseEvent::Error(expected_error)]);

    let error = parse_message(&[], &mut callbacks).err().unwrap();

    assert_eq!(error, expected_error);

    assert!(callbacks.events.is_empty());
}

#[test]
fn completes_full_parse_of_request_handshake_begin() {
    let mut callbacks = Callbacks::expect(&[
        ParseEvent::Enum("function", Region::from(0, 1), "request handshake begin"),
        ParseEvent::U16("version", Region::from(1, 3), 0xAABB),
        ParseEvent::OnStartStruct("crypto spec"),
        ParseEvent::Enum("handshake ephemeral", Region::from(3, 4), "X25519"),
        ParseEvent::Enum("handshake hash", Region::from(4, 5), "SHA-256"),
        ParseEvent::Enum("handshake kdf", Region::from(5, 6), "HKDF-SHA-256"),
        ParseEvent::Enum("session nonce mode", Region::from(6, 7), "strict increment"),
        ParseEvent::Enum("session crypto mode", Region::from(7, 8), "HMAC-SHA-256-16"),
        ParseEvent::OnEndStruct(Region::from(3, 8)),
        ParseEvent::OnStartStruct("session constraints"),
        ParseEvent::U16("max nonce", Region::from(8, 10), 0xCAFE),
        ParseEvent::U32("max session duration", Region::from(10, 14), 0x01020304),
        ParseEvent::OnEndStruct(Region::from(8, 14)),
        ParseEvent::Enum("handshake mode", Region::from(14, 15), "shared secret"),
        ParseEvent::Bytes(
            "mode ephemeral",
            Region::from(15, 20),
            &[0xAA, 0xBB, 0xCC, 0xDD],
        ),
        ParseEvent::Bytes("mode data", Region::from(20, 23), &[0xFF, 0xFF]),
    ]);

    let message = parse_message(RHB, &mut callbacks).unwrap();

    assert!(callbacks.events.is_empty());

    let expected = RequestHandshakeBegin {
        function: Function::RequestHandshakeBegin,
        version: 0xAABB,
        crypto_spec: CryptoSpec {
            handshake_ephemeral: HandshakeEphemeral::X25519,
            handshake_hash: HandshakeHash::Sha256,
            handshake_kdf: HandshakeKDF::HkdfSha256,
            session_nonce_mode: SessionNonceMode::StrictIncrement,
            session_crypto_mode: SessionCryptoMode::HmacSha256Trunc16,
        },
        constraints: SessionConstraints {
            max_nonce: 0xCAFE,
            max_session_duration: 0x01020304,
        },
        handshake_mode: HandshakeMode::SharedSecret,
        mode_ephemeral: &[0xAA, 0xBB, 0xCC, 0xDD],
        mode_data: &[0xFF, 0xFF],
    };

    assert_eq!(message, Message::RequestHandshakeBegin(expected));
}
