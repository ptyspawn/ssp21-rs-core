use crate::error::ParseError;
use crate::message::Field;
use crate::parse::ParseCallbacks;
use std::ffi::{c_void, CString};

#[repr(C)]
struct Region {
    start: usize,
    end: usize,
}

type StartStructCallback =
    unsafe extern "C" fn(name: *const std::os::raw::c_char, user_data: *mut c_void) -> ();
type EndStructCallback = unsafe extern "C" fn(region: Region, user_data: *mut c_void) -> ();
type OnFieldCallback = unsafe extern "C" fn(
    name: *const std::os::raw::c_char,
    value: *const std::os::raw::c_char,
    region: Region,
    user_data: *mut c_void,
) -> ();
type ErrorCallback = unsafe extern "C" fn(
    position: usize,
    message: *const std::os::raw::c_char,
    user_data: *mut c_void,
);

#[repr(C)]
struct Callbacks {
    user_data: *mut c_void,
    start_struct: StartStructCallback,
    end_struct: EndStructCallback,
    field: OnFieldCallback,
    error: ErrorCallback,
}

impl Callbacks {
    pub fn convert(region: crate::parse::Region) -> Region {
        Region {
            start: region.begin.value,
            end: region.end.value,
        }
    }
}

impl ParseCallbacks for Callbacks {
    fn on_start_struct(&mut self, name: &'static str) {
        let n = CString::new(name).unwrap();
        unsafe {
            (self.start_struct)(n.as_ptr(), self.user_data);
        }
    }

    fn on_field(&mut self, name: &'static str, region: crate::parse::Region, value: Field) {
        let n = CString::new(name).unwrap();
        let v = {
            let s = match value {
                Field::Bytes(x) => format!("{}", x.len()),
                Field::DurationMilliseconds(x) => format!("{}", x),
                Field::Enum(d, v) => (d.render)(v).to_string(),
                Field::U16(x) => format!("{}", x),
            };
            CString::new(s).unwrap()
        };

        unsafe {
            (self.field)(
                n.as_ptr(),
                v.as_ptr(),
                Self::convert(region),
                self.user_data,
            );
        }
    }

    fn on_end_struct(&mut self, region: crate::parse::Region) {
        unsafe {
            (self.end_struct)(Self::convert(region), self.user_data);
        }
    }

    fn on_error(&mut self, error: ParseError) {
        let (message, position): (&'static str, usize) = match error {
            ParseError::EndOfStream(pos, _) => ("end of stream", pos.value),
            ParseError::TrailingBytes(pos) => ("unexpected trailing bytes", pos.value),
            ParseError::BadLengthCount(pos, _) => ("bad length byte count", pos.value),
            ParseError::BadLengthEncoding(pos, _, _) => ("bad length encoding", pos.value),
            ParseError::UnknownFunction(pos, _) => ("unknown function code", pos.value),
        };

        let cmessage = CString::new(message).unwrap();

        unsafe {
            (self.error)(position, cmessage.as_ptr(), self.user_data);
        }
    }
}
