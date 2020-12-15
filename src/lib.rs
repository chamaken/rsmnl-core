//! # rslmnl
//!
//! `rsmnl` is a Netlink message handling library imitating
//! [libmnl](https://netfilter.org/projects/libmnl/).
//!
//! Cite from the libmnl:
//! > libmnl is a minimalistic user-space library oriented to Netlink
//! > developers. There are a lot of common tasks in parsing, validating,
//! > constructing of both the Netlink header and TLVs that are repetitive and
//! > easy to get wrong. This library aims to provide simple helpers that allows
//! > you to re-use code and to avoid re-inventing the wheel.
#![allow(dead_code)]

extern crate libc;
extern crate errno;
use errno::Errno;

mod nlmsg;
mod attr;
mod callback;
mod socket;
mod msgvec;

pub use nlmsg::Msghdr as Msghdr;
pub use attr::Attr as Attr;
pub use attr::NestAttr as NestAttr;
pub use attr::AttrTbl as AttrTbl;
pub use socket::Socket as Socket;
pub use callback::NOCB as NOCB;
pub use callback::run as cb_run;
pub use callback::run2 as cb_run2;
pub use msgvec::MsgVec as MsgVec;

#[derive(Debug, Copy, Clone)]
pub enum AttrDataType {
    UNSPEC,
    U8,
    U16,
    U32,
    U64,
    String,
    Flag,
    MSecs,
    Nested,
    NestedCompat,
    NulString,
    Binary,
}

#[derive(Debug, PartialEq)]
pub enum CbStatus {
    Ok,
    Stop,
}

// The major premise - alignment of Nlmsghdr and Nlattr is the same: 4
pub const ALIGNTO: usize = 4;
pub const SOCKET_AUTOPID: u32 = 0;

pub type Result<T> = std::result::Result<T, Errno>;
pub type GenError = Box<dyn std::error::Error>;
#[macro_export]
macro_rules! gen_errno {
    ($e: expr) => { Err(crate::GenError::from(Errno($e))) }
}
pub type CbResult = std::result::Result<CbStatus, GenError>;

#[inline]
pub fn align(len: usize) -> usize {
    (len + ALIGNTO - 1) & !(ALIGNTO - 1)
}

pub fn socket_buffer_size() -> usize {
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    assert!(pagesize > Msghdr::HDRLEN);
    if pagesize < 8192 { pagesize } else { 8192 }
}

pub fn default_buffer() -> Vec<u8> {
    vec![0u8; socket_buffer_size()]
}

pub const SOCKET_DUMP_SIZE: usize	= 32768;

pub fn dump_buffer() -> [u8; SOCKET_DUMP_SIZE] {
    [0u8; SOCKET_DUMP_SIZE]
}

/// @imitates: [mnl_attr_parse_payload]
pub fn parse_payload<T: FnMut(&Attr) -> CbResult>
    (payload: &[u8], mut cb: T) -> CbResult
{
    let mut ret: CbResult = gen_errno!(libc::ENOENT);
    let mut attr: &Attr = unsafe { &*(payload.as_ptr() as *const _ as *const Attr) };
    while attr.ok(payload.as_ptr() as *const _ as isize
                  + payload.len() as isize
                  - attr as *const _ as isize) {
        ret = cb(attr);
        match ret {
            Ok(CbStatus::Ok) => {}
            _ => return ret,
        }
        unsafe { attr = attr.next() };
    }
    ret
}
