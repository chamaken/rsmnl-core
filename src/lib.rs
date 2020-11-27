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

#[macro_use]
extern crate rsmnl_derive;

pub mod linux;
use linux::netlink as netlink;

mod nlmsg;
mod batch;
mod attr;
mod callback;
mod socket;

pub use nlmsg::Msghdr as Msghdr;
pub use batch::MsgBatch as MsgBatch;
pub use attr::Attr as Attr;
pub use attr::AttrSet as AttrSet;
pub use socket::Socket as Socket;
// pub use callback::NlmsgCB as NlmsgCB;
pub use callback::NO_CB as NO_CB;
pub use callback::run as cb_run;
pub use callback::run2 as cb_run2;


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

pub type Result<T> = ::std::result::Result<T, Errno>;

pub type GenError = Box<dyn (::std::error::Error)>;
#[macro_export]
macro_rules! gen_errno {
    ($e: expr) => { Err(crate::GenError::from(Box::new(Errno($e)))) }
    // ($e: expr) => { Err(Box::new(Errno($e))) }
    // ($e: expr) => { Err(crate::GenError::from(Errno::new($e))) }
}

pub type CbResult = ::std::result::Result<CbStatus, GenError>;
// need #![feature(type_alias_impl_trait)] to use `impl` instead of `dyn`
pub type MsghdrCb = dyn FnMut(&Msghdr) -> CbResult;
pub type AttrCb = dyn FnMut(&Attr) -> CbResult;

#[inline]
pub fn align(len: usize) -> usize {
    (len + ALIGNTO - 1) & !(ALIGNTO - 1)
}

pub fn default_bufsize() -> usize {
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    assert!(pagesize > Msghdr::HDRLEN);
    if pagesize < 8192 { pagesize } else { 8192 }
}

pub fn default_buf() -> Vec<u8> {
    vec![0u8; default_bufsize()]
}

/// @symbol mnl_attr_parse_payload
pub fn parse_payload<T: FnMut(&Attr) -> CbResult>
    (payload: &[u8], mut cb: T) -> CbResult
{
    let mut ret: CbResult = gen_errno!(libc::ENOENT);
    let mut attr: &Attr = unsafe { &mut *(payload.as_ptr() as *const _ as *mut Attr) };
    while attr.ok((payload.as_ptr() as *const _ as libc::intptr_t
                   + payload.len() as libc::intptr_t
                   - attr as *const _ as libc::intptr_t) as isize) {
        ret = cb(attr);
        match ret {
            Ok(CbStatus::Ok) => {}
            _ => return ret,
        }
        unsafe { attr = attr.next() };
    }
    ret
}
