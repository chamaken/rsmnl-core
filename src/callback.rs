use std::{
    collections::HashMap,
    convert::TryFrom
};

extern crate libc;
extern crate errno;

use errno::Errno;
use linux::netlink;
use linux::netlink::{ Nlmsgerr, MsgType };
use { CbStatus, CbResult, Msghdr };

pub const NOCB: Option<fn(&Msghdr) -> CbResult> = None;
pub const DYN_NOCB: Option<Box<dyn FnMut(&Msghdr) -> CbResult>> = None;

fn error(nlh: &Msghdr) -> CbResult {
    let err = nlh.payload::<Nlmsgerr>()?;
    match err.error {
        e if e < 0 => crate::gen_errno!(-err.error),
        e if e > 0 => crate::gen_errno!(err.error),
        _  => Ok(CbStatus::Stop),
    }
}

// buf would be better immutable
fn __run<'a, T: FnMut(&'a Msghdr<'a>) -> CbResult>(
    buf: &'a [u8], seq: u32, portid: u32,
    mut cb_data: Option<T>,
    cb_ctl: &mut HashMap<MsgType, T>)
    -> CbResult
{
    let mut nlh = unsafe { &*(buf.as_ptr() as *const _ as *const Msghdr) };
    let mut len = buf.len() as isize;
    if !nlh.ok(len) {
        return crate::gen_errno!(libc::EBADMSG);
    }

    loop {
        nlh.portid_ok(portid)?;
        nlh.seq_ok(seq)?;
        // dump was interrupted
        if nlh.nlmsg_flags & netlink::NLM_F_DUMP_INTR != 0 {
            return crate::gen_errno!(libc::EINTR);
        }
        match MsgType::try_from(nlh.nlmsg_type)? {
            MsgType::Other(_) => {
                if let Some(ref mut cb) = cb_data {
                    match cb(&nlh) {
                        ret @ Err(_) => return ret,
                        ret @ Ok(CbStatus::Stop) => return ret,
                        _ => {},
                    }
                }
            },
            ref k if cb_ctl.contains_key(k) => {
                let ctlcb = cb_ctl.get_mut(k).unwrap();
                match ctlcb(&mut nlh) {
                    ret @ Err(_) => return ret,
                    ret @ Ok(CbStatus::Stop) => return ret,
                    _ => {},
                }
            },
            MsgType::Noop => {},
            MsgType::Error => return error(&nlh),
            MsgType::Done => return Ok(CbStatus::Stop),
            MsgType::Overrun => {},
        }
        nlh = unsafe { nlh.next(&mut len) };
        if !nlh.ok(len) { break; }
    }
    Ok(CbStatus::Ok)
}

/// You can set the cb_ctl_array to NULL if you want to use the default control
/// callback handlers, in that case, the parameter cb_ctl_array_len is not
/// checked.
///
/// Your callback may return three possible values:
/// 	- MNL_CB_ERROR (<=-1): an error has occurred. Stop callback runqueue.
/// 	- MNL_CB_STOP (=0): stop callback runqueue.
/// 	- MNL_CB_OK (>=1): no problem has occurred.
///
/// This function propagates the callback return value. On error, it returns
/// -1 and errno is explicitly set. If the portID is not the expected, errno
/// is set to ESRCH. If the sequence number is not the expected, errno is set
/// to EPROTO. If the dump was interrupted, errno is set to EINTR and you should
/// request a new fresh dump again.
///
/// @imitates: [libmnl::mnl_cb_run2]
pub fn run2<T: FnMut(&Msghdr) -> CbResult>(
    buf: &[u8], seq: u32, portid: u32,
    cb_data: Option<T>,
    cb_ctl: &mut HashMap<MsgType, T>)
    -> CbResult
{
    __run(buf, seq, portid, cb_data, cb_ctl)
}

/// This function is like mnl_cb_run2() but it does not allow you to set
/// the control callback handlers.
///
/// Your callback may return three possible values:
/// 	- MNL_CB_ERROR (<=-1): an error has occurred. Stop callback runqueue.
/// 	- MNL_CB_STOP (=0): stop callback runqueue.
/// 	- MNL_CB_OK (>=1): no problems has occurred.
///
/// This function propagates the callback return value.
///
/// @imitates: [libmnl::mnl_cb_run]
pub fn run<T: FnMut(&Msghdr) -> CbResult>(
    buf: &[u8], seq: u32, portid: u32,
    cb_data: Option<T>)
    -> CbResult
{
    __run(buf, seq, portid, cb_data, &mut HashMap::new())
}
