use std::collections::HashMap;

extern crate libc;
extern crate errno;

use errno::Errno;
use linux::netlink as netlink;
use super::{CbStatus, CbResult, gen_errno};


// pub const NO_CB: Option<Box<super::NlmsgCb>> = None::<_>;
pub const NO_CB: Option<Box<dyn FnMut(&mut super::Nlmsg) -> CbResult>> = None;

fn error(nlh: &super::Nlmsg) -> CbResult {
    let err = nlh.payload::<netlink::Nlmsgerr>()?;
    match err.error {
        e if e < 0 => gen_errno!(-err.error),
        e if e > 0 => gen_errno!(err.error),
        _  => Ok(CbStatus::Stop),
    }
}

// buf would be better immutable
pub fn __run<CB: FnMut(&mut super::Nlmsg) -> CbResult>(
    buf: &mut [u8], seq: u32, portid: u32,
    mut cb_data: Option<CB>,
    cb_ctl: &mut HashMap<netlink::ControlType, CB>)
    -> CbResult
{
    let mut nlh = unsafe { super::Nlmsg::from_bytes(buf) };
    if !nlh.ok() {
        return gen_errno!(libc::EBADMSG);
    }

    loop {
        nlh.portid_ok(portid)?;
        nlh.seq_ok(seq)?;
        // dump was interrupted
        if *nlh.nlmsg_flags & netlink::NLM_F_DUMP_INTR != 0 {
            return gen_errno!(libc::EINTR);
        }
        match netlink::ControlType::from(*nlh.nlmsg_type) {
            netlink::ControlType::Data(_) => {
                if let Some(ref mut cb) = cb_data {
                    match cb(&mut nlh) {
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
            netlink::ControlType::Noop => {},
            netlink::ControlType::Error => {
                return error(&nlh);
            },
            netlink::ControlType::Done => return Ok(CbStatus::Stop),
            netlink::ControlType::Overrun => {},
        }
        match nlh.next() {
            Some(n) => nlh = n,
            None => break,
        }
    }
    Ok(CbStatus::Ok)
}

pub fn run2<CB: FnMut(&mut super::Nlmsg) -> CbResult>(
    buf: &mut [u8], seq: u32, portid: u32,
    cb_data: Option<CB>,
    cb_ctl: &mut HashMap<netlink::ControlType, CB>)
    -> CbResult
{
    __run(buf, seq, portid, cb_data, cb_ctl)
}

pub fn run<CB: FnMut(&mut super::Nlmsg) -> CbResult>(
    buf: &mut [u8], seq: u32, portid: u32,
    cb_data: Option<CB>)
    -> CbResult
{
    __run(buf, seq, portid, cb_data, &mut HashMap::new())
}
