use errno::Errno;
use libc::{self, nlmsgerr};
use {CbResult, CbStatus, Msghdr};

pub const NOCB: Option<fn(&Msghdr) -> CbResult> = None;

fn noop(_nlh: &Msghdr) -> CbResult {
    Ok(CbStatus::Ok)
}

fn error(nlh: &Msghdr) -> CbResult {
    let err = nlh.payload::<nlmsgerr>()?;
    match err.error {
        e if e < 0 => crate::gen_errno!(-err.error),
        e if e > 0 => crate::gen_errno!(err.error),
        _ => Ok(CbStatus::Stop),
    }
}

fn stop(_nlh: &Msghdr) -> CbResult {
    Ok(CbStatus::Stop)
}

const DEFAULT_CB_ARRAY: [Option<fn(&Msghdr) -> CbResult>; libc::NLMSG_MIN_TYPE as usize] = [
    None,
    Some(noop),  // NLMSG_NOOP:		0x1
    Some(error), // NLMSG_ERROR:		0x2
    Some(stop),  // NLMSG_DONE:		0x3
    Some(noop),  // NLMSG_OVERRUN:	0x4
    // ..Default::default()
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
];

// T might be a dyn FnMut and U is fn
fn __run<'a, T, U>(
    buf: &'a [u8],
    seq: u32,
    portid: u32,
    mut cb_data: Option<T>,
    cb_ctl_array: &mut [Option<U>],
) -> CbResult
where
    T: FnMut(&'a Msghdr<'a>) -> CbResult,
    U: FnMut(&'a Msghdr<'a>) -> CbResult,
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
        if nlh.nlmsg_flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
            return crate::gen_errno!(libc::EINTR);
        }
        if nlh.nlmsg_type >= libc::NLMSG_MIN_TYPE as u16 {
            if let Some(ref mut cb) = cb_data {
                match cb(&nlh) {
                    Ok(CbStatus::Ok) => {}
                    ret @ _ => return ret,
                }
            }
        } else if nlh.nlmsg_type < cb_ctl_array.len() as u16 {
            if let Some(ref mut ctl_cb) = cb_ctl_array[nlh.nlmsg_type as usize] {
                match ctl_cb(&nlh) {
                    Ok(CbStatus::Ok) => {}
                    ret @ _ => return ret,
                }
            }
        } else if let Some(default_cb) = DEFAULT_CB_ARRAY[nlh.nlmsg_type as usize] {
            match default_cb(&nlh) {
                Ok(CbStatus::Ok) => {}
                ret @ _ => return ret,
            }
        }
        nlh = unsafe { nlh.next(&mut len) };
        if !nlh.ok(len) {
            break;
        }
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
pub fn run2<T, U>(
    buf: &[u8],
    seq: u32,
    portid: u32,
    cb_data: Option<T>,
    cb_ctl_array: &mut [Option<U>],
) -> CbResult
where
    T: FnMut(&Msghdr) -> CbResult,
    U: FnMut(&Msghdr) -> CbResult,
{
    __run(buf, seq, portid, cb_data, cb_ctl_array)
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
pub fn run<U: FnMut(&Msghdr) -> CbResult>(
    buf: &[u8],
    seq: u32,
    portid: u32,
    cb_data: Option<U>,
) -> CbResult {
    __run(buf, seq, portid, cb_data, &mut [] as &mut [Option<U>])
}
