use std::{
    mem,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{Attr, CbResult, CbStatus, MsgVec, Msghdr, Socket};

mod linux_bindings;
use linux_bindings as linux;

fn data_attr_cb(attr: &Attr) -> CbResult {
    let atype = attr.atype();
    // skip unsupported attribute in user-space */
    if atype >= linux::__IFLA_MAX as u16 {
        return Ok(CbStatus::Ok);
    }

    match atype {
        libc::IFLA_MTU => print!("mtu={} ", attr.value_ref::<u32>()?),
        libc::IFLA_IFNAME => print!("name={} ", attr.str_ref()?),
        _ => {}
    }

    Ok(CbStatus::Ok)
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifm = nlh.payload::<linux::ifinfomsg>().unwrap();
    print!(
        "index={} type={} flags=0x{:x} family={} ",
        ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family
    );

    if ifm.ifi_flags & libc::IFF_RUNNING as u32 != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    nlh.parse(mem::size_of::<linux::ifinfomsg>(), data_attr_cb)
        .unwrap();
    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_GETLINK;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    let rt: &mut linux::rtgenmsg = nlv.put_extra_header().unwrap();
    rt.rtgen_family = libc::AF_PACKET as u8;

    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::dump_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

        match mnl::cb_run(&buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        };
    }

    Ok(())
}
