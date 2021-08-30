use std::mem;

extern crate rsmnl as mnl;
use mnl::{Attr, CbResult, CbStatus, Msghdr, Socket};

mod linux_bindings;
use linux_bindings as linux;

fn data_attr_cb<'a, 'b>(
    tb: &'b mut [Option<&'a Attr<'a>>],
) -> impl FnMut(&'a Attr<'a>) -> CbResult + 'b {
    move |attr: &Attr| {
        let atype = attr.atype() as usize;
        // skip unsupported attribute in user-space
        if atype >= tb.len() {
            return Ok(CbStatus::Ok);
        }
        tb[atype] = Some(attr);
        Ok(CbStatus::Ok)
    }
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifm: &linux::ifinfomsg = nlh.payload()?;
    print!(
        "index={} type={} flags=0x{:x} family={} ",
        ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family
    );

    if ifm.ifi_flags & libc::IFF_RUNNING as u32 != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let mut tb: [Option<&Attr>; linux::__IFLA_MAX as usize] = [None; linux::__IFLA_MAX as usize]; // IFLA_MAX as usize - 1
    nlh.parse(mem::size_of::<linux::ifinfomsg>(), data_attr_cb(&mut tb))
        .unwrap();
    tb[libc::IFLA_MTU as usize].map(|attr| attr.value_ref::<u32>().map(|x| print!("mtu={} ", x)));
    tb[libc::IFLA_IFNAME as usize].map(|attr| attr.str_ref().map(|x| print!("name={} ", x)));

    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    nl.bind(linux::RTMGRP_LINK, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;
        match mnl::cb_run(&buf[0..nrecv], 0, 0, Some(&mut data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
