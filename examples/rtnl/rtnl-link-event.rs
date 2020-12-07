use std::mem;

extern crate rsmnl as mnl;
use mnl:: {
    Msghdr, CbStatus, CbResult, AttrTbl, Socket,
    linux:: {
        netlink as netlink,
        rtnetlink,
        if_link,
        ifh
    }
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifm: &rtnetlink::Ifinfomsg = nlh.payload()?;
    print!("index={} type={} flags=0x{:x} family={} ",
           ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

    if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let tb = if_link::IflaTbl::from_nlmsg(
        mem::size_of::<rtnetlink::Ifinfomsg>(), nlh
    )?;
    tb.mtu()?.map(|x| print!("mtu={} ", x));
    tb.ifname()?.map(|x| print!("name={} ", x));

    println!("");
    Ok(CbStatus::Ok)
}

fn main() {
    let mut nl = Socket::open(netlink::Family::Route, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(rtnetlink::RTMGRP_LINK, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let mut buf = mnl::default_buf();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
        match mnl::cb_run(&mut buf[0..nrecv], 0, 0, Some(&mut data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
