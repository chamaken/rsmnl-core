use std::io::Write;
use std::mem::size_of;
use std::collections::HashMap;
use std::convert::TryFrom;

extern crate rsmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_link;
use mnl::linux::ifh;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_attr_cb<'a, 'b>(tb: &'a mut HashMap<if_link::AttrType, &'b mnl::Attr<'b>>)
                    -> impl FnMut(&'b mnl::Attr<'b>) -> mnl::CbResult + 'a {
    move |attr: &mnl::Attr| {
        // skip unsupported attribute in user-space
        if let Err(_) = attr.type_valid(if_link::IFLA_MAX) {
            return Ok(mnl::CbStatus::Ok);
        }

        let atype = if_link::AttrType::try_from(attr.atype())?;
        match atype {
            if_link::AttrType::Mtu => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                    println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                    return Err(Box::new(errno));
                }
            },
            if_link::AttrType::Ifname => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::String) {
                    println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                    return Err(Box::new(errno));
                }
            },
            _ => {},
        }
        tb.insert(atype, attr);
        Ok(mnl::CbStatus::Ok)
    }
}

fn data_cb(nlh: &mut mnl::Nlmsg) -> mnl::CbResult {
    let mut tb = HashMap::new();

    let ifm: &rtnetlink::Ifinfomsg = nlh.payload()?;
    print!("index={} type={} flags=0x{:x} family={} ",
           ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

    if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let _ = nlh.parse(size_of::<rtnetlink::Ifinfomsg>(), &mut data_attr_cb(&mut tb));
    tb.get(&if_link::AttrType::Mtu)
        .map(|attr| print!("mtu={} ", attr.value::<u32>().unwrap()));
    tb.get(&if_link::AttrType::Ifname)
        .map(|attr| print!("name={} ", attr.str_value().unwrap()));
    println!("");
                      
    Ok(mnl::CbStatus::Ok)
}

fn main() {
    let mut nl = mnl::Socket::open(netlink::Family::ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(rtnetlink::RTMGRP_LINK, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let mut buf = mnl::default_buf();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
        match mnl::cb_run(&mut buf[0..nrecv], 0, 0, Some(&mut data_cb)) {
            Ok(mnl::CbStatus::Ok) => continue,
            Ok(mnl::CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
