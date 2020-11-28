use std::{
    io::Write,
    mem::size_of,
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::TryFrom;

extern crate libc;
extern crate rsmnl as mnl;
use libc::AF_PACKET;

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_link;
use mnl::linux::ifh;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        writeln!(&mut ::std::io::stderr(), $($arg)*)
            .expect("failed printing to stderr");
    } }
);

fn data_attr_cb<'a, 'b>(tb: &'a mut HashMap<if_link::AttrType, &'b mnl::Attr<'b>>)
                        -> impl FnMut(&'b mnl::Attr<'b>) -> mnl::CbResult + 'a {
    move |attr: &mnl::Attr| {
        // skip unsupported attribute in user-space
        if attr.type_valid(if_link::AttrType::_MAX as u16 - 1).is_err() {
            return Ok(mnl::CbStatus::Ok);
        }

        let atype = if_link::AttrType::try_from(attr.atype())?;
        match atype {
            if_link::AttrType::Address => {
                attr.validate(mnl::AttrDataType::Binary).map_err(|errno| {
                    println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                    errno
                })?
            },
            if_link::AttrType::Mtu => {
                attr.validate(mnl::AttrDataType::U32).map_err(|errno| {
                    println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                    errno
                })?
            },
            if_link::AttrType::Ifname => {
                attr.validate(mnl::AttrDataType::String).map_err(|errno| {
                    println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                    errno
                })?
            },
            _ => {},
        }
        tb.insert(atype, attr);
        Ok(mnl::CbStatus::Ok)
    }
}

fn data_cb(nlh: &mut mnl::Msghdr) -> mnl::CbResult {
    let mut tb = HashMap::<if_link::AttrType, &mnl::Attr>::new();

    let ifm = nlh.payload::<rtnetlink::Ifinfomsg>().unwrap();
    print!("index={} type={} flags=0x{:x} family={} ",
           ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

    if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    nlh.parse(size_of::<rtnetlink::Ifinfomsg>(), data_attr_cb(&mut tb))?;
    tb.get(&if_link::AttrType::Mtu)
        .map(|attr| print!("mtu={} ", attr.value_ref::<u32>().unwrap()));
    tb.get(&if_link::AttrType::Ifname)
        .map(|attr| print!("name={} ", attr.str_ref().unwrap()));
    tb.get(&if_link::AttrType::Address)
        .map(|attr| {
            print!("hwaddr={}",
                   attr.bytes_ref()
                   .into_iter()
                   .map(|&e| format!("{:02x}", e))
                   .collect::<Vec<_>>()
                   .join(":"));
        });
    println!("");
    Ok(mnl::CbStatus::Ok)
}

fn main() {
    let mut nl = mnl::Socket::open(netlink::Family::ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    {
        let mut nlh = mnl::Msghdr::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_GETLINK;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        *nlh.nlmsg_seq = seq;
        let rt: &mut rtnetlink::Rtgenmsg = nlh.put_extra_header().unwrap();
        rt.rtgen_family = AF_PACKET as u8;

        nl.sendto(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        match mnl::cb_run(&mut buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(mnl::CbStatus::Ok) => continue,
            Ok(mnl::CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
