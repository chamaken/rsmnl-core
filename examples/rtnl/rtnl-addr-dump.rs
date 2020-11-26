use std::{
    env,
    io::Write,
    mem::size_of,
    vec::Vec,
    net::{
        Ipv4Addr,
        Ipv6Addr
    },
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH}
};

extern crate libc;
extern crate rsmnl as mnl;

use libc::{ AF_INET, AF_INET6 };
use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_addr;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        writeln!(&mut ::std::io::stderr(), $($arg)*)
            .expect("failed printing to stderr");
    } }
);

fn data_attr_cb<'a, 'b>(tb: &'a mut HashMap<if_addr::IFA, &'b mnl::Attr<'b>>)
                    -> impl FnMut(&'b mnl::Attr<'b>) -> mnl::CbResult + 'a {
    move |attr: &mnl::Attr| {
        // skip unsupported attribute in user-space
        if attr.type_valid(if_addr::IFA_MAX).is_err() {
            return Ok(mnl::CbStatus::Ok);
        }

        let atype = if_addr::IFA::from(attr.atype());
        match atype {
            if_addr::IFA::ADDRESS => {
                attr.validate(mnl::AttrDataType::Binary).map_err(|errno| {
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

fn data_cb(nlh: &mut mnl::Nlmsg) -> mnl::CbResult {
    let mut tb = HashMap::<if_addr::IFA, &mnl::Attr>::new();
    let ifa = nlh.payload::<if_addr::Ifaddrmsg>().unwrap();
    print!("index={} family={} ", ifa.ifa_index, ifa.ifa_family);
    nlh.parse(size_of::<if_addr::Ifaddrmsg>(), data_attr_cb(&mut tb))?;
    print!("addr=");
    tb.get(&if_addr::IFA::ADDRESS)
        .map(|attr| {
            if ifa.ifa_family == AF_INET as u8 {
                let in_addr = attr.value::<Ipv4Addr>().unwrap();
                print!("{} ", in_addr);
            } else if ifa.ifa_family == AF_INET6 as u8 {
                let in6_addr = attr.value::<Ipv6Addr>().unwrap();
                print!("{} ", in6_addr);
            }
        });

    print!("scope=");
    match ifa.ifa_scope {
        0	=> print!("global "),
        200	=> print!("site "),
        253	=> print!("link "),
        254	=> print!("host "),
        255	=> print!("nowhere "),
        _	=> print!("{} ", ifa.ifa_scope),
    }
    
    println!("");
    Ok(mnl::CbStatus::Ok)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("Usage: {} <inet|inet6>", args[0]);
    }

    let mut nl = mnl::Socket::open(netlink::Family::ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    {
        let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_GETADDR;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        *nlh.nlmsg_seq = seq;
        let rt = nlh.put_extra_header::<rtnetlink::Rtgenmsg>().unwrap();
        if args[1] == "inet" {
            rt.rtgen_family = AF_INET as u8;
        } else if args[1] == "inet6" {
            rt.rtgen_family = AF_INET6 as u8;
        }
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
