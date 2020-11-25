use std::{
    env,
    io,
    net::IpAddr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH}
};

extern crate libc;
use libc::{ if_nametoindex, AF_INET, AF_INET6 };

extern crate rsmnl as mnl;

use mnl::linux::netlink;
use mnl::linux::rtnetlink;


fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 3 {
	panic!("
Usage:   {0} iface destination cidr [gateway]
Example: {0} eth0 10.0.1.12 32 10.0.1.11
         {0} eth0 ffff::10.0.1.12 128 fdff::1\n",
               args[0]);
    }

    let iface = unsafe {
        if_nametoindex(args[1].as_ptr() as *const _ as *const i8)
    };
    if iface == 0 {
        panic!("if_nametoindex: {}", io::Error::last_os_error());
    }

    let dst = IpAddr::from_str(&args[2]).unwrap();
    let prefix = args[3].parse::<u32>().unwrap();

    let gw = if args.len() == 5 {
        let addr = IpAddr::from_str(&args[4]).unwrap();
        if dst.is_ipv4() && addr.is_ipv4()
            || dst.is_ipv6() && addr.is_ipv6() {
                Some(addr)
            } else {
                panic!("gateway address family does not match destination's");
            }
    } else {
        None
    };

    let mut nl = mnl::Socket::open(netlink::Family::ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    {
        let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_NEWROUTE;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE | netlink::NLM_F_ACK;
        *nlh.nlmsg_seq = seq;

        let rtm: &mut rtnetlink::Rtmsg = nlh.put_extra_header().unwrap();
        rtm.rtm_family = match dst {
            IpAddr::V4(_) => AF_INET as u8,
            IpAddr::V6(_) => AF_INET6 as u8,
        };
        rtm.rtm_dst_len = prefix as u8;
        rtm.rtm_src_len = 0;
        rtm.rtm_tos = 0;
        rtm.rtm_protocol = rtnetlink::RTPROT_STATIC;
        rtm.rtm_table = rtnetlink::RT_TABLE_MAIN as u8;
        rtm.rtm_type = rtnetlink::RTN_UNICAST;
        // is there any gateway?
        rtm.rtm_scope = if args.len() == 4 {
            rtnetlink::RT_SCOPE_LINK
        } else {
            rtnetlink::RT_SCOPE_UNIVERSE
        };
        rtm.rtm_flags = 0;

        match dst {
            IpAddr::V4(addr) => {
                let _ = nlh.put(rtnetlink::RTA_DST,
                                &addr.octets()).unwrap();
            },
            IpAddr::V6(addr) => {
                let _ = nlh.put(rtnetlink::RTA_DST,
                                &addr.segments()).unwrap();
            },
        }
        nlh.put(rtnetlink::RTA_OIF, &iface).unwrap();
        if let Some(nh) = gw {
            match nh {
                IpAddr::V4(addr) => {
                    let _ = nlh.put(rtnetlink::RTA_GATEWAY,
                                    &addr.octets()).unwrap();
                },
                IpAddr::V6(addr) => {
                    let _ = nlh.put(rtnetlink::RTA_GATEWAY,
                                    &addr.segments()).unwrap();
                },
            }
        }
        nl.sendto(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }
    {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        mnl::cb_run(&mut buf[0..nrecv], seq, portid, mnl::NO_CB)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));
    }
}
