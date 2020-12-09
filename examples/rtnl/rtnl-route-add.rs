use std:: {
    env,
    ffi::CString,
    io,
    net::{ IpAddr },
    time::{ SystemTime, UNIX_EPOCH }
};

extern crate libc;
use libc::{ if_nametoindex };

extern crate rsmnl as mnl;
use mnl:: {
    Socket, MsgVec,
    linux::netlink,
    linux::netlink:: { Family },
    linux::rtnetlink,
    linux::rtnetlink:: { Rtmsg, RtattrType }
};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 3 {
	panic!("
Usage: {} iface destination cidr [gateway]
Example: {} eth0 10.0.1.12 32 10.0.1.11
         {} eth0 ffff::10.0.1.12 128 fdff::1\n",
               args[0], args[0], args[0]);
    }

    let iface = unsafe {
        let ptr = CString::new(args[1].clone()).unwrap(); // clone?
        match if_nametoindex(ptr.as_ptr()) {
            0 => panic!("if_nametoindex: {}", io::Error::last_os_error()),
            i @ _ => i
        }
    };
    let dst = args[2].parse().expect(&format!("failed to parse address: {}", args[2]));
    let prefix = args[3].parse::<u32>().unwrap();
    let gw = if args.len() == 5 {
        Some(args[4].parse().expect(&format!("failed to parse address: {}", args[4])))
    } else {
        None
    };

    let mut nl = Socket::open(Family::Route, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = rtnetlink::RTM_NEWROUTE;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE | netlink::NLM_F_ACK;
    nlh.nlmsg_seq = seq;

    let rtm = nlv.push_extra_header::<Rtmsg>().unwrap();
    rtm.rtm_family = match dst {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
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
        IpAddr::V4(addr) =>
            // nlv.push(RtattrType::Dst, &addr.octets()).unwrap(),
            RtattrType::push_v4dst(&mut nlv, &addr).unwrap(),
        IpAddr::V6(addr) =>
            // nlv.push(RtattrType::Dst, &addr.segments()).unwrap(),
            RtattrType::push_v6dst(&mut nlv, &addr).unwrap(),
    };
    nlv.push(RtattrType::Oif, &iface).unwrap();
    gw.map(|nh| match nh {
        IpAddr::V4(addr) =>
            RtattrType::push_v4gateway(&mut nlv, &addr).unwrap(),
        IpAddr::V6(addr) =>
            RtattrType::push_v6gateway(&mut nlv, &addr).unwrap(),
    });
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let mut buf = mnl::default_buffer();
    let nrecv = nl.recvfrom(&mut buf)
        .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
    mnl::cb_run(&buf[0..nrecv], seq, portid, mnl::CB_NONE)
        .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));
}
