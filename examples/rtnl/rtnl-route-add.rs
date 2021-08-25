use std:: {
    env,
    ffi::CString,
    io,
    net::{ IpAddr },
    process,
    time::{ SystemTime, UNIX_EPOCH }
};

extern crate libc;
use libc::{ if_nametoindex };

extern crate rsmnl as mnl;
use mnl:: {
    Socket, MsgVec,
};

mod linux_bindings;
use linux_bindings as linux;

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 3 {
	println!("Usage: {} iface destination cidr [gateway]", args[0]);
        println!("Example: {} eth0 10.0.1.12 32 10.0.1.11", args[0]);
        println!("         {} eth0 ffff::10.0.1.12 128 fdff::1\n", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let iface = unsafe {
        let ptr = CString::new(args[1].clone()).unwrap();
        match if_nametoindex(ptr.as_ptr()) {
            0 => return Err(format!("if_nametoindex: {}", io::Error::last_os_error())),
            i @ _ => i
        }
    };
    let dst = args[2].parse()
        .map_err(|_| format!("failed to parse address: {}", args[2]))?;
    let prefix = args[3].parse::<u32>()
        .map_err(|_| format!("failed to parse prefix: {}", args[3]))?;
    let gw = if args.len() == 5 {
        Some(args[4].parse()
             .map_err(|_| format!("failed to parse address: {}", args[4]))?)
    } else {
        None
    };

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_NEWROUTE;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16;
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    nlh.nlmsg_seq = seq;

    let rtm = nlv.put_extra_header::<linux::rtmsg>().unwrap();
    rtm.rtm_family = match dst {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    };
    rtm.rtm_dst_len = prefix as u8;
    rtm.rtm_src_len = 0;
    rtm.rtm_tos = 0;
    rtm.rtm_protocol = libc::RTPROT_STATIC;
    rtm.rtm_table = libc::RT_TABLE_MAIN as u8;
    rtm.rtm_type = libc::RTN_UNICAST;
    // is there any gateway?
    rtm.rtm_scope = if args.len() == 4 {
        libc::RT_SCOPE_LINK
    } else {
        libc::RT_SCOPE_UNIVERSE
    };
    rtm.rtm_flags = 0;

    match dst {
        IpAddr::V4(addr) =>
            nlv.put(libc::RTA_DST, &addr).unwrap(),            
        IpAddr::V6(addr) =>
            nlv.put(libc::RTA_DST, &addr).unwrap(),
    };
    nlv.put(libc::RTA_OIF, &iface).unwrap();
    gw.map(|nh| match nh {
        IpAddr::V4(addr) =>
            nlv.put(libc::RTA_GATEWAY, &addr).unwrap(),
        IpAddr::V6(addr) =>
            nlv.put(libc::RTA_GATEWAY, &addr).unwrap(),
    });
    
    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    let nrecv = nl.recvfrom(&mut buf)
        .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
    mnl::cb_run(&buf[0..nrecv], seq, portid, mnl::NOCB)
        .map_err(|errno| format!("mnl_cb_run: {}", errno))?;

    Ok(())
}
