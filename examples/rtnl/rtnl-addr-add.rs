use std::{
    env,
    ffi::CString,
    io,
    net::IpAddr,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;
use libc::if_nametoindex;

extern crate rsmnl as mnl;
use mnl::{MsgVec, Socket};

mod linux_bindings;
use linux_bindings as linux;

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 3 {
        println!("Usage: {} iface destination cidr", args[0]);
        println!("Example: {} eth0 10.0.1.12 32", args[0]);
        println!("         {} eth0 ffff::10.0.1.12 128", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let iface: u32 = unsafe {
        let ifname = CString::new(args[1].clone()).unwrap();
        match if_nametoindex(ifname.as_ptr()) {
            0 => return Err(format!("if_nametoindex: {}", io::Error::last_os_error())),
            i @ _ => i,
        }
    };

    let prefix: u8 = args[3].parse().unwrap();

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_NEWADDR as u16;
    nlh.nlmsg_flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;

    let mut ifm = nlv.put_extra_header::<linux::ifaddrmsg>().unwrap();
    ifm.ifa_prefixlen = prefix;
    ifm.ifa_flags = libc::IFA_F_PERMANENT as u8;
    ifm.ifa_scope = libc::RT_SCOPE_UNIVERSE as u8;
    ifm.ifa_index = iface;

    match args[2].parse::<IpAddr>() {
        Ok(r) => match r {
            IpAddr::V4(addr) => {
                ifm.ifa_family = libc::AF_INET as u8;
                nlv.put(libc::IFA_LOCAL as u16, &addr).unwrap();
                nlv.put(libc::IFA_ADDRESS as u16, &addr).unwrap();
            }
            IpAddr::V6(addr) => {
                ifm.ifa_family = libc::AF_INET6 as u8;
                nlv.put(libc::IFA_ADDRESS as u16, &addr).unwrap();
            }
        },
        Err(err) => return Err(format!("inet_pton: {}", err)),
    };

    let mut nl = Socket::open(libc::NETLINK_ROUTE as i32, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    let ret = nl
        .recvfrom(&mut buf)
        .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

    match mnl::cb_run(&buf[0..ret], seq, portid, mnl::NOCB) {
        Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        _ => {}
    };

    Ok(())
}
