use std::env;
use std::mem::size_of;
use std::time::{SystemTime, UNIX_EPOCH};

extern crate rsmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_link;
use mnl::linux::ifh;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        panic!("Usage: {} [ifname] [up|down]", args[0]);
    }

    let mut change: u32 = 0;
    let mut flags: u32 = 0;
    // if args[2].eq_ignore_ascii_case("up")
    match args[2].to_lowercase().as_ref() {
        "up" => {
            change |= ifh::IFF_UP;
            flags |= ifh::IFF_UP;
        },
        "down" => {
            change |= ifh::IFF_UP;
            flags &= !ifh::IFF_UP;
        },
        _ => panic!("{} is not `up' nor `down'", args[2]),
    }

    let mut nl = mnl::Socket::open(netlink::Family::ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    let mut buf = mnl::default_buf();
    {
        let mut nlh = mnl::Msghdr::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_NEWLINK;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_ACK;
        *nlh.nlmsg_seq = seq;
        let ifm: &mut rtnetlink::Ifinfomsg = nlh.put_extra_header().unwrap();
        ifm.ifi_family = 0; // no libc::AF_UNSPEC;
        ifm.ifi_change = change;
        ifm.ifi_flags = flags;

        nlh.put_str(if_link::IFLA_IFNAME, &args[1]).unwrap();

        println!("{0:.1$?}", nlh, size_of::<rtnetlink::Ifinfomsg>());

        // let my_stdout = StdoutRawFd::Dummy;
        // nlh.fprintf(&my_stdout, size_of::<rtnetlink::Ifinfomsg>());

        nl.sendto(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        mnl::cb_run(&mut buf[0..nrecv], seq, portid, mnl::CB_NONE)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));
    }
}
