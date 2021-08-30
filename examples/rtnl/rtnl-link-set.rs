use std::{
    env, process,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate rsmnl as mnl;
use mnl::{MsgVec, Socket};

mod linux_bindings;
use linux_bindings as linux;

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} [ifname] [up|down]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let mut change: u32 = 0;
    let mut flags: u32 = 0;
    match args[2].to_lowercase().as_ref() {
        "up" => {
            change |= libc::IFF_UP as u32;
            flags |= libc::IFF_UP as u32;
            Ok(())
        }
        "down" => {
            change |= libc::IFF_UP as u32;
            flags &= !libc::IFF_UP as u32;
            Ok(())
        }
        _ => Err(format!("{} is not neither `up' nor `down'", args[2])),
    }?;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_NEWLINK;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    let ifm: &mut linux::ifinfomsg = nlv.put_extra_header().unwrap();
    ifm.ifi_family = libc::AF_UNSPEC as u8;
    ifm.ifi_change = change;
    ifm.ifi_flags = flags;

    nlv.put_str(libc::IFLA_IFNAME, &args[1]).unwrap();

    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    let nrecv = nl
        .recvfrom(&mut buf)
        .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

    mnl::cb_run(&buf[0..nrecv], seq, portid, mnl::NOCB)
        .map_err(|errno| format!("mnl_cb_run: {}", errno))?;

    Ok(())
}
