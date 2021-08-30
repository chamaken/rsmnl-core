use std::{env, process};

extern crate libc;
extern crate rsmnl as mnl;

use mnl::{CbStatus, Msghdr, Socket};

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("{} [group]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let group: u32 = args[1].trim().parse().expect("group number required");

    let mut nl = Socket::open(libc::NETLINK_GENERIC, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    nl.add_membership(group)
        .map_err(|errno| format!("mnl_socket_setsockopt: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

        match mnl::cb_run(
            &buf[0..nrecv],
            0,
            0,
            Some(|nlh: &Msghdr| {
                println!(
                    "received event type={} from genetlink group {}",
                    nlh.nlmsg_type, group
                );
                Ok(CbStatus::Ok)
            }),
        ) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
