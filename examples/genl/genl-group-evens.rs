use std::env;

extern crate libc;
extern crate rsmnl as mnl;

use mnl:: {
    Msghdr, Socket, CbStatus, CbResult,
    linux::netlink:: { Family }
};

fn data_cb(nlh: &mut Msghdr) -> CbResult {
    println!("type: {}", *nlh.nlmsg_type);
    Ok(CbStatus::Ok)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("{} [group]", args[0]);
    }
    let group: u32 = args[1].trim().parse().expect("group number required");

    let mut nl = Socket::open(Family::Generic, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    nl.add_membership(group)
        .unwrap_or_else(|errno| panic!("mnl_socket_setsockopt: {}", errno));

    let mut buf = [0u8; 8192]; // vec![0u8; mnl::default_bufsize()]
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        // match mnl::cb_run(&mut buf[0..nrecv], 0, 0, Some(|nlh: &mut Msghdr| {
        //     println!("received event type={} from genetlink group {}",
        //              *nlh.nlmsg_type, group);
        //     Ok(CbResult::Ok)
        // })) {
        match mnl::cb_run(&mut buf[0..nrecv], 0, 0, Some(|_| { Ok(CbStatus::Ok) })) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
