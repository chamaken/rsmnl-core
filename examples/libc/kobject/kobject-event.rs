extern crate libc;
extern crate rsmnl as mnl;
use mnl::Socket;

fn main() {
    let mut nl = Socket::open(libc::NETLINK_KOBJECT_UEVENT, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));

    // There is one single group in kobject over netlink
    nl.bind(1 << 0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        if nrecv == 0 {
            break;
        }
	// kobject uses a string based protocol, with no initial
	// netlink header.
        for i in 0..nrecv {
            print!("{}", buf[i] as char);
        }
        println!("");
    }
}
