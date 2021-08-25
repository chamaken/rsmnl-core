extern crate libc;
extern crate rsmnl as mnl;
use mnl::Socket;

fn main() -> Result<(), String>{
    let mut nl = Socket::open(libc::NETLINK_KOBJECT_UEVENT, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    // There is one single group in kobject over netlink
    nl.bind(1 << 0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
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
