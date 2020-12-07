use std:: {
    env,
    mem,
    vec::Vec,
    time::{SystemTime, UNIX_EPOCH}
};

extern crate libc;
extern crate rsmnl as mnl;
use mnl:: {
    Msghdr, AttrTbl, Socket, CbResult, CbStatus,
    linux:: {
        netlink as netlink,
        rtnetlink,
        if_addr:: {
            Ifaddrmsg, IfAddrTbl
        }
    }
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifa = nlh.payload::<Ifaddrmsg>().unwrap();
    print!("index={} family={} ", ifa.ifa_index, ifa.ifa_family);

    let tb = IfAddrTbl::from_nlmsg(mem::size_of::<Ifaddrmsg>(), nlh)?;
    print!("addr=");
    if ifa.ifa_family == libc::AF_INET as u8 {
        tb.address4()?.map(|x| print!("{} ", x));
    } else if ifa.ifa_family == libc::AF_INET6 as u8 {
        tb.address6()?.map(|x| print!("{} ", x));
    }

    print!("scope=");
    match ifa.ifa_scope {
        0	=> print!("global "),
        200	=> print!("site "),
        253	=> print!("link "),
        254	=> print!("host "),
        255	=> print!("nowhere "),
        _	=> print!("{} ", ifa.ifa_scope),
    }

    println!("");
    Ok(CbStatus::Ok)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("Usage: {} <inet|inet6>", args[0]);
    }

    let mut nl = Socket::open(netlink::Family::Route, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    {
        let mut nlh = Msghdr::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_GETADDR;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        *nlh.nlmsg_seq = seq;

        let rt = nlh.put_extra_header::<rtnetlink::Rtgenmsg>().unwrap();
        if args[1] == "inet" {
            rt.rtgen_family = libc::AF_INET as u8;
        } else if args[1] == "inet6" {
            rt.rtgen_family = libc::AF_INET6 as u8;
        }
        nl.sendto(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        match mnl::cb_run(&mut buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
