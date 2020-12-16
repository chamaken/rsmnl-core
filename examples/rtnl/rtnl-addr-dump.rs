use std:: {
    env,
    mem,
    vec::Vec,
    time:: { SystemTime, UNIX_EPOCH },
    net:: { Ipv4Addr, Ipv6Addr },
};

extern crate libc;
extern crate rsmnl as mnl;
use mnl:: {
    MsgVec, Msghdr, Attr, Socket, CbResult, CbStatus,
};

mod bindgen;
use bindgen:: {
    rtnetlink:: { self, rtgenmsg },
    if_addr:: { self, ifaddrmsg },
};

fn data_attr_cb<'a, 'b>(tb: &'b mut [Option<&'a Attr<'a>>])
                        -> impl FnMut(&'a Attr<'a>) -> CbResult + 'b
{
    // validation will be done on getting value
    move |attr: &Attr| {
        let atype = attr.atype() as usize;
	// skip unsupported attribute in user-space */
        if atype >= tb.len() {
            return Ok(CbStatus::Ok);
        }
        tb[atype] = Some(attr);
        Ok(CbStatus::Ok)
    }
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifa = nlh.payload::<ifaddrmsg>().unwrap();
    print!("index={} family={} ", ifa.ifa_index, ifa.ifa_family);

    let mut tb: [Option<&Attr>; if_addr::__IFA_MAX as usize] = Default::default();
    nlh.parse(mem::size_of::<ifaddrmsg>(), data_attr_cb(&mut tb))?;

    print!("addr=");
    if let Some(attr) = tb[if_addr::IFA_ADDRESS as usize] {
        if ifa.ifa_family == libc::AF_INET as u8 {
            print!("{} ", attr.value_ref::<Ipv4Addr>()?);
        } else if ifa.ifa_family == libc::AF_INET6 as u8 {
            print!("{} ", attr.value_ref::<Ipv6Addr>()?);
        }
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

    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = rtnetlink::RTM_GETADDR as u16;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    nlh.nlmsg_seq = seq;

    let rt = nlv.push_extra_header::<rtgenmsg>().unwrap();
    if args[1] == "inet" {
        rt.rtgen_family = libc::AF_INET as u8;
    } else if args[1] == "inet6" {
        rt.rtgen_family = libc::AF_INET6 as u8;
    }
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));


    let mut buf = mnl::dump_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        match mnl::cb_run(&buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
