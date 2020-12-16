use std:: {
    mem,
    time:: {
        SystemTime, UNIX_EPOCH
    }
};

extern crate libc;
use libc::AF_PACKET;

extern crate rsmnl as mnl;
use mnl:: {
    Msghdr, MsgVec, Attr, CbStatus, CbResult, Socket,
};

mod bindgen;
use bindgen:: {
    rtnetlink:: { rtgenmsg, ifinfomsg, },
    if_link,
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
    let ifm = nlh.payload::<ifinfomsg>().unwrap();
    print!("index={} type={} flags=0x{:x} family={} ",
           ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

    if ifm.ifi_flags & libc::IFF_RUNNING as u32 != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let mut tb: [Option<&Attr>; if_link::__IFLA_MAX as usize] // IFLA_MAX as usize - 1
        = [None; if_link::__IFLA_MAX as usize];
    nlh.parse(mem::size_of::<ifinfomsg>(), data_attr_cb(&mut tb)).unwrap();

    if let Some(attr) = tb[libc::IFLA_MTU as usize] {
        print!("mtu={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::IFLA_IFNAME as usize] {
        print!("name={} ", attr.str_ref()?);
    }
    if let Some(attr) = tb[libc::IFLA_ADDRESS as usize] {
        let hwaddr = attr.bytes_ref();
        print!("hwaddr={}",
               hwaddr
               .into_iter()
               .map(|&e| format!("{:02x}", e))
               .collect::<Vec<_>>()
               .join(":"));
    }
    println!("");
    Ok(CbStatus::Ok)
}

fn main() {
    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = libc::RTM_GETLINK;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    nlh.nlmsg_seq = seq;
    let rt: &mut rtgenmsg = nlv.push_extra_header().unwrap();
    rt.rtgen_family = AF_PACKET as u8;
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
