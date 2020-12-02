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
    Msghdr, CbStatus, CbResult, AttrTbl, Socket,
    linux:: {
        netlink as netlink,
        rtnetlink,
        if_link,
        ifh
    }
};

fn data_cb(nlh: &mut Msghdr) -> CbResult {
    let ifm = nlh.payload::<rtnetlink::Ifinfomsg>().unwrap();
    print!("index={} type={} flags=0x{:x} family={} ",
           ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

    if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let tb = if_link::IflaTbl::from_nlmsg(
        mem::size_of::<rtnetlink::Ifinfomsg>(), nlh
    )?;
    tb.mtu()?.map(|x| print!("mtu={} ", x));
    tb.ifname()?.map(|x| print!("name={} ", x));
    tb.address()?.map(|x| print!("hwaddr={}",
                                 x
                                 .into_iter()
                                 .map(|&e| format!("{:02x}", e))
                                 .collect::<Vec<_>>()
                                 .join(":")));
    println!("");
    Ok(CbStatus::Ok)
}

fn main() {
    let mut nl = Socket::open(netlink::Family::Route, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    {
        let mut nlh = Msghdr::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_GETLINK;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        *nlh.nlmsg_seq = seq;
        let rt: &mut rtnetlink::Rtgenmsg = nlh.put_extra_header().unwrap();
        rt.rtgen_family = AF_PACKET as u8;

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
