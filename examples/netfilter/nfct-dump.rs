use std:: {
    mem,
    time:: { SystemTime, UNIX_EPOCH }
};

extern crate libc;
extern crate rsmnl as mnl;

use mnl:: {
    Socket, MsgVec, Msghdr, CbResult, CbStatus, AttrTbl,
    linux:: {
        netlink,
        netfilter:: {
            nfnetlink as nfnl,
            nfnetlink::Nfgenmsg,
            nfnetlink_conntrack:: {
                CtnlMsgTypes, CtattrTypeTbl,
            },
        },
    },
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let tb = CtattrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
    if let Some(tuple_tb) = tb.tuple_orig()? {
        if let Some(ip_tb) = tuple_tb.ip()? {
            ip_tb.v4src()?.map(|x| print!("src={} ", x));
            ip_tb.v4dst()?.map(|x| print!("dst={} ", x));
            ip_tb.v6src()?.map(|x| print!("src={} ", x));
            ip_tb.v6dst()?.map(|x| print!("dst={} ", x));
        }
        if let Some(proto_tb) = tuple_tb.proto()? {
            proto_tb.num()?.map(|x| print!("proto={} ", x));
            proto_tb.src_port()?.map(|x| print!("sport={} ", u16::from_be(*x)));
            proto_tb.dst_port()?.map(|x| print!("dport={} ", u16::from_be(*x)));
            proto_tb.icmp_id()?.map(|x| print!("id={} ", u16::from_be(*x)));
            proto_tb.icmp_type()?.map(|x| print!("type={} ", x));
            proto_tb.icmp_code()?.map(|x| print!("code={} ", x));
            proto_tb.icmpv6_id()?.map(|x| print!("id={} ", u16::from_be(*x)));
            proto_tb.icmpv6_type()?.map(|x| print!("type={} ", x));
            proto_tb.icmpv6_code()?.map(|x| print!("code={} ", x));
        }
    }

    tb.mark()?.map(|x| print!("mark={} ", u32::from_be(*x)));
    tb.secmark()?.map(|x| print!("secmark={} ", u32::from_be(*x))); // obsolete?

    if let Some(cntb) = tb.counters_orig()? {
        print!("original ");
        cntb.packets()?.map(|x| print!("packets={} ", u64::from_be(*x)));
        cntb.bytes()?.map(|x| print!("bytes={} ", u64::from_be(*x)));
    }

    if let Some(cntb) = tb.counters_reply()? {
        print!("reply ");
        cntb.packets()?.map(|x| print!("packets={} ", u64::from_be(*x)));
        cntb.bytes()?.map(|x| print!("bytes={} ", u64::from_be(*x)));
    }

    println!("");
    Ok(CbStatus::Ok)
}

fn main() {
    let mut nl = Socket::open(netlink::Family::Netfilter, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | CtnlMsgTypes::Get as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
    nlh.nlmsg_seq = seq;
    let nfh = nlv.push_extra_header::<Nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = nfnl::NFNETLINK_V0;
    nfh.res_id = 0;
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let mut buf = mnl::dump_buffer();
    let portid = nl.portid();
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
