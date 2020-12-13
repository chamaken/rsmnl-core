use std:: {
    mem,
    time:: { SystemTime, UNIX_EPOCH }
};

extern crate libc;
extern crate errno;
use errno::Errno;

extern crate rsmnl as mnl;
use mnl:: {
    Socket, MsgVec, Msghdr, Attr, CbResult, CbStatus, AttrTbl, Result,
    linux:: {
        netlink:: { self, Family },
        netfilter:: {
            nfnetlink as nfnl,
            nfnetlink::Nfgenmsg,
            nfnetlink_conntrack:: {
                CtnlMsgTypes, CtattrTypeTbl,
            },
        },
    },
};

// _I know_ enum ctattr_type is less than 64
// and all of each child is less than 16
#[derive(Debug, PartialEq, Eq, Hash)]
struct CtBitset {
    root: u32,
    children: Vec<u16>,
}

impl CtBitset {
    pub fn from_nlmsg(nlh: &Msghdr) -> Result<Self> {
        let mut tid = CtBitset { root: 0, children: Vec::new() };
        nlh.parse(mem::size_of::<Nfgenmsg>(), root_cb(&mut tid))
            .map_err(|err| {
                if let Some(e) = err.downcast_ref::<Errno>() {
                    *e
                } else {
                    unreachable!()
                }
            })?;
        Ok(tid)
    }
}

fn child_cb<'a>(cur: &'a mut u16, tagid: &'a mut CtBitset)
            -> impl FnMut(&Attr) -> CbResult + 'a
{
    move |attr: &Attr| {
        let nla_type = attr.atype();
        assert!(nla_type < 16);
        *cur |= 1 << attr.atype();
        if attr.nla_type & libc::NLA_F_NESTED as u16 != 0 {
            let mut b = 0u16;
            attr.parse_nested(child_cb(&mut b, tagid))?;
            tagid.children.push(b);
        }
        Ok(CbStatus::Ok)
    }
}

fn root_cb(tagid: &mut CtBitset)
           -> impl FnMut(&Attr) -> CbResult + '_
{
    move |attr: &Attr| {
        let nla_type = attr.atype();
        assert!(nla_type < 64);
        tagid.root |= 1 << nla_type;
        if attr.nla_type & libc::NLA_F_NESTED as u16 != 0 {
            let mut b = 0u16;
            attr.parse_nested(child_cb(&mut b, tagid))?;
            tagid.children.push(b);
        }
        Ok(CbStatus::Ok)
    }
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    let tid = CtBitset::from_nlmsg(nlh)?;
    println!("{:?}", tid);
    let tb = CtattrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
    print!("    ");
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
    let mut nl = Socket::open(Family::Netfilter, 0)
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
