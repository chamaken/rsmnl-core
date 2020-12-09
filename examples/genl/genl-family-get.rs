use std:: {
    env,
    mem,
    time::{ SystemTime, UNIX_EPOCH }
};

extern crate libc;
extern crate rsmnl as mnl;

use mnl:: {
    AttrTbl, Socket, Msghdr, MsgVec, CbStatus, CbResult,
    linux::netlink,
    linux::netlink:: { Family },
    linux::genetlink as genl,
    linux::genetlink:: { Genlmsghdr, CtrlAttr, CtrlAttrTbl },
};

fn data_cb(nlh: &Msghdr) -> CbResult {
    let tb = CtrlAttrTbl::from_nlmsg(mem::size_of::<Genlmsghdr>(), nlh)?;
    tb.family_name()?.map(|x| print!("name: {}, ", x));
    tb.family_id()?.map(|x| print!("id: {}, ", x));
    tb.version()?.map(|x| print!("version: {}, ", x));
    tb.hdrsize()?.map(|x| print!("hdrsize: {}, ", x));
    tb.maxattr()?.map(|x| print!("maxattr: {}", x));
    println!("");

    if let Some(optbs) = tb.ops()? {
        println!("  ops:");
        for optb in optbs {
            optb.id()?.map(|x| print!("    id: 0x{:x}, ", x));
            optb.flags()?.map(|x| print!("flags: 0x{:08x} ", x));
            println!("");
        }
    }

    if let Some(mctbs) = tb.mcast_groups()? {
        println!("  grps:");
        for mctb in mctbs {
            mctb.id()?.map(|x| print!("    id: 0x{:x}, ", x));
            mctb.name()?.map(|x| print!("name: {} ", x));
            println!("");
        }
    }

    Ok(CbStatus::Ok)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 2 {
        panic!("{} [family name]", args[0]);
    }

    let mut nl = Socket::open(Family::Generic, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = genl::GENL_ID_CTRL;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_ACK;
    nlh.nlmsg_seq = seq;

    let genl = nlv.push_extra_header::<genl::Genlmsghdr>().unwrap();
    genl.cmd = genl::CTRL_CMD_GETFAMILY;
    genl.version = 1;

    CtrlAttr::push_family_id(&mut nlv, &genl::GENL_ID_CTRL).unwrap();
    if args.len() >= 2 {
        CtrlAttr::push_family_name(&mut nlv, &args[1]).unwrap();
    } else {
        nlh.nlmsg_flags |= netlink::NLM_F_DUMP;
    }

    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let mut buf = mnl::dump_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));

        match mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => panic!("mnl_cb_run: {}", errno),
        }
    }
}
