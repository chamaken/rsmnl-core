use std:: {
    env,
    mem,
    time::{ SystemTime, UNIX_EPOCH }
};

extern crate libc;
use libc:: {
    genlmsghdr,
};

extern crate rsmnl as mnl;
use mnl:: {
    Attr, NestAttr, Socket, Msghdr, MsgVec, CbStatus, CbResult,
};

// without validation,
//   parse_mc_grps_cb
//   parse_family_ops_cb
// and data_attr_cb does same thing.
fn data_attr_cb<'a, 'b>(tb: &'b mut [Option<&'a Attr<'a>>])
                        -> impl FnMut(&'a Attr<'a>) -> CbResult + 'b
{
    // omit validation, will done in getting value.
    move |attr: &Attr| {
        tb[attr.atype() as usize] = Some(attr);
        Ok(CbStatus::Ok)
    }
}

fn parse_genl_mc_grps(nested: &Attr) -> CbResult {
    let mut nest = NestAttr::new(nested);
    while let Some(attr) = nest.next() {
        // let tb: [Option<&Attr>; libc::CTRL_ATTR_MCAST_GRP_MAX as usize + 1] = Default::default();
        let mut tb: [Option<&Attr>; libc::CTRL_ATTR_MCAST_GRP_ID as usize + 1] = Default::default();
        attr.parse_nested(data_attr_cb(&mut tb))?;
        if let Some(x) = tb[libc::CTRL_ATTR_MCAST_GRP_ID as usize] {
            print!("    id: 0x{:x} ", x.value_ref::<u32>()?);
        }
        if let Some(x) = tb[libc::CTRL_ATTR_MCAST_GRP_NAME as usize] {
            print!("name: {} ", x.strz_ref()?);
        }
        println!("");
    }
    Ok(CbStatus::Ok)
}    

fn parse_genl_family_ops(nested: &Attr) -> CbResult {
    let mut nest = NestAttr::new(nested);
    while let Some(attr) = nest.next() {
        // let tb: [Option<&Attr>; libc::CTRL_ATTR_OP_MAX as usize + 1] = Default::default();
        let mut tb: [Option<&Attr>; libc::CTRL_ATTR_OP_FLAGS as usize + 1] = Default::default();
        attr.parse_nested(data_attr_cb(&mut tb))?;
        if let Some(x) = tb[libc::CTRL_ATTR_OP_ID as usize] {
	    print!("    id: 0x{:x}, ", x.value_ref::<u32>()?);
        }
        if let Some(x) = tb[libc::CTRL_ATTR_OP_FLAGS as usize] {
	    print!("flags: 0x{:08x} ", x.value_ref::<u32>()?);
        }
        println!("");
    }
    Ok(CbStatus::Ok)
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    // let mut tb: [Option<&Attr>; libc::CTRL_ATTR_MAX as usize + 1] = Default::default();
    let mut tb: [Option<&Attr>; libc::CTRL_ATTR_MCAST_GROUPS as usize + 1] = Default::default();
    let _genl: &genlmsghdr = nlh.payload()?;

    nlh.parse(mem::size_of::<genlmsghdr>(), data_attr_cb(&mut tb))?;
    if let Some(x) = tb[libc::CTRL_ATTR_FAMILY_NAME as usize] {
        print!("name={}, ", x.strz_ref()?);
    }
    if let Some(x) = tb[libc::CTRL_ATTR_FAMILY_ID as usize] {
        print!("id={}, ", x.value_ref::<u16>()?);
    }
    if let Some(x) = tb[libc::CTRL_ATTR_VERSION as usize] {
        print!("version={}, ", x.value_ref::<u32>()?);
    }
    if let Some(x) = tb[libc::CTRL_ATTR_HDRSIZE as usize] {
        print!("hdrsize={}, ", x.value_ref::<u32>()?);
    }
    if let Some(x) = tb[libc::CTRL_ATTR_MAXATTR as usize] {
        print!("maxattr={}, ", x.value_ref::<u32>()?);
    }
    println!("");
    if let Some(x) = tb[libc::CTRL_ATTR_OPS as usize] {
        println!("  ops:");
        parse_genl_family_ops(x)?;
    }
    if let Some(x) = tb[libc::CTRL_ATTR_MCAST_GROUPS as usize] {
        println!("  grps:");
        parse_genl_mc_grps(x)?;
    }
    println!("");
    Ok(CbStatus::Ok)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 2 {
        panic!("{} [family name]", args[0]);
    }

    let mut nl = Socket::open(libc::NETLINK_GENERIC, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = libc::GENL_ID_CTRL as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16;
    nlh.nlmsg_seq = seq;
    if args.len() < 2 {
        nlh.nlmsg_flags |= libc::NLM_F_DUMP as u16;
    }

    let genl = nlv.push_extra_header::<genlmsghdr>().unwrap();
    genl.cmd = libc::CTRL_CMD_GETFAMILY as u8;
    genl.version = 1;

    nlv.push(libc::CTRL_ATTR_FAMILY_ID as u16, &(libc::GENL_ID_CTRL as u16)).unwrap();
    if args.len() >= 2 {
        nlv.push_strz(libc::CTRL_ATTR_FAMILY_NAME as u16, &args[1]).unwrap();
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
