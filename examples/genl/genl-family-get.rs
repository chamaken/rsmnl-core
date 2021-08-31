use std::{
    env, mem, process,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{Attr, CbResult, CbStatus, MsgVec, Msghdr, NestAttr, Socket};

mod linux_bindings;
use linux_bindings as linux;

// without validation,
//   parse_mc_grps_cb
//   parse_family_ops_cb
//   data_attr_cb
// does same thing.
fn data_attr_cb<'a, 'b>(
    tb: &'b mut [Option<&'a Attr<'a>>],
) -> impl FnMut(&'a Attr<'a>) -> CbResult + 'b {
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

fn parse_genl_mc_grps(nested: &Attr) -> CbResult {
    let mut nest = NestAttr::new(nested);
    while let Some(attr) = nest.next() {
        // let tb: [Option<&Attr>; libc::CTRL_ATTR__MAX as usize + 1] = Default::default();
        let mut tb: [Option<&Attr>; linux::__CTRL_ATTR_MAX as usize] = Default::default();
        attr.parse_nested(data_attr_cb(&mut tb))?;
        if let Some(x) = tb[libc::CTRL_ATTR_MCAST_GRP_ID as usize] {
            print!("    id: 0x{:x} ", x.value_ref::<u32>()?);
        }
        if let Some(x) = tb[libc::CTRL_ATTR_MCAST_GRP_NAME as usize] {
            print!("name: {} ", x.cstr()?);
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

    nlh.parse(mem::size_of::<libc::genlmsghdr>(), data_attr_cb(&mut tb))?;
    if let Some(x) = tb[libc::CTRL_ATTR_FAMILY_NAME as usize] {
        print!("name={}, ", x.cstr()?);
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

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() > 2 {
        println!("{} [family name]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::GENL_ID_CTRL as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    if args.len() < 2 {
        nlh.nlmsg_flags |= libc::NLM_F_DUMP as u16;
    }

    let genl = nlv.put_extra_header::<libc::genlmsghdr>().unwrap();
    genl.cmd = libc::CTRL_CMD_GETFAMILY as u8;
    genl.version = 1;

    nlv.put(
        libc::CTRL_ATTR_FAMILY_ID as u16,
        &(libc::GENL_ID_CTRL as u16),
    )
    .unwrap();
    if args.len() >= 2 {
        nlv.put_strz(libc::CTRL_ATTR_FAMILY_NAME as u16, &args[1])
            .unwrap();
    }

    let mut nl = Socket::open(libc::NETLINK_GENERIC, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::dump_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

        match mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
