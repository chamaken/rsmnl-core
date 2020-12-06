use std::env;
use std::io::Write;
use std::mem::size_of;

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::genetlink as genl;


macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn parse_mc_grps_cb<'a, 'b>(tb: &'b mut [Option<&'a mnl::Attr>]) -> Box<FnMut(&'a mnl::Attr) -> mnl::CbRet + 'b> {
    Box::new(move |attr: &'a mnl::Attr| {
        // skip unsupported attribute in user-space
        if let Err(_) = attr.type_valid(genl::CTRL_ATTR_MCAST_GRP_MAX as u16) {
            return mnl::CbRet::OK;
        }

        let atype = attr.atype();
        match atype {
            n if n == genl::CtrlAttrMcastGrp::ID as u16 => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
            n if n == genl::CtrlAttrMcastGrp::NAME as u16 => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::STRING) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
            _ => {},
        }
        tb[atype as usize] = Some(attr);
        mnl::CbRet::OK
    })
}

fn parse_genl_mc_grps(nested: &mnl::Attr) {
    for pos in nested.nesteds() {
        let mut tb: [Option<&mnl::Attr>; genl::CTRL_ATTR_MCAST_GRP_MAX as usize + 1]
            = [None; genl::CTRL_ATTR_MCAST_GRP_MAX as usize + 1];

        let _ = pos.cl_parse_nested(parse_mc_grps_cb(&mut tb));

        tb[genl::CtrlAttrMcastGrp::ID as usize]
            .map(|attr| print!("id-0x{:x} ", attr.u32()));
        tb[genl::CtrlAttrMcastGrp::NAME as usize]
            .map(|attr| print!("name: {} ", attr.str()));
        println!("");
    }
}

fn parse_genl_family_ops<'a>(nested: &mnl::Attr) {
    for pos in nested.nesteds() {
        let mut tb: [Option<&'a mnl::Attr>; genl::CTRL_ATTR_OP_MAX as usize + 1]
            = [None; genl::CTRL_ATTR_OP_MAX as usize + 1];

        let _ = pos.cl_parse_nested(Box::new(|attr: &'a mnl::Attr| {
            if let Err(_) = attr.type_valid(genl::CTRL_ATTR_OP_MAX) {
                return mnl::CbRet::OK;
            }

            let atype = attr.atype();
            match atype {
                n if (n == genl::CtrlAttrOp::ID as u16 ||
                      n == genl::CtrlAttrOp::FLAGS as u16) => {
                    if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                        println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                        return mnl::CbRet::ERROR;
                    }
                },
                n if n == genl::CTRL_ATTR_OP_MAX => {},
                _ => {
                    return mnl::CbRet::OK;
                },
            }

            tb[atype as usize] = Some(attr);
            return mnl::CbRet::OK;
        }));

        tb[genl::CtrlAttrOp::ID as usize]
            .map(|attr| print!("id-0x{:x} ", attr.u32()));
        tb[genl::CtrlAttrOp::FLAGS as usize]
            .map(|attr| print!("flags 0x{:08x}", attr.u32()));
        println!("");
    }
}

fn data_attr_cb<'a, 'b>(tb: &'b mut [Option<&'a mnl::Attr>])
                        -> Box<FnMut(&'a mnl::Attr) -> mnl::CbRet + 'b>
{
    Box::new(move |attr: &'a mnl::Attr| {
        if let Err(_) = attr.type_valid(genl::CTRL_ATTR_MAX) {
            return mnl::CbRet::OK;
        }

        let atype = attr.atype();
        match atype {
            n if n == genl::CtrlAttr::FAMILY_NAME as u16 => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::STRING) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
            n if n == genl::CtrlAttr::FAMILY_ID as u16 => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::U16) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
            n if (n == genl::CtrlAttr::VERSION as u16 ||
                  n == genl::CtrlAttr::HDRSIZE as u16 ||
                  n == genl::CtrlAttr::MAXATTR as u16) => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
            n if (n == genl::CtrlAttr::OPS as u16 ||
                  n == genl::CtrlAttr::MCAST_GROUPS as u16) => {
                if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
            _ => {},
        }

        tb[atype as usize] = Some(attr);
        return mnl::CbRet::OK;
    })
}

fn data_cb() -> Box<FnMut(mnl::Nlmsg) -> mnl::CbRet> {
    Box::new(|nlh: mnl::Nlmsg| {
        let mut tb: [Option<&mnl::Attr>; genl::CTRL_ATTR_MAX as usize + 1]
            = [None; genl::CTRL_ATTR_MAX as usize + 1];

        let _ = nlh.cl_parse(size_of::<genl::Genlmsghdr>(), data_attr_cb(&mut tb));

        tb[genl::CtrlAttr::FAMILY_NAME as usize]
            .map(|attr| print!("name={}\t", attr.str()));
        tb[genl::CtrlAttr::FAMILY_ID as usize]
            .map(|attr| print!("id={}\t", attr.u16()));
        tb[genl::CtrlAttr::VERSION as usize]
            .map(|attr| print!("version={}\t", attr.u32()));
        tb[genl::CtrlAttr::HDRSIZE as usize]
            .map(|attr| print!("hdrsize={}\t", attr.u32()));
        tb[genl::CtrlAttr::MAXATTR as usize]
            .map(|attr| print!("maxattr={}\t", attr.u32()));
        println!("");

        tb[genl::CtrlAttr::OPS as usize]
            .map(|attr| {
                println!("ops:");
                parse_genl_family_ops(attr);
            });
        tb[genl::CtrlAttr::MCAST_GROUPS as usize]
            .map(|attr| {
                println!("grps:");
                parse_genl_mc_grps(attr);
            });
        println!("");

        return mnl::CbRet::OK;
    })
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 2 {
        panic!("{} [family name]", args[0]);
    }

    let nl = mnl::Socket::open(netlink::Family::GENERIC)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let seq = time::now().to_timespec().sec as u32;
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        *nlh.nlmsg_type = genl::GENL_ID_CTRL;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_ACK;
        *nlh.nlmsg_seq = seq;

        let genl = nlh.put_sized_header::<genl::Genlmsghdr>().unwrap();
        genl.cmd = genl::CtrlCmd::GETFAMILY as u8;
        genl.version = 1;

        nlh.put_u16(genl::CtrlAttr::FAMILY_ID as u16, genl::GENL_ID_CTRL).unwrap();
        if args.len() >= 2 {
            nlh.put_strz(genl::CtrlAttr::FAMILY_NAME as u16, &args[1]).unwrap();
        } else {
            *nlh.nlmsg_flags |= netlink::NLM_F_DUMP;
        }

        nl.send_nlmsg(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));

        if mnl::cl_run(&buf[0..nrecv], seq, portid, Some(data_cb()))
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno))
            == mnl::CbRet::STOP {
            break;
        }
    }
    let _ = nl.close();
}
