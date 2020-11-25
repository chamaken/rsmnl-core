use std::io::Write;
use std::mem::size_of;
use std::time::{SystemTime, UNIX_EPOCH};

extern crate libc;
extern crate rsmnl as mnl;
use libc::AF_PACKET;

// extern crate enum_primitive;
// use enum_primitive::FromPrimitive;

use mnl::linux::{netlink, rtnetlink, if_link, ifh};

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_cb() -> dyn FnMut(&mnl::Nlmsg) -> mnl::Result<mnl::CbStatus> {
    Box::new(|nlh: &mnl::Nlmsg| {
        let ifm = nlh.payload::<rtnetlink::Ifinfomsg>().unwrap();
        print!("index={} type={} flags=0x{:x} family={} ",
               ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

        if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
            print!("[RUNNING] ");
        } else {
            print!("[NOT RUNNING] ");
        }

        let mut attrs = nlh.attrs(size_of::<rtnetlink::Ifinfomsg>())?;
        while let Some(attr) = attrs.next() {
	    // skip unsupported attribute in user-space
            if let Err(_) = attr.type_valid(if_link::IFLA_MAX) {
                continue;
            }

            let atype = if_link::AttrType::from(attr.atype());
            match atype {
                if_link::AttrType::MTU => {
                    if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                        println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                        return Err(errno);
                    }
                    print!("mtu={} ", attr.value::<u32>()?);
                },
                if_link::AttrType::IFNAME => {
                    if let Err(errno) = attr.validate(mnl::AttrDataType::String) {
                        println_stderr!("mnl_attr_validate - {:?}: {}", atype, errno);
                        return Err(errno);
                    }
                    print!("name={} ", attr.str_value()?);
                },
                _ => {},
            }
        }
        println!("");
        Ok(mnl::CbStatus::Ok)
    })
}

fn main() {
    let mut nl = mnl::Socket::open(netlink::Family::ROUTE, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    {
        let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_GETLINK;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        *nlh.nlmsg_seq = seq;
        let rt = nlh.put_extra_header::<rtnetlink::Rtgenmsg>().unwrap();
        rt.rtgen_family = AF_PACKET as u8;

        nl.sendto(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        match mnl::cb_run(&mut buf[..nrecv], seq, portid, Some(&mut data_cb())) {
            Ok(mnl::CbStatus::Ok) => continue,
            Ok(mnl::CbStatus::Stop) => break,
            Err(errno) => panic!("mnl::cb_run: {}", errno),
        }
    }
}
