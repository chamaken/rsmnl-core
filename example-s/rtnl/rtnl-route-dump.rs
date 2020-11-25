use std:: {
    env,
    io,
    io::Write,
    mem::size_of,
    ffi::CStr,
    net::IpAddr,
    collections::HashMap,
};

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;
use libc::{ c_int, c_char, c_void, socklen_t };

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;

extern {
    // const char *inet_ntop(int af, const void *src,
    //                       char *dst, socklen_t size);
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t) -> *const c_char;
}
pub const INET_ADDRSTRLEN: usize = 16;
pub const INET6_ADDRSTRLEN: usize = 46;

trait AddrFamily {
    fn family(&self) -> c_int;
}
impl AddrFamily for libc::in_addr {
    fn family(&self) -> c_int { libc::AF_INET }
}
impl AddrFamily for libc::in6_addr {
    fn family(&self) -> c_int { libc::AF_INET6 }
}

fn _inet_ntoa<T: AddrFamily>(addr: &T) -> String {
    let mut buf = [0u8; INET6_ADDRSTRLEN];
    unsafe {
        let rs = inet_ntop(addr.family(), addr as *const _ as *const c_void,
                           buf.as_mut_ptr() as *mut c_char, INET6_ADDRSTRLEN as socklen_t);
        CStr::from_ptr(rs).to_string_lossy().into_owned()
    }
}

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_attr_cb2<'a, 'b>(tb: &'a mut HashMap<rtnetlink::RTA, &'b mnl::Attr>)
                         -> impl FnMut(&'b mnl::Attr) -> io::Result<mnl::CbStatus> + 'a {
    move |attr: &mnl::Attr| {
        // skip unsupported attribute in user-space
        if let Err(_) = attr.type_valid(rtnetlink::RTAX_MAX as u16) {
            return Ok(mnl::CbStatus::Ok);
        }

        if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
            println_stderr!("mnl_attr_validate: {}", errno);
            return Err(errno);
        }

        tb.insert(rtnetlink::RTA::from(attr.atype()), attr);
        Ok(mnl::CbStatus::Ok)
    }
}

fn attributes_show_ip<T>(tb: &[Option<&mnl::Attr>]) {
    tb.get(&rtnetlink::RTA::TABLE)
        .map(|attr| print!("table={} ", attr.u32()));
    tb.get(&rtnetlink::RTA::DST)
        .map(|attr| print!("dst={} ", IpAddr::from(attr.payload::<T>())));
    tb.get(&rtnetlink::RTA::SRC)
        .map(|attr| print!("src={} ", IpAddr::from(attr.payload::<T>())));
    tb.get(&rtnetlink::RTA::OIF)
        .map(|attr| print!("oif={} ", attr.u32()));
    tb.get(&rtnetlink::RTA::FLOW)
        .map(|attr| print!("flow={} ", attr.u32()));
    tb.get(&rtnetlink::RTA::PREFSRC)
        .map(|attr| print!("prefsrc={} ", IpAddr::from(attr.payload::<T>())));
    tb.get(&rtnetlink::RTA::GATEWAY)
        .map(|attr| print!("gw={} ", IpAddr::from(attr.payload::<T>())));
    tb.get(&rtnetlink::RTA::PRIORITY)
        .map(|attr| print!("prio={} ", attr.u32()));
    tb.get(&rtnetlink::RTA::METRICS)
        .map(|attr| {
            let mut tbx: [Option<&mnl::Attr>; rtnetlink::RTAX_MAX as usize + 1]
                = [None; rtnetlink::RTAX_MAX as usize + 1];
            let _ = attr.parse_nested(data_attr_cb2, &mut tbx);
            for i in 0..rtnetlink::RTAX_MAX as usize {
                tbx[i].map(|attr| print!("metrics[{}]={} ", i, attr.u32()));
            }
        });
}

fn data_ipv4_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> io::Result<mnl::CbStatus> {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(rtnetlink::RTA_MAX) {
        return Ok<mnl::CbStatus::Ok;
    }

    let atype = attr.atype();
    match atype {
        n if (n == rtnetlink::RTA_TABLE ||
              n == rtnetlink::RTA_DST ||
              n == rtnetlink::RTA_SRC ||
	      n == rtnetlink::RTA_DST ||
	      n == rtnetlink::RTA_SRC ||
	      n == rtnetlink::RTA_OIF ||
	      n == rtnetlink::RTA_FLOW ||
	      n == rtnetlink::RTA_PREFSRC ||
	      n == rtnetlink::RTA_GATEWAY ||
	      n == rtnetlink::RTA_PRIORITY) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbStatus::ERROR;
            }
        },
        n if n == rtnetlink::RTA_METRICS => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbStatus::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbStatus::Ok
}

fn data_ipv6_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbStatus {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(rtnetlink::RTA_MAX) {
        return mnl::CbStatus::Ok;
    }

    let atype = attr.atype();
    match atype {
	n if (n == rtnetlink::RTA_TABLE ||
	      n == rtnetlink::RTA_OIF ||
	      n == rtnetlink::RTA_FLOW ||
	      n == rtnetlink::RTA_PRIORITY) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbStatus::ERROR;
            }
        },
	n if (n == rtnetlink::RTA_DST ||
	      n == rtnetlink::RTA_SRC ||
	      n == rtnetlink::RTA_PREFSRC ||
	      n == rtnetlink::RTA_GATEWAY) => {
                if let Err(errno) = attr.validate2(mnl::AttrDataType::BINARY, size_of::<libc::in6_addr>()) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbStatus::ERROR;
                }
            },
        n if n == rtnetlink::RTA_METRICS => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbStatus::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbStatus::Ok
}

fn data_cb(nlh: mnl::Nlmsg, _: &mut Option<u8>) -> mnl::CbStatus {
    let rm = nlh.payload::<rtnetlink::Rtmsg>();

    // protocol family = AF_INET | AF_INET6 //
    print!("family={} ", rm.rtm_family);

    // destination CIDR, eg. 24 or 32 for IPv4
    print!("dst_len={} ", rm.rtm_dst_len);

    // source CIDR
    print!("src_len={} ", rm.rtm_src_len);

    // type of service (TOS), eg. 0
    print!("tos={} ", rm.rtm_tos);

    // table id:
    //	RT_TABLE_UNSPEC		= 0
    //
    //	... user defined values ...
    //
    //		RT_TABLE_COMPAT		= 252
    //		RT_TABLE_DEFAULT	= 253
    //		RT_TABLE_MAIN		= 254
    //		RT_TABLE_LOCAL		= 255
    //		RT_TABLE_MAX		= 0xFFFFFFFF
    //
    //	Synonimous attribute: RTA_TABLE.
    print!("table={} ", rm.rtm_table);

    // type:
    // 	RTN_UNSPEC	= 0
    // 	RTN_UNICAST	= 1
    // 	RTN_LOCAL	= 2
    // 	RTN_BROADCAST	= 3
    //	RTN_ANYCAST	= 4
    //	RTN_MULTICAST	= 5
    //	RTN_BLACKHOLE	= 6
    //	RTN_UNREACHABLE	= 7
    //	RTN_PROHIBIT	= 8
    //	RTN_THROW	= 9
    //	RTN_NAT		= 10
    //	RTN_XRESOLVE	= 11
    //	__RTN_MAX	= 12
    print!("type={} ", rm.rtm_type);

    // scope:
    // 	RT_SCOPE_UNIVERSE	= 0   : everywhere in the universe
    //
    //	... user defined values ...
    //
    //	 	RT_SCOPE_SITE		= 200
    //	 	RT_SCOPE_LINK		= 253 : destination attached to link
    //	 	RT_SCOPE_HOST		= 254 : local address
    //	 	RT_SCOPE_NOWHERE	= 255 : not existing destination
    print!("scope={} ", rm.rtm_scope);

    // protocol:
    // 	RTPROT_UNSPEC	= 0
    // 	RTPROT_REDIRECT = 1
    // 	RTPROT_KERNEL	= 2 : route installed by kernel
    // 	RTPROT_BOOT	= 3 : route installed during boot
    // 	RTPROT_STATIC	= 4 : route installed by administrator
    //
    // Values >= RTPROT_STATIC are not interpreted by kernel, they are
    // just user-defined.
    print!("proto={} ", rm.rtm_protocol);

    // flags:
    // 	RTM_F_NOTIFY	= 0x100: notify user of route change
    // 	RTM_F_CLONED	= 0x200: this route is cloned
    // 	RTM_F_EQUALIZE	= 0x400: Multipath equalizer: NI
    // 	RTM_F_PREFIX	= 0x800: Prefix addresses
    print!("flags={:x} ", rm.rtm_flags);

    let mut tb: [Option<&mnl::Attr>; rtnetlink::RTA_MAX as usize + 1]
        = [None; rtnetlink::RTA_MAX as usize + 1];
    match rm.rtm_family as c_int {
        libc::AF_INET => {
            let _ = nlh.parse(size_of::<rtnetlink::Rtmsg>(), data_ipv4_attr_cb, &mut tb);
            attributes_show_ip::<libc::in_addr>(&tb);
        },
        libc::AF_INET6 => {
            let _ = nlh.parse(size_of::<rtnetlink::Rtmsg>(), data_ipv6_attr_cb, &mut tb);
            attributes_show_ip::<libc::in6_addr>(&tb);
        },
        _ => unreachable!()
    }

    println!("");
    mnl::CbStatus::Ok
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("Usage: {} <inet|inet6>", args[0]);
    }

    let nl = mnl::Socket::open(netlink::Family::ROUTE)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = mnl::default_buf();
    let seq = time::now().to_timespec().sec as u32;
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_GETROUTE;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        *nlh.nlmsg_seq = seq;
        let rtm = nlh.put_sized_header::<rtnetlink::Rtmsg>().unwrap();
        if args[1] == "inet" {
            rtm.rtm_family = libc::AF_INET as u8;
        } else if args[1] == "inet6" {
            rtm.rtm_family = libc::AF_INET6 as u8;
        }
        nl.send_nlmsg(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        if mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb), &mut None)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno))
            == mnl::CbStatus::STOP {
            break;
        }
    }
    let _ = nl.close();
}
