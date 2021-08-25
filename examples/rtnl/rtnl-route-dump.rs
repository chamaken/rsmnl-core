use std:: {
    env,
    mem,
    net::{ Ipv4Addr, Ipv6Addr },
    process,
    time::{ SystemTime, UNIX_EPOCH }
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl:: {
    Socket, Msghdr, MsgVec, CbStatus, CbResult, Attr,
};

mod linux_bindings;
use linux_bindings as linux;

fn data_attr_cb2<'a, 'b>(tb: &'b mut[Option<&'a Attr<'a>>])
                        -> impl FnMut(&'a Attr) -> CbResult + 'b {
    move |attr: &Attr| {
        let atype = attr.atype() as usize;
        // skip unsupported attribute in user-space
        if atype >= tb.len() {
            return Ok(CbStatus::Ok)
        }

        tb[atype] = Some(attr);
        Ok(CbStatus::Ok)
    }
}

fn attributes_show_ipv4(tb: &[Option<&Attr>]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(attr) = tb[libc::RTA_TABLE as usize] {
        print!("table={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_DST as usize] {
        print!("dst={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_SRC as usize] {
        print!("src={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_OIF as usize] {
        print!("oif={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_FLOW as usize] {
        print!("flow={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_PREFSRC as usize] {
        print!("prefsrc={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_GATEWAY as usize] {
        print!("gw={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_PRIORITY as usize] {
        print!("prio={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_METRICS as usize] {
        let mut tbx: [Option<&Attr>; linux::__RTAX_MAX as usize]
            = [None; linux::__RTAX_MAX as usize];
        attr.parse_nested(data_attr_cb2(&mut tbx))?;
        for i in 0..linux::__RTAX_MAX - 1 {
            if let Some(a) = tbx[i as usize] {
                print!("metrics[{}]={} ", i, a.value_ref::<u32>()?);
            }
        }
    }

    Ok(())
}

fn attributes_show_ipv6(tb: &[Option<&Attr>]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(attr) = tb[libc::RTA_TABLE as usize] {
        print!("table={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_DST as usize] {
        print!("dst={} ", attr.value_ref::<Ipv6Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_SRC as usize] {
        print!("src={} ", attr.value_ref::<Ipv6Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_OIF as usize] {
        print!("oif={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_FLOW as usize] {
        print!("flow={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_PREFSRC as usize] {
        print!("prefsrc={} ", attr.value_ref::<Ipv6Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_GATEWAY as usize] {
        print!("gw={} ", attr.value_ref::<Ipv6Addr>()?);
    }
    if let Some(attr) = tb[libc::RTA_PRIORITY as usize] {
        print!("prio={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::RTA_METRICS as usize] {
        let mut tbx: [Option<&Attr>; linux::__RTAX_MAX as usize]
            = [None; linux::__RTAX_MAX as usize];
        attr.parse_nested(data_attr_cb2(&mut tbx))?;
        for i in 0..linux::__RTAX_MAX - 1 {
            if let Some(a) = tbx[i as usize] {
                print!("metrics[{}]={} ", i, a.value_ref::<u32>()?);
            }
        }
    }
    
    Ok(())
}
                           
fn data_cb(nlh: &Msghdr) -> CbResult {
    let rm = nlh.payload::<linux::rtmsg>()?;

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

    let mut tb: [Option<&Attr>; linux::rtattr_type_t___RTA_MAX as usize]
        = [None; linux::rtattr_type_t___RTA_MAX as usize];
    nlh.parse(mem::size_of::<linux::rtmsg>(), data_attr_cb2(&mut tb))?;
    match rm.rtm_family as i32 {
        libc::AF_INET => attributes_show_ipv4(&mut tb)?,
        libc::AF_INET6 => attributes_show_ipv6(&mut tb)?,
        i @ _ => print!("unknown address family: {}", i),
    }
    println!("");

    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <inet|inet6>", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_GETROUTE;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    nlh.nlmsg_seq = seq;

    let rtm = nlv.put_extra_header::<linux::rtmsg>().unwrap();
    if args[1] == "inet" {
        rtm.rtm_family = libc::AF_INET as u8;
    } else if args[1] == "inet6" {
        rtm.rtm_family = libc::AF_INET6 as u8;
    }

    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::dump_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        match mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
