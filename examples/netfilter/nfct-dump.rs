use std:: {
    mem,
    net:: { Ipv4Addr, Ipv6Addr },
    time:: { SystemTime, UNIX_EPOCH }
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl:: {
    Socket, MsgVec, Msghdr, Attr, CbResult, CbStatus,
};

mod linux_bindings;
use linux_bindings as linux;

// without validation,
//   parse_counters_cb
//   parse_ip_cb
//   parse_proto_cb
//   parse_tuple_cb
// does same thing.
fn data_attr_cb<'a, 'b>(tb: &'b mut [Option<&'a Attr<'a>>])
                -> impl FnMut(&'a Attr<'a>) -> CbResult + 'b {
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

fn print_counters(nest: &Attr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_counters___CTA_COUNTERS_MAX as usize]
        = [None; linux::ctattr_counters___CTA_COUNTERS_MAX as usize];

    nest.parse_nested(data_attr_cb(&mut tb))?;

    if let Some(attr) = tb[linux::ctattr_counters_CTA_COUNTERS_PACKETS as usize] {
        print!("packets={} ", u64::from_be(attr.value()?));
    }
    if let Some(attr) = tb[linux::ctattr_counters_CTA_COUNTERS_BYTES as usize] {
        print!("bytes={} ",  u64::from_be(attr.value()?));
    }

    Ok(CbStatus::Ok)
}

fn print_ip(nest: &Attr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_ip___CTA_IP_MAX as usize]
        = [None; linux::ctattr_ip___CTA_IP_MAX as usize];

    nest.parse_nested(data_attr_cb(&mut tb))?;

    if let Some(attr) = tb[linux::ctattr_ip_CTA_IP_V4_SRC as usize] {
        print!("src={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[linux::ctattr_ip_CTA_IP_V4_DST as usize] {
        print!("dst={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[linux::ctattr_ip_CTA_IP_V6_SRC as usize] {
        print!("src={} ", attr.value_ref::<Ipv6Addr>()?);
    }
    if let Some(attr) = tb[linux::ctattr_ip_CTA_IP_V6_DST as usize] {
        print!("dst={} ", attr.value_ref::<Ipv6Addr>()?);
    }

    Ok(CbStatus::Ok)
}

fn print_proto(nest: &Attr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_l4proto___CTA_PROTO_MAX as usize]
        = [None; linux::ctattr_l4proto___CTA_PROTO_MAX as usize];

    nest.parse_nested(data_attr_cb(&mut tb))?;

    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_NUM as usize] {
        print!("proto={} ", attr.value_ref::<u8>()?);
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_SRC_PORT as usize] {
        print!("sport={} ", u16::from_be(attr.value()?));
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_DST_PORT as usize] {
        print!("dport={} ", u16::from_be(attr.value()?));
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_ICMP_ID as usize] {
        print!("id={} ", u16::from_be(attr.value()?));
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_ICMP_TYPE as usize] {
        print!("type={} ", attr.value_ref::<u8>()?);
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_ICMP_CODE as usize] {
        print!("code={} ", attr.value_ref::<u8>()?);
    }

    Ok(CbStatus::Ok)
}

fn print_tuple(nest: &Attr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_tuple___CTA_TUPLE_MAX as usize]
        = [None; linux::ctattr_tuple___CTA_TUPLE_MAX as usize];

    nest.parse_nested(data_attr_cb(&mut tb))?;

    if let Some(attr) = tb[linux::ctattr_tuple_CTA_TUPLE_IP as usize] {
        print_ip(attr)?;
    }
    if let Some(attr) = tb[linux::ctattr_tuple_CTA_TUPLE_PROTO as usize] {
        print_proto(attr)?;
    }

    Ok(CbStatus::Ok)
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_type___CTA_MAX as usize]
        = [None; linux::ctattr_type___CTA_MAX as usize];

    nlh.parse(mem::size_of::<linux::nfgenmsg>(), data_attr_cb(&mut tb))?;

    if let Some(attr) = tb[linux::ctattr_type_CTA_TUPLE_ORIG as usize] {
        print_tuple(attr)?;
    }
    if let Some(attr) = tb[linux::ctattr_type_CTA_MARK as usize] {
        print!("mark={} ", u32::from_be(attr.value()?));
    }
    if let Some(attr) = tb[linux::ctattr_type_CTA_SECMARK as usize] {
        // obsolete?
        print!("secmark={} ", u32::from_be(attr.value()?));
    }
    if let Some(attr) = tb[linux::ctattr_type_CTA_COUNTERS_ORIG as usize] {
        print!("original ");
        print_counters(attr)?;
    }
    if let Some(attr) = tb[linux::ctattr_type_CTA_COUNTERS_REPLY as usize] {
        print!("reply ");
        print_counters(attr)?;
    }
    println!("");

    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = ((libc::NFNL_SUBSYS_CTNETLINK << 8) | linux::cntl_msg_types_IPCTNL_MSG_CT_GET as i32) as u16;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    nlh.nlmsg_seq = seq;
    let nfh = nlv.put_extra_header::<linux::nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = libc::NFNETLINK_V0 as u8;
    nfh.res_id = 0;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::dump_buffer();
    let portid = nl.portid();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;

        match mnl::cb_run(&buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        }
    }

    Ok(())
}
