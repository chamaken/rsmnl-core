use std::{mem, net::Ipv4Addr};

extern crate libc;
extern crate rsmnl as mnl;

use mnl::{Attr, CbResult, CbStatus, Msghdr, Socket};

mod linux_bindings;
use linux_bindings as linux;

fn parse_attr_cb<'a, 'b>(
    tb: &'b mut [Option<&'a Attr<'a>>],
) -> impl FnMut(&'a Attr<'a>) -> CbResult + 'b {
    move |attr: &Attr| {
        let atype = attr.atype() as usize;
        if atype >= tb.len() {
            return Ok(CbStatus::Ok);
        }
        tb[atype] = Some(attr);

        Ok(CbStatus::Ok)
    }
}

fn print_ip(nest: &Attr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_ip___CTA_IP_MAX as usize] =
        [None; linux::ctattr_ip___CTA_IP_MAX as usize];

    nest.parse_nested(parse_attr_cb(&mut tb))?;
    if let Some(attr) = tb[linux::ctattr_ip_CTA_IP_V4_SRC as usize] {
        print!("src={} ", attr.value_ref::<Ipv4Addr>()?);
    }
    if let Some(attr) = tb[linux::ctattr_ip_CTA_IP_V4_DST as usize] {
        print!("dst={} ", attr.value_ref::<Ipv4Addr>()?);
    }

    Ok(CbStatus::Ok)
}

fn print_proto(nest: &Attr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::ctattr_l4proto___CTA_PROTO_MAX as usize] =
        [None; linux::ctattr_l4proto___CTA_PROTO_MAX as usize];

    nest.parse_nested(parse_attr_cb(&mut tb))?;
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_NUM as usize] {
        print!("proto={} ", attr.value_ref::<u8>()?);
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_SRC_PORT as usize] {
        print!("sport={} ", u16::from_be(attr.value::<u16>()?));
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_DST_PORT as usize] {
        print!("dport={} ", u16::from_be(attr.value::<u16>()?));
    }
    if let Some(attr) = tb[linux::ctattr_l4proto_CTA_PROTO_ICMP_ID as usize] {
        print!("id={} ", u16::from_be(attr.value::<u16>()?));
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
    let mut tb: [Option<&Attr>; linux::ctattr_tuple___CTA_TUPLE_MAX as usize] =
        [None; linux::ctattr_tuple___CTA_TUPLE_MAX as usize];

    nest.parse_nested(parse_attr_cb(&mut tb))?;
    if let Some(attr) = tb[linux::ctattr_tuple_CTA_TUPLE_IP as usize] {
        print_ip(attr)?;
    }
    if let Some(attr) = tb[linux::ctattr_tuple_CTA_TUPLE_PROTO as usize] {
        print_proto(attr)?;
    }

    Ok(CbStatus::Ok)
}

fn data_cb(nlh: &Msghdr) -> CbResult {
    match nlh.nlmsg_type & 0xFF {
        t if t == linux::cntl_msg_types_IPCTNL_MSG_CT_NEW as u16 => {
            if nlh.nlmsg_flags & (libc::NLM_F_CREATE as u16 | libc::NLM_F_EXCL as u16) != 0 {
                print!("{:9} ", "[NEW] ");
            } else {
                print!("{:9} ", "[UPDATE] ");
            }
        }
        t if t == linux::cntl_msg_types_IPCTNL_MSG_CT_DELETE as u16 => {
            print!("{:9} ", "[DESTROY] ")
        }
        _ => {}
    }

    let mut tb: [Option<&Attr>; linux::ctattr_type___CTA_MAX as usize] =
        [None; linux::ctattr_type___CTA_MAX as usize];

    nlh.parse(mem::size_of::<linux::nfgenmsg>(), parse_attr_cb(&mut tb))?;
    if let Some(attr) = tb[linux::ctattr_type_CTA_TUPLE_ORIG as usize] {
        print_tuple(attr)?;
    }
    if let Some(attr) = tb[linux::ctattr_type_CTA_MARK as usize] {
        print!("mark={} ", u32::from_be(attr.value::<u32>()?));
    }
    if let Some(attr) = tb[linux::ctattr_type_CTA_SECMARK as usize] {
        print!("secmark={} ", u32::from_be(attr.value::<u32>()?));
    }
    println!();
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    nl.bind(
        linux::NF_NETLINK_CONNTRACK_NEW
            | linux::NF_NETLINK_CONNTRACK_UPDATE
            | linux::NF_NETLINK_CONNTRACK_DESTROY,
        mnl::SOCKET_AUTOPID,
    )
    .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        mnl::cb_run(&buf[..nrecv], 0, 0, Some(data_cb))
            .map_err(|errno| format!("mnl_cb_run: {}", errno))?;
    }
}
