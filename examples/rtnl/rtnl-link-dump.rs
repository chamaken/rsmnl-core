use std::{
    mem,
    time::{SystemTime, UNIX_EPOCH},
};

extern crate libc;

extern crate rsmnl as mnl;
use mnl::{Attr, CbResult, CbStatus, MsgVec, Msghdr, Socket};

mod linux_bindings;
use linux_bindings as linux;

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

fn data_cb(nlh: &Msghdr) -> CbResult {
    let ifm = nlh.payload::<linux::ifinfomsg>().unwrap();
    print!(
        "index={} type={} flags=0x{:x} family={} ",
        ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family
    );

    if ifm.ifi_flags & libc::IFF_RUNNING as u32 != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let mut tb: [Option<&Attr>; linux::__IFLA_MAX as usize] // IFLA_MAX as usize - 1
        = [None; linux::__IFLA_MAX as usize];
    nlh.parse(mem::size_of::<linux::ifinfomsg>(), data_attr_cb(&mut tb))
        .unwrap();

    if let Some(attr) = tb[libc::IFLA_MTU as usize] {
        print!("mtu={} ", attr.value_ref::<u32>()?);
    }
    if let Some(attr) = tb[libc::IFLA_IFNAME as usize] {
        print!("name={} ", attr.str_ref()?);
    }
    if let Some(attr) = tb[libc::IFLA_ADDRESS as usize] {
        let hwaddr = attr.bytes_ref();
        print!(
            "hwaddr={}",
            hwaddr
                .into_iter()
                .map(|&e| format!("{:02x}", e))
                .collect::<Vec<_>>()
                .join(":")
        );
    }
    println!("");
    Ok(CbStatus::Ok)
}

fn main() -> Result<(), String> {
    let mut nlv = MsgVec::new();
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type = libc::RTM_GETLINK;
    nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    nlh.nlmsg_seq = seq;
    let rt: &mut linux::rtgenmsg = nlv.put_extra_header().unwrap();
    rt.rtgen_family = libc::AF_PACKET as u8;

    let mut nl = Socket::open(libc::NETLINK_ROUTE, 0)
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

        match mnl::cb_run(&buf[..nrecv], seq, portid, Some(data_cb)) {
            Ok(CbStatus::Ok) => continue,
            Ok(CbStatus::Stop) => break,
            Err(errno) => return Err(format!("mnl_cb_run: {}", errno)),
        };
    }

    Ok(())
}
