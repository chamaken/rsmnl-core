use std::{
    io,
    net::Ipv4Addr,
    os::unix::io::AsRawFd,
    os::unix::io::{FromRawFd, IntoRawFd},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

extern crate errno;
extern crate libc;
use errno::Errno;

extern crate mio;
use mio::{net::UdpSocket, Events, Interest, Poll, Token};

extern crate rsmnl as mnl;
use mnl::{CbResult, CbStatus, MsgVec, Msghdr, Socket};

mod linux_bindings;
use linux_bindings as linux;

fn put_msg(nlv: &mut MsgVec, i: u16, seq: u32) -> Result<(), Errno> {
    let nlh = nlv.put_header();
    nlh.nlmsg_type =
        (libc::NFNL_SUBSYS_CTNETLINK << 8) as u16 | linux::cntl_msg_types_IPCTNL_MSG_CT_NEW as u16;
    nlh.nlmsg_flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK) as u16;
    nlh.nlmsg_seq = seq;

    let nfh = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = libc::NFNETLINK_V0 as u8;
    nfh.res_id = 0;

    nlv.nest_start(linux::ctattr_type_CTA_TUPLE_ORIG as u16)?;
    nlv.nest_start(linux::ctattr_tuple_CTA_TUPLE_IP as u16)?;
    nlv.put(
        linux::ctattr_ip_CTA_IP_V4_SRC as u16,
        &Ipv4Addr::new(1, 1, 1, 1),
    )?;
    nlv.put(
        linux::ctattr_ip_CTA_IP_V4_DST as u16,
        &Ipv4Addr::new(2, 2, 2, 2),
    )?;
    nlv.nest_end()?;

    nlv.nest_start(linux::ctattr_tuple_CTA_TUPLE_PROTO as u16)?;
    nlv.put(
        linux::ctattr_l4proto_CTA_PROTO_NUM as u16,
        &(libc::IPPROTO_TCP as u8),
    )?;
    nlv.put(
        linux::ctattr_l4proto_CTA_PROTO_SRC_PORT as u16,
        &u16::to_be(i),
    )?;
    nlv.put(
        linux::ctattr_l4proto_CTA_PROTO_DST_PORT as u16,
        &u16::to_be(1025),
    )?;
    nlv.nest_end()?;
    nlv.nest_end()?;

    nlv.nest_start(linux::ctattr_type_CTA_TUPLE_REPLY as u16)?;
    nlv.nest_start(linux::ctattr_tuple_CTA_TUPLE_IP as u16)?;
    nlv.put(
        linux::ctattr_ip_CTA_IP_V4_SRC as u16,
        &Ipv4Addr::new(2, 2, 2, 2),
    )?;
    nlv.put(
        linux::ctattr_ip_CTA_IP_V4_DST as u16,
        &Ipv4Addr::new(1, 1, 1, 1),
    )?;
    nlv.nest_end()?;

    nlv.nest_start(linux::ctattr_tuple_CTA_TUPLE_PROTO as u16)?;
    nlv.put(
        linux::ctattr_l4proto_CTA_PROTO_NUM as u16,
        &(libc::IPPROTO_TCP as u8),
    )?;
    nlv.put(
        linux::ctattr_l4proto_CTA_PROTO_SRC_PORT as u16,
        &u16::to_be(1025),
    )?;
    nlv.put(
        linux::ctattr_l4proto_CTA_PROTO_DST_PORT as u16,
        &u16::to_be(i),
    )?;
    nlv.nest_end()?;
    nlv.nest_end()?;

    nlv.nest_start(linux::ctattr_type_CTA_PROTOINFO as u16)?;
    nlv.nest_start(linux::ctattr_protoinfo_CTA_PROTOINFO_TCP as u16)?;
    nlv.put(
        linux::ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_STATE as u16,
        &linux::tcp_conntrack_TCP_CONNTRACK_SYN_SENT,
    )?;
    nlv.nest_end()?;
    nlv.nest_end()?;

    nlv.put(
        linux::ctattr_type_CTA_STATUS as u16,
        &u32::to_be(linux::ip_conntrack_status_IPS_CONFIRMED as u32),
    )?;
    nlv.put(linux::ctattr_type_CTA_TIMEOUT as u16, &u32::to_be(1000))?;

    Ok(())
}

fn error_cb(nlh: &Msghdr) -> CbResult {
    let err = nlh.payload::<libc::nlmsgerr>()?;
    if err.error != 0 {
        println!(
            "message with seq {} has failed: {}",
            nlh.nlmsg_seq,
            io::Error::from_raw_os_error(-err.error)
        );
    }
    Ok(CbStatus::Ok)
}

fn send_batch(nl: &mut Socket, nlv: &MsgVec, portid: u32) -> Result<(), String> {
    nl.sendto(nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut poll = Poll::new().unwrap();
    let token = Token(nl.as_raw_fd() as usize);
    let mut listener = unsafe { UdpSocket::from_raw_fd(nl.as_raw_fd()) };
    poll.registry()
        .register(&mut listener, token, Interest::READABLE)
        .unwrap();
    let mut events = Events::with_capacity(256);

    let mut buf = mnl::default_buffer();
    let mut ctlcbs: [Option<fn(&Msghdr) -> CbResult>; libc::NLMSG_ERROR as usize + 1] =
        Default::default();
    ctlcbs[libc::NLMSG_ERROR as usize] = Some(error_cb);

    loop {
        poll.poll(&mut events, Some(Duration::new(0, 0))).unwrap();
        if events.is_empty() {
            // timed out
            listener.into_raw_fd();
            return Ok(());
        }

        loop {
            let nrecv = match nl.recvfrom(&mut buf) {
                Err(errno) => {
                    if errno.0 == libc::EAGAIN {
                        break;
                    } else {
                        return Err(format!("mnl_socket_recvfrom: {}", errno));
                    }
                }
                Ok(n) => n,
            };
            mnl::cb_run2(&buf[0..nrecv], 0, portid, mnl::NOCB, &mut ctlcbs)
                .map_err(|errno| format!("mnl_cb_run2: {}", errno))?;
        }
    }
}

fn main() -> Result<(), String> {
    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;
    // mio restriction, can handle only edge-trigger
    nl.set_nonblock().unwrap();
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    for i in 1024u16..65535 {
        put_msg(&mut nlv, i, seq + i as u32 - 1024).unwrap();
        // MsgVec has no size limit,
        // but ENOSPC returns at recvfrom if it's too big
        if nlv.len() < 40000 {
            continue;
        }
        send_batch(&mut nl, &mut nlv, portid)?;
        nlv.reset();
    }

    // check if there is any message in the batch not sent yet.
    if nlv.len() != 0 {
        send_batch(&mut nl, &mut nlv, portid)?;
    }

    Ok(())
}
