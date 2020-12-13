use std:: {
    io,
    net::Ipv4Addr,
    os::unix::io::AsRawFd,
    time:: {
        Duration, SystemTime, UNIX_EPOCH
    },
    os::unix::io:: { FromRawFd, IntoRawFd },
};

extern crate libc;
extern crate errno;
use errno::Errno;

extern crate mio;
use mio:: {
    Poll, Interest, Token, Events,
    net::UdpSocket,
};

extern crate rsmnl as mnl;
use mnl:: {
    Msghdr, Socket, MsgVec, CbStatus, CbResult,
    linux:: {
        netlink,
        netfilter:: {
            nfnetlink as nfnl,
            nfnetlink:: { Nfgenmsg },
            nfnetlink_conntrack as nfct,
            nfnetlink_conntrack:: {
                CtattrType, CtattrTuple, CtattrIp,
                CtattrL4proto, CtattrProtoinfo, CtattrProtoinfoTcp,
            },
            nf_conntrack_common as nfct_common,
            nf_conntrack_tcp as nfct_tcp,
        },
    },
};

fn put_msg(nlv: &mut MsgVec, i: u16, seq: u32) -> Result<(), Errno> {
    let nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | nfct::IPCTNL_MSG_CT_NEW;
    nlh.nlmsg_flags =
        netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE
        | netlink::NLM_F_EXCL | netlink::NLM_F_ACK;
    nlh.nlmsg_seq = seq;

    let nfh = nlv.push_extra_header::<Nfgenmsg>()?;
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = nfnl::NFNETLINK_V0;
    nfh.res_id = 0;

    nlv.nest_start(CtattrType::TupleOrig)?;
    nlv.nest_start(CtattrTuple::Ip)?;
    nlv.push(CtattrIp::V4Src, &Ipv4Addr::new(1, 1, 1, 1))?;
    nlv.push(CtattrIp::V4Dst, &Ipv4Addr::new(2, 2, 2, 2))?;
    nlv.nest_end()?;

    nlv.nest_start(CtattrTuple::Proto)?;
    nlv.push(CtattrL4proto::Num, &(libc::IPPROTO_TCP as u8))?;
    nlv.push(CtattrL4proto::SrcPort, &u16::to_be(i))?;
    nlv.push(CtattrL4proto::DstPort, &u16::to_be(1025))?;
    nlv.nest_end()?;
    nlv.nest_end()?;

    nlv.nest_start(CtattrType::TupleReply)?;
    nlv.nest_start(CtattrTuple::Ip)?;
    nlv.push(CtattrIp::V4Src, &Ipv4Addr::new(2, 2, 2, 2))?;
    nlv.push(CtattrIp::V4Dst, &Ipv4Addr::new(1, 1, 1, 1))?;
    nlv.nest_end()?;

    nlv.nest_start(CtattrTuple::Proto)?;
    nlv.push(CtattrL4proto::Num, &(libc::IPPROTO_TCP as u8))?;
    nlv.push(CtattrL4proto::SrcPort, &u16::to_be(1025))?;
    nlv.push(CtattrL4proto::DstPort, &u16::to_be(i))?;
    nlv.nest_end()?;
    nlv.nest_end()?;

    nlv.nest_start(CtattrType::Protoinfo)?;
    nlv.nest_start(CtattrProtoinfo::Tcp)?;
    nlv.push(CtattrProtoinfoTcp::State, &nfct_tcp::TCP_CONNTRACK_SYN_SENT)?;
    nlv.nest_end()?;
    nlv.nest_end()?;

    nlv.push(CtattrType::Status, &u32::to_be(nfct_common::IPS_CONFIRMED))?;
    nlv.push(CtattrType::Timeout, &u32::to_be(1000))?;

    Ok(())
}

fn error_cb(nlh: &Msghdr) -> CbResult {
    let err = nlh.payload::<netlink::Nlmsgerr>()?;
    if err.error != 0 {
        println!("message with seq {} has failed: {}",
                 nlh.nlmsg_seq, io::Error::from_raw_os_error(-err.error));
    }
    Ok(CbStatus::Ok)
}

fn send_batch(nl: &mut Socket, nlv: &MsgVec, portid: u32) {
    nl.sendto(nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let mut poll = Poll::new().unwrap();
    let token = Token(nl.as_raw_fd() as usize);
    let mut listener = unsafe { UdpSocket::from_raw_fd(nl.as_raw_fd()) };
    poll.registry().register(&mut listener, token, Interest::READABLE).unwrap();
    let mut events = Events::with_capacity(256);

    let mut buf = mnl::default_buffer();
    let mut ctlcbs: [Option<fn(&Msghdr) -> CbResult>; libc::NLMSG_ERROR as usize + 1] = Default::default();
    ctlcbs[libc::NLMSG_ERROR as usize] = Some(error_cb);

    loop {
        poll.poll(&mut events, Some(Duration::new(0, 0))).unwrap();
        if events.is_empty() { // timed out
            listener.into_raw_fd();
            return;
        }

        loop {
            let nrecv = match nl.recvfrom(&mut buf) {
                Err(errno) => {
                    if errno.0 == libc::EAGAIN {
                        break;
                    } else {
                        panic!("mnl_socket_recvfrom: {}", errno);
                    }
                },
                Ok(n) => n,
            };
            mnl::cb_run2(&buf[0..nrecv], 0, portid, mnl::NOCB, &mut ctlcbs)
                .unwrap_or_else(|errno| panic!("mnl_cb_run2: {}", errno));
        }
    }
}

fn main() {
    let mut nl = Socket::open(netlink::Family::Netfilter, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    // mio restriction, can handle only edge-trigger
    nl.set_nonblock().unwrap();
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    let seq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    for i in 1024u16..65535 {
        put_msg(&mut nlv, i, seq + i as u32 - 1024).unwrap();
        // MsgVec has no size limit,
        // but ENOSPC returns at recvfrom if it's too big
        if nlv.len() < 40000 {
            continue;
        }
        send_batch(&mut nl, &mut nlv, portid);
        nlv.reset();
    }

    // check if there is any message in the batch not sent yet.
    if nlv.len() != 0 {
        send_batch(&mut nl, &mut nlv, portid);
    }
}
