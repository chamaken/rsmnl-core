use std:: {
    env,
    mem,
    vec::Vec,
};

extern crate libc;
extern crate rsmnl as mnl;

use mnl:: {
    Socket, MsgVec, Msghdr, AttrTbl, Result, CbResult, CbStatus,
    linux:: {
        netlink:: { self, Family },
        netfilter:: {
            nfnetlink as nfnl,
            nfnetlink:: { Nfgenmsg, },
            nfnetlink_log as nful,
            nfnetlink_log:: {
                NfulnlMsgTypes, NfulnlMsgConfigCmd, NfulnlMsgConfigCmds,
                NfulnlAttrConfig, NfulnlMsgPacketHdr, NfulnlAttrTypeTbl,
                NfulnlMsgConfigMode,
            },
        },
    },
};

fn log_cb(nlh: &Msghdr) -> CbResult {

    let mut ph = &NfulnlMsgPacketHdr { hw_protocol: 0, hook: 0, _pad: 0 };
    let mut prefix = "";
    let mut mark: u32 = 0;

    let tb = NfulnlAttrTypeTbl::from_nlmsg(mem::size_of::<Nfgenmsg>(), nlh)?;
    tb.packet_hdr()?.map(|x| ph = x);
    tb.prefix()?.map(|x| prefix = x);
    tb.mark()?.map(|x| mark = *x);

    println!("log received (prefix=\"{}\", hw=0x{:x}, hook={}, mark={})",
             prefix, ph.hw_protocol, ph.hook, mark);

    Ok(CbStatus::Ok)
}

fn nflog_build_cfg_pf_request(nlv: &mut MsgVec, command: u8) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | NfulnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlv.push_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = nfnl::NFNETLINK_V0;

    let cmd = NfulnlMsgConfigCmd { command: command };
    // nlv.push(NfulnlAttrConfig::Cmd, &cmd)?;
    NfulnlAttrConfig::push_cmd(nlv, &cmd)?;

    Ok(())
}

fn nflog_build_cfg_request(nlv: &mut MsgVec, command: u8, qnum: u16) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | NfulnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlv.push_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = qnum.to_be();

    let cmd = nful::NfulnlMsgConfigCmd { command: command };
    nlv.push(NfulnlAttrConfig::Cmd, &cmd)?;

    Ok(())
}

fn nflog_build_cfg_params(nlv: &mut MsgVec, mode: u8, range: u32, qnum: u16) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | NfulnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlv.push_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = qnum.to_be();

    let params = NfulnlMsgConfigMode {
        copy_range: range.to_be(),
        copy_mode: mode,
        _pad: 0,
    };
    nlv.push(NfulnlAttrConfig::Mode, &params)?;

    Ok(())
}


fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: {} [queue_num]", args[0]);
    }
    let qnum: u16 = args[1].trim().parse().expect("queue number required");

    let mut nl = Socket::open(Family::Netfilter, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    nflog_build_cfg_pf_request(&mut nlv, NfulnlMsgConfigCmds::PfUnbind as u8).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    nflog_build_cfg_pf_request(&mut nlv, NfulnlMsgConfigCmds::PfBind as u8).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    nflog_build_cfg_request(&mut nlv, NfulnlMsgConfigCmds::Bind as u8, qnum).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    nflog_build_cfg_params(&mut nlv, nful::COPY_PACKET, 0xffff, qnum).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        mnl::cb_run(&buf[..nrecv], 0, portid, Some(log_cb))
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));
    }
}
