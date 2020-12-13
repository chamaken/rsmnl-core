use std:: {
    env,
    mem,
    vec::Vec,
};

extern crate libc;
extern crate rsmnl as mnl;

use mnl:: {
    MsgVec, Msghdr, AttrTbl, Result, Socket, CbStatus, CbResult,
    linux:: {
        netlink:: { self, Family },
        netfilter as nf,
        netfilter:: {
            nfnetlink as nfnl,
            nfnetlink:: { Nfgenmsg, },
            nfnetlink_queue:: {
                NfqnlAttrType, NfqnlAttrTypeTbl,
                NfqnlMsgTypes, NfqnlMsgConfigCmd, NfqnlMsgConfigCmds,
                NfqnlAttrConfig, NfqnlConfigMode, NfqnlMsgConfigParams,
                NfqnlMsgVerdictHdr,
            },
        },
    },
};

fn queue_cb(packet_id: &mut u32) -> impl FnMut(&Msghdr) -> CbResult + '_
{
    move |nlh: &Msghdr| {
        let tb = NfqnlAttrTypeTbl::from_nlmsg(mem::size_of::<nfnl::Nfgenmsg>(), nlh)?;
        tb.packet_hdr()?.map(|ph| {
            *packet_id = u32::from_be(ph.packet_id);
            println!("packet received (id={} hw=0x{:04x} hook={})",
                     packet_id, u16::from_be(ph.hw_protocol), ph.hook);
        });
        Ok(CbStatus::Ok)
    }
}

fn nfq_build_cfg_pf_request(nlv: &mut MsgVec, command: u8) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlv.push_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;

    let cmd = NfqnlMsgConfigCmd {
        command: command,
        pf: libc::AF_INET.to_be() as u16,
        ..Default::default()
    };
    nlv.push(NfqnlAttrConfig::Cmd, &cmd)?;

    Ok(())
}

fn nfq_build_cfg_request(nlv: &mut MsgVec, command: u8, queue_num: u16) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlv.push_extra_header::<nfnl::Nfgenmsg>()?;
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = queue_num.to_be();

    let cmd = NfqnlMsgConfigCmd {
        command: command,
        pf: libc::AF_INET.to_be() as u16,
        ..Default::default()
    };
    nlv.push(NfqnlAttrConfig::Cmd, &cmd)?;

    Ok(())
}

fn nfq_build_cfg_params(nlv: &mut MsgVec, mode: u8, range: u32, queue_num: u16) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Config as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlv.push_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = queue_num.to_be();

    let params = NfqnlMsgConfigParams { copy_range: range.to_be(), copy_mode: mode };
    nlv.push(NfqnlAttrConfig::Params, &params)?;

    Ok(())
}

fn nfq_build_verdict(nlv: &mut MsgVec, id: u32, queue_num: u16, verd: u32) -> Result<()> {
    let mut nlh = nlv.push_header();
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | NfqnlMsgTypes::Verdict as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;
    let nfg = nlv.push_extra_header::<Nfgenmsg>()?;
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = queue_num.to_be();

    let vh = NfqnlMsgVerdictHdr { verdict: verd.to_be(), id: id.to_be() };
    nlv.push(NfqnlAttrType::VerdictHdr, &vh)?;

    Ok(())
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: {} [queue_num]", args[0]);
    }
    let queue_num: u16 = args[1].trim().parse().expect("queue number required");

    let mut nl = Socket::open(Family::Netfilter, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    nfq_build_cfg_pf_request(&mut nlv, NfqnlMsgConfigCmds::PfUnbind as u8).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    nfq_build_cfg_pf_request(&mut nlv, NfqnlMsgConfigCmds::PfBind as u8).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    nfq_build_cfg_request(&mut nlv, NfqnlMsgConfigCmds::Bind as u8, queue_num).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    nfq_build_cfg_params(&mut nlv, NfqnlConfigMode::Packet as u8, 0xFFFF, queue_num).unwrap();
    nl.sendto(&nlv)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    nlv.reset();

    let mut buf = mnl::default_buffer();
    let mut id: u32 = 0;
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        mnl::cb_run(&buf[..nrecv], 0, portid, Some(queue_cb(&mut id)))
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));

        nfq_build_verdict(&mut nlv, id, queue_num, nf::NF_ACCEPT).unwrap();
        nl.sendto(&nlv)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
        nlv.reset();
    }
}
