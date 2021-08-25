use std::{env, mem, process, vec::Vec};

extern crate libc;

extern crate errno;
use errno::Errno;

extern crate rsmnl as mnl;
use mnl::{Attr, CbResult, CbStatus, MsgVec, Msghdr, Socket};

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

fn queue_cb(packet_id: &mut u32) -> impl FnMut(&Msghdr) -> CbResult + '_ {
    move |nlh: &Msghdr| {
        let mut tb: [Option<&Attr>; linux::nfqnl_attr_type___NFQA_MAX as usize] =
            [None; linux::nfqnl_attr_type___NFQA_MAX as usize];

        nlh.parse(mem::size_of::<linux::nfgenmsg>(), parse_attr_cb(&mut tb))?;
        if let Some(attr) = tb[linux::nfqnl_attr_type_NFQA_PACKET_HDR as usize] {
            let ph = attr.value_ref::<linux::nfqnl_msg_packet_hdr>()?;
            let id = u32::from_be(ph.packet_id);

            println!(
                "packet received (id={} hw=0x{:04x} hook={})",
                id,
                u16::from_be(ph.hw_protocol),
                ph.hook
            );
            *packet_id = id;
        }
        Ok(CbStatus::Ok)
    }
}

fn nfq_build_cfg_pf_request(nlv: &mut MsgVec, command: u8) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((linux::NFNL_SUBSYS_QUEUE << 8) | linux::nfqnl_msg_types_NFQNL_MSG_CONFIG) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;

    let cmd = linux::nfqnl_msg_config_cmd {
        command: command,
        pf: (libc::AF_INET as u16).to_be(),
        _pad: 0,
    };
    nlv.put(linux::nfqnl_attr_config_NFQA_CFG_CMD as u16, &cmd)?;

    Ok(())
}

fn nfq_build_cfg_request(nlv: &mut MsgVec, command: u8, queue_num: u16) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((libc::NFNL_SUBSYS_QUEUE << 8) | linux::nfqnl_msg_types_NFQNL_MSG_CONFIG as i32) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();

    let cmd = linux::nfqnl_msg_config_cmd {
        command: command,
        pf: (libc::AF_INET as u16).to_be(),
        _pad: 0,
    };
    nlv.put(linux::nfqnl_attr_config_NFQA_CFG_CMD as u16, &cmd)?;

    Ok(())
}

fn nfq_build_cfg_params(
    nlv: &mut MsgVec,
    mode: u8,
    range: u32,
    queue_num: u16,
) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((libc::NFNL_SUBSYS_QUEUE << 8) | linux::nfqnl_msg_types_NFQNL_MSG_CONFIG as i32) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();

    let params = linux::nfqnl_msg_config_params {
        copy_range: range.to_be(),
        copy_mode: mode,
    };
    nlv.put(linux::nfqnl_attr_config_NFQA_CFG_PARAMS as u16, &params)?;

    Ok(())
}

fn nfq_build_verdict(nlv: &mut MsgVec, id: u32, queue_num: u16, verd: u32) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((libc::NFNL_SUBSYS_QUEUE << 8) | linux::nfqnl_msg_types_NFQNL_MSG_VERDICT as i32) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;
    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();

    let vh = linux::nfqnl_msg_verdict_hdr {
        verdict: verd.to_be(),
        id: id.to_be(),
    };
    nlv.put(linux::nfqnl_attr_type_NFQA_VERDICT_HDR as u16, &vh)?;

    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [queue_num]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }
    let queue_num: u16 = args[1].trim().parse().expect("queue number required");

    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    nfq_build_cfg_pf_request(
        &mut nlv,
        linux::nfqnl_msg_config_cmds_NFQNL_CFG_CMD_PF_UNBIND as u8,
    )
    .map_err(|errno| format!("nfq_build_cfg_pf_request: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nfq_build_cfg_pf_request(
        &mut nlv,
        linux::nfqnl_msg_config_cmds_NFQNL_CFG_CMD_PF_BIND as u8,
    )
    .map_err(|errno| format!("nfq_build_cfg_pf_request: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nfq_build_cfg_request(
        &mut nlv,
        linux::nfqnl_msg_config_cmds_NFQNL_CFG_CMD_BIND as u8,
        queue_num,
    )
    .map_err(|errno| format!("nfq_build_cfg_request: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nfq_build_cfg_params(
        &mut nlv,
        linux::nfqnl_config_mode_NFQNL_COPY_PACKET as u8,
        0xFFFF,
        queue_num,
    )
    .map_err(|errno| format!("nfq_build_cfg_params: {}", errno))?;
    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    let mut id: u32 = 0;
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        mnl::cb_run(&buf[..nrecv], 0, portid, Some(queue_cb(&mut id)))
            .map_err(|errno| format!("mnl_cb_run: {}", errno))?;

        nlv.reset();
        nfq_build_verdict(&mut nlv, id, queue_num, libc::NF_ACCEPT as u32)
            .map_err(|errno| format!("nfq_build_verdict: {}", errno))?;
        nl.sendto(&nlv)
            .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;
    }
}
