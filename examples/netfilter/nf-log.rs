use std::{env, mem, process, vec::Vec};

extern crate errno;
extern crate libc;
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

fn log_cb(nlh: &Msghdr) -> CbResult {
    let mut tb: [Option<&Attr>; linux::nfulnl_attr_type___NFULA_MAX as usize] =
        [None; linux::nfulnl_attr_type___NFULA_MAX as usize];
    let mut ph = &linux::nfulnl_msg_packet_hdr {
        hw_protocol: 0,
        hook: 0,
        _pad: 0,
    };
    let mut prefix = "";
    let mut mark = 0u32;

    nlh.parse(mem::size_of::<linux::nfgenmsg>(), parse_attr_cb(&mut tb))?;
    if let Some(attr) = tb[linux::nfulnl_attr_type_NFULA_PACKET_HDR as usize] {
        ph = attr.value_ref::<linux::nfulnl_msg_packet_hdr>()?;
    }
    if let Some(attr) = tb[linux::nfulnl_attr_type_NFULA_PREFIX as usize] {
        prefix = attr.str()?;
    }
    if let Some(attr) = tb[linux::nfulnl_attr_type_NFULA_MARK as usize] {
        mark = attr.value::<u32>()?;
    }

    println!(
        "log received (prefix=\"{}\" hw=0x{:04x} hook={} mark={})",
        prefix, ph.hw_protocol, ph.hook, mark
    );

    Ok(CbStatus::Ok)
}

fn nflog_build_cfg_pf_request(nlv: &mut MsgVec, command: u8) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((libc::NFNL_SUBSYS_ULOG << 8) | linux::nfulnl_msg_types_NFULNL_MSG_CONFIG as i32) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;

    let cmd = linux::nfulnl_msg_config_cmd { command: command };
    nlv.put(linux::nfulnl_attr_config_NFULA_CFG_CMD as u16, &cmd)?;

    Ok(())
}

fn nflog_build_cfg_request(nlv: &mut MsgVec, command: u8, qnum: u16) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((libc::NFNL_SUBSYS_ULOG << 8) | linux::nfulnl_msg_types_NFULNL_MSG_CONFIG as i32) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = qnum.to_be();

    let cmd = linux::nfulnl_msg_config_cmd { command: command };
    nlv.put(linux::nfulnl_attr_config_NFULA_CFG_CMD as u16, &cmd)?;

    Ok(())
}

fn nflog_build_cfg_params(nlv: &mut MsgVec, mode: u8, range: u32, qnum: u16) -> Result<(), Errno> {
    let mut nlh = nlv.put_header();
    nlh.nlmsg_type =
        ((libc::NFNL_SUBSYS_ULOG << 8) | linux::nfulnl_msg_types_NFULNL_MSG_CONFIG as i32) as u16;
    nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;

    let nfg = nlv.put_extra_header::<linux::nfgenmsg>()?;
    nfg.nfgen_family = libc::AF_UNSPEC as u8;
    nfg.version = libc::NFNETLINK_V0 as u8;
    nfg.res_id = qnum.to_be();

    let params = linux::nfulnl_msg_config_mode {
        copy_range: range.to_be(),
        copy_mode: mode,
        _pad: 0,
    };
    nlv.put(linux::nfulnl_attr_config_NFULA_CFG_MODE as u16, &params)?;

    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [queue_num]", args[0]);
        process::exit(libc::EXIT_FAILURE);
    }
    let qnum: u16 = args[1].trim().parse().expect("queue number required");

    let mut nl = Socket::open(libc::NETLINK_NETFILTER, 0)
        .map_err(|errno| format!("mnl_socket_open: {}", errno))?;

    nl.bind(0, mnl::SOCKET_AUTOPID)
        .map_err(|errno| format!("mnl_socket_bind: {}", errno))?;
    let portid = nl.portid();

    let mut nlv = MsgVec::new();
    nflog_build_cfg_pf_request(
        &mut nlv,
        linux::nfulnl_msg_config_cmds_NFULNL_CFG_CMD_PF_UNBIND as u8,
    )
    .map_err(|errno| format!("nflog_build_cfg_pf_request: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nflog_build_cfg_pf_request(
        &mut nlv,
        linux::nfulnl_msg_config_cmds_NFULNL_CFG_CMD_PF_BIND as u8,
    )
    .map_err(|errno| format!("nflog_build_cfg_pf_request: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nflog_build_cfg_request(
        &mut nlv,
        linux::nfulnl_msg_config_cmds_NFULNL_CFG_CMD_BIND as u8,
        qnum,
    )
    .map_err(|errno| format!("nflog_build_cfg_request: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    nlv.reset();
    nflog_build_cfg_params(&mut nlv, linux::NFULNL_COPY_PACKET as u8, 0xffff, qnum)
        .map_err(|errno| format!("nflog_build_cfg_params: {}", errno))?;

    nl.sendto(&nlv)
        .map_err(|errno| format!("mnl_socket_sendto: {}", errno))?;

    let mut buf = mnl::default_buffer();
    loop {
        let nrecv = nl
            .recvfrom(&mut buf)
            .map_err(|errno| format!("mnl_socket_recvfrom: {}", errno))?;
        mnl::cb_run(&buf[..nrecv], 0, portid, Some(log_cb))
            .map_err(|errno| format!("mnl_cb_run: {}", errno))?;
    }
}
