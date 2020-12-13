use errno::Errno;
use { MsgVec, Attr, AttrTbl, Result };
use linux::netfilter::nfnetlink_conntrack::CtattrTypeTbl;

// This file describes the netlink messages (i.e. 'protocol packets'),
// and not any kind of function definitions.  It is shared between kernel and
// userspace.  Don't put kernel specific stuff in here

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfulnlMsgTypes { // NFULNL_MSG_
    Packet 	= 0,	// packet from kernel to userspace
    Config,		// connect to a particular queue
    MAX,
}
pub const NFULNL_MSG_PACKET: u16	= NfulnlMsgTypes::Packet as u16;
pub const NFULNL_MSG_CONFIG: u16	= NfulnlMsgTypes::Config as u16;
pub const NFULNL_MSG_MAX: u16		= NfulnlMsgTypes::MAX as u16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfulnlMsgPacketHdr {
    pub hw_protocol: u16,	// hw protocol (network order)
    pub hook: u8,		// netfilter hook
    pub _pad: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfulnlMsgPacketHw {
    pub hw_addrlen: u16,
    pub _pad: u16,
    pub hw_addr: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfulnlMsgPacketTimestamp {
    pub sec: u64,
    pub usec: u64,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="NfulnlVlanAttrTbl"]
pub enum NfulnlVlanAttr {
    Unspec,

    #[nla_type(u16, proto)]
    Proto,		/* __be16 skb vlan_proto */

    #[nla_type(u16, tci)]
    Tci,		/* __be16 skb htons(vlan_tci) */

    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="NfulnlAttrTypeTbl"]
pub enum NfulnlAttrType {
    UNSPEC		= 0,

    #[nla_type(NfulnlMsgPacketHdr, packet_hdr)]
    PacketHdr,

    #[nla_type(u32, mark)]
    Mark,			// __u32 nfmark

    #[nla_type(NfulnlMsgPacketTimestamp, timestamp)]
    Timestamp,			// nfulnl_msg_packet_timestamp

    #[nla_type(u32, ifindex_indev)]
    IfindexIndev,		// __u32 ifindex

    #[nla_type(u32, ifindex_outdev)]
    IfindexOutdev,		// __u32 ifindex

    #[nla_type(u32, ifindex_physindev)]
    IfindexPhysindev,		// __u32 ifindex

    #[nla_type(u32, ifindex_physoutdev)]
    IfindexPhysoutdev,		// __u32 ifindex

    #[nla_type(NfulnlMsgPacketHw, hwaddr)]
    Hwaddr,			// nfulnl_msg_packet_hw

    #[nla_type(bytes, payload)]
    Payload,			// opaque data payload

    #[nla_type(str, prefix)]
    Prefix,			// string prefix

    #[nla_type(u32, uid)]
    Uid,			// user id of socket

    #[nla_type(u32, seq)]
    Seq,			// instance-local sequence number

    #[nla_type(u32, seq_global)]
    SeqGlobal,			// global sequence number

    #[nla_type(u32, gid)]
    Gid,			// group id of socket

    #[nla_type(u16, hwtype)]
    Hwtype,			// hardware type

    #[nla_type(bytes, hwheader)]
    Hwheader,			// hardware header

    #[nla_type(u16, hwlen)]
    Hwlen,			// hardware header length

    #[nla_nest(CtattrTypeTbl, ct)]
    Ct,				// nf_conntrack_netlink.h

    #[nla_type(u32, ct_info)]
    CtInfo,			// enum ip_conntrack_info

    #[nla_nest(NfulnlVlanAttrTbl, vlan)]
    Vlan,			// nested attribute: packet vlan info

    #[nla_type(bytes, l2hdr)]
    L2Hdr,			// full L2 header

    _MAX
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfulnlMsgConfigCmds { // NFULNL_CFG_CMD_
    None	= 0,
    Bind,
    Unbind,
    PfBind,
    PfUnbind,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NfulnlMsgConfigCmd {
    pub command: u8,	// nfulnl_msg_config_cmds
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NfulnlMsgConfigMode {
    pub copy_range: u32,
    pub copy_mode: u8,
    pub _pad: u8,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
pub enum NfulnlAttrConfig {
    Unspec	= 0,

    #[nla_type(NfulnlMsgConfigCmd, cmd)]
    Cmd,		// nfulnl_msg_config_cmd

    #[nla_type(NfulnlMsgConfigMode, mode)]
    Mode,		// nfulnl_msg_config_mode

    Nlbufsiz,		// __u32 buffer size
    Timeout,		// __u32 in 1/100 s
    Qthresh,		// __u32
    Flags,		// __u16
    _MAX
}

pub const COPY_NONE: u8		= 0x00;
pub const COPY_META: u8		= 0x01;
pub const COPY_PACKET: u8	= 0x02;
// 0xff is reserved, don't use it for new copy modes.

pub const CFG_F_SEQ: u16	= 0x0001;
pub const CFG_F_SEQ_GLOBAL: u16	= 0x0002;
pub const CFG_F_CONNTRACK: u16	= 0x0004;
