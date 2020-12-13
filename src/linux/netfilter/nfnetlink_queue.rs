use errno::Errno;
use { MsgVec, Attr, AttrTbl, Result };

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfqnlMsgTypes { // NFQNL_MSG_
    Packet		= 0,	// packet from kernel to userspace
    Verdict,			// verdict from userspace to kernel
    Config,			// connect to a particular queue
    VerdictBatch,	    	// batchv from userspace to kernel
    MAX
}
pub const NFQNL_MSG_PACKET: usize		= NfqnlMsgTypes::Packet as usize;
pub const NFQNL_MSG_VERDICT: usize		= NfqnlMsgTypes::Verdict as usize;
pub const NFQNL_MSG_CONFIG: usize		= NfqnlMsgTypes::Config as usize;
pub const NFQNL_MSG_VERDICT_BATCH: usize	= NfqnlMsgTypes::VerdictBatch as usize;
pub const NFQNL_MSG_MAX: usize			= NfqnlMsgTypes::MAX as usize;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NfqnlMsgPacketHdr {
    pub packet_id: u32,		// unique ID of packet in queue
    pub hw_protocol: u16,       // hw protocol (network order)
    pub hook: u8,               // netfilter hook
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfqnlMsgPacketHw {
    pub hw_addrlen: u16,
    pub _pad: u16,
    pub hw_addr: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfqnlMsgPacketTimestamp {
    pub sec: u64,
    pub usec: u64,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
pub enum NfqnlVlanAttr { // NFQA_VLAN_
    Unspec	= 0,
    Proto,		// __be16 skb vlan_proto
    Tci,		// __be16 skb htons(vlan_tci)
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="NfqnlAttrTypeTbl"]
pub enum NfqnlAttrType { // NFQA_
    Unspec		= 0,

    #[nla_type(NfqnlMsgPacketHdr, packet_hdr)]
    PacketHdr,

    VerdictHdr,		// nfqnl_msg_verdict_hdr
    Mark,		// __u32 nfmark
    Timestamp,		// nfqnl_msg_packet_timestamp
    IfindexIndev,	// __u32 ifindex
    IfindexOutdev,	// __u32 ifindex
    IfindexPhyindev,	// __u32 ifindex
    IfindexPhyoutdev,	// __u32 ifindex
    Hwaddr,		// nfqnl_msg_packet_hw
    Payload,		// opaque data payload
    Ct,			// nf_conntrack_netlink.h
    CtInfo,		// enum ip_conntrack_info
    CapLen,		// __u32 length of captured packet
    SkbInfo,		// __u32 skb meta information
    Exp,		// nf_conntrack_netlink.h
    Uid,		// __u32 sk uid
    Gid,		// __u32 sk gid
    Secctx,		// security context string
    Vlan,		// nested attribute: packet vlan info
    L2Hdr,		// full L2 header
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfqnlMsgVerdictHdr {
    pub verdict: u32,
    pub id: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfqnlMsgConfigCmds { // NFQNL_CFG_
    None	= 0,
    Bind,
    Unbind,
    PfBind,
    PfUnbind,
}
pub const NFQNL_CFG_CMD_NONE: u8	= NfqnlMsgConfigCmds::None as u8;
pub const NFQNL_CFG_CMD_BIND: u8	= NfqnlMsgConfigCmds::Bind as u8;
pub const NFQNL_CFG_CMD_UNBIND: u8	= NfqnlMsgConfigCmds::Unbind as u8;
pub const NFQNL_CFG_CMD_PF_BIND: u8	= NfqnlMsgConfigCmds::PfBind as u8;
pub const NFQNL_CFG_CMD_PF_UNBIND: u8	= NfqnlMsgConfigCmds::PfUnbind as u8;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NfqnlMsgConfigCmd {
    pub command: u8,	// nfqnl_msg_config_cmds
    pub _pad: u8,
    pub pf: u16,	// AF_xxx for PF_[UN]BIND
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfqnlConfigMode { // NFQNL_COPY_
    None	= 0,
    Meta,
    Packet,
}
pub const NFQNL_COPY_NONE: u8	= NfqnlConfigMode::None as u8;
pub const NFQNL_COPY_META: u8	= NfqnlConfigMode::Meta as u8;
pub const NFQNL_COPY_PACKET: u8	= NfqnlConfigMode::Packet as u8;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NfqnlMsgConfigParams {
    pub copy_range: u32,
    pub copy_mode: u8,		// enum nfqnl_config_mode
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
pub enum NfqnlAttrConfig { // NFQ_CFG_
    Unspec		= 0,
    Cmd,		// nfqnl_msg_config_cmd
    Params,		// nfqnl_msg_config_params
    QueueMaxlen,	// __u32
    Mask,		// identify which flags to change
    Flags,		// value of these flags (__u32)
    _MAX
}

// Flags for NFQA_CFG_FLAGS
pub const NFQA_CFG_F_FAIL_OPEN: u32	= 1 << 0;
pub const NFQA_CFG_F_CONNTRACK: u32	= 1 << 1;
pub const NFQA_CFG_F_GSO: u32		= 1 << 2;
pub const NFQA_CFG_F_UID_GID: u32	= 1 << 3;
pub const NFQA_CFG_F_SECCTX: u32	= 1 << 4;
pub const NFQA_CFG_F_MAX: u32		= 1 << 5;

// flags for NFQA_SKB_INFO
// packet appears to have wrong checksums, but they are ok
pub const NFQA_SKB_CSUMNOTREADY: u32 = 1 << 0;
// packet is GSO (i.e., exceeds device mtu)
pub const NFQA_SKB_GSO: u32 = 1 << 1;
// csum not validated (incoming device doesn't support hw checksum, etc.)
pub const NFQA_SKB_CSUM_NOTVERIFIED: u32 =  1 << 2;
