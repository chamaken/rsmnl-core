use errno::Errno;
use std::net::{ Ipv4Addr, Ipv6Addr };
use { MsgVec, Attr, AttrTbl, Result };

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtnlMsgTypes { // IPCTNL_MSG_
    New			= 0,
    Get,
    Delete,
    GetCtrzero,
    GetStatsCpu,
    GetStats,
    GetDying,
    GetUnconfirmed,
    MAX
}
pub const IPCTNL_MSG_CT_NEW: u16		= CtnlMsgTypes::New as u16;
pub const IPCTNL_MSG_CT_GET: u16		= CtnlMsgTypes::Get as u16;
pub const IPCTNL_MSG_CT_DELETE: u16		= CtnlMsgTypes::Delete as u16;
pub const IPCTNL_MSG_CT_GET_CTRZERO: u16	= CtnlMsgTypes::GetCtrzero as u16;
pub const IPCTNL_MSG_CT_GET_STATS_CPU: u16	= CtnlMsgTypes::GetStatsCpu as u16;
pub const IPCTNL_MSG_CT_GET_STATS: u16		= CtnlMsgTypes::GetStats as u16;
pub const IPCTNL_MSG_CT_GET_DYING: u16		= CtnlMsgTypes::GetDying as u16;
pub const IPCTNL_MSG_CT_GET_UNCONFIRMED: u16	= CtnlMsgTypes::GetUnconfirmed as u16;
pub const IPCTNL_MSG_MAX: u16			= CtnlMsgTypes::MAX as u16;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtnlExpMsgTypes { // IPCTNL_MSG_EXP_
    New			= 0,
    Get,
    Delete,
    GetStatsCpu,
    MAX
}
pub const IPCTNL_MSG_EXP_NEW: u16		= CtnlExpMsgTypes::New as u16;
pub const IPCTNL_MSG_EXP_GET: u16		= CtnlExpMsgTypes::Get as u16;
pub const IPCTNL_MSG_EXP_DELETE: u16		= CtnlExpMsgTypes::Delete as u16;
pub const IPCTNL_MSG_EXP_GET_STATS_CPU: u16	= CtnlExpMsgTypes::GetStatsCpu as u16;
pub const IPCTNL_MSG_EXP_MAX: u16		= CtnlExpMsgTypes::MAX as u16;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrTypeTbl"]
pub enum CtattrType { // CTA_
    Unspec		= 0,

    #[nla_nest(CtattrTupleTbl, tuple_orig)]
    TupleOrig,

    #[nla_nest(CtattrTupleTbl, tuple_reply)]
    TupleReply,

    #[nla_type(u32, status)]	// big endian
    Status,

    #[nla_nest(CtattrProtoinfoTbl, protoinfo)]
    Protoinfo,

    Help,
    NatSrc,

    #[nla_type(u32, timeout)] // big endian
    Timeout,

    #[nla_type(u32, mark)]
    Mark,

    #[nla_nest(CtattrCountersTbl, counters_orig)]
    CountersOrig,

    CountersReply,
    Use,
    Id,
    NatDst,
    TupleMaster,
    SeqAdjOrig,
    SeqAdjReply,
    Secmark,		// obsolete
    Zone,
    Secctx,
    Timestamp,
    #[nla_type(u32, mark_mask)]
    MarkMask,
    Labels,
    LabelsMask,
    Synproxy,
    Filter,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrTupleTbl"]
pub enum CtattrTuple { // CTA_TUPLE_
    Unspec	= 0,

    #[nla_nest(CtattrIpTbl, ip)]
    Ip,

    #[nla_nest(CtattrL4ProtoTbl, proto)]
    Proto,

    Zone,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrIpTbl"]
pub enum CtattrIp { // CTA_IP_
    Unspec	= 0,

    #[nla_type(Ipv4Addr, v4src)]
    V4Src,

    #[nla_type(Ipv4Addr, v4dst)]
    V4Dst,

    #[nla_type(Ipv6Addr, v6src)]
    V6Src,

    #[nla_type(Ipv6Addr, v6dst)]
    V6Dst,

    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrL4ProtoTbl"]
pub enum CtattrL4proto { // CTA_PROTO_
    Unspec	= 0,

    #[nla_type(u8, num)]
    Num,

    #[nla_type(u16, src_port)] // big endian
    SrcPort,

    #[nla_type(u16, dst_port)] // big endian
    DstPort,

    IcmpId,
    IcmpType,
    IcmpCode,
    Icmpv6Id,
    Icmpv6Type,
    Icmpv6Code,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoTbl"]
pub enum CtattrProtoinfo { // CTA_PROTOINFO_
    Unspec	= 0,

    #[nla_nest(CtattrProtoinfoTcpTbl, tcp)]
    Tcp,
    Dccp,
    Sctp,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoTcpTbl"]
pub enum CtattrProtoinfoTcp { // CTA_PROTOINFO_TCP_
    Unspec		= 0,

    // #[nla_type(
    State,
    WscaleOriginal,
    WscaleReply,
    FlagsOriginal,
    FlagsReply,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoDccpTbl"]
pub enum CtattrProtoinfoDccp { // CTA_PROTOINFO_DCCP_
    Unspec		= 0,
    State,
    Role,
    HandshakeSeq,
    Pad,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoSctpTbl"]
pub enum CtattrProtoinfoSctp { // CTA_PROTOINFO_SCTP_
    Unspec		= 0,
    State,
    VtagOriginal,
    VtagReply,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrCountersTbl"]
pub enum CtattrCounters { // CTA_COUNTERS_
    Unspec	= 0,
    #[nla_type(u64, packets)]
    Packets,	// 64bit counters
    #[nla_type(u64, bytes)]
    Bytes,	// 64bit counters
    Packets32,	// old 32bit counters, unused, XXX: 32Packets
    Bytes32,	// old 32bit counters, unused, XXX: 32Bytes
    Pad,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrTstampTbl"]
pub enum CtattrTstamp { // CTA_TIMESTAMP_
    Unspec	= 0,
    Start	= 1,
    Stop	= 2,
    Pad		= 3,
    _MAX	= 4,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrNatTbl"]
pub enum CtattrNat { // CTA_NAT_
    Unspec	= 0,
    V4Minip,
    V4Maxip,
    Proto,
    V6Minip,
    V6Maxip,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtonatTbl"]
pub enum CtattrProtonat { // CTA_PROTONAT_
    Unspec	= 0,
    PortMin	= 1,
    PortMax	= 2,
    _MAX	= 3,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrSeqadjTbl"]
pub enum CtattrSeqadj { // CTA_SEQADJ_
    Unspec		= 0,
    CorrectionPos,
    OffsetBefore,
    OffsetAfter,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrNatseqTbl"]
pub enum CtattrNatseq { // CTA_NAT_SEQ_
    Unspec		= 0,
    CorrectionPos,
    OffsetBefore,
    OffsetAfter,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrSynproxyTbl"]
pub enum CtattrSynproxy { // CTA_SYNPROXY_
    Unspec	= 0,
    Isn,
    Its,
    Tsoff,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrExpectTbl"]
pub enum CtattrExpect { // CTA_EXPECT_
    Unspec	= 0,
    Master,
    Tuple,
    Mask,
    Timeout,
    Id,
    HelpName,
    Zone,
    Flags,
    Class,
    Nat,
    Fn,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrExpectNatTbl"]
pub enum CtattrExpectNat { // CTA_EXPECT_NAT_
    Unspec	= 0,
    Dir,
    Tuple,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrHelpTbl"]
pub enum CtattrHelp { // CTA_HELP_
    Unspec	= 0,
    Name,
    Info,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrSecctxTbl"]
pub enum CtattrSecctx { // CTA_SECCTX_
    Unspec	= 0,
    Name,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrStatsCpuTbl"]
pub enum CtattrStatsCpu { // CTA_STATS_
    Unspec,
    Searched,		// no longer used
    Found,
    New,		// no longer used
    Invalid,
    Ignore,
    Delete,		// no longer used
    DeleteList,		// no longer used
    Insert,
    InsertFailed,
    Drop,
    EarlyDrop,
    StatsError,		// note: `#[deny(ambiguous_associated_items)]` on by default
    SearchRestart,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrStatsGlobalTbl"]
pub enum CtattrStatsGlobal { // CTA_STATS_GLOBAL_
    Unspec	= 0,
    Entries,
    MaxEntries,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrExpectStatsTbl"]
pub enum CtattrExpectStats { // CTA_STATS_EXP_
    Unspec	= 0,
    New,
    Create,
    Delete,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrFilterTbl"]
pub enum CtattrFilter { // CTA_FILTER_
    Unspec	= 0,
    OrigFlags,
    ReplyFlags,
    _MAX
}


// XXX: copy only NF_NETLINK_ from nfnetlink_compat.h
// Old nfnetlink macros for userspace */
// nfnetlink groups: Up to 32 maximum
pub const NF_NETLINK_CONNTRACK_NEW: u32		= 0x00000001;
pub const NF_NETLINK_CONNTRACK_UPDATE: u32	= 0x00000002;
pub const NF_NETLINK_CONNTRACK_DESTROY: u32	= 0x00000004;
pub const NF_NETLINK_CONNTRACK_EXP_NEW: u32	= 0x00000008;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE: u32	= 0x00000010;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32	= 0x00000020;
