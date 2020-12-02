use errno::Errno;
use {Msghdr, Attr, AttrTbl, Result};

#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum CtnlMsgTypes {
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
    
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum CtnlExpMsgTypes {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrTypeTbl"]
pub enum CtattrType {
    Unspec		= 0,
    TupleOrig,
    TupleReply,
    Status,
    Protoinfo,
    Help,
    NatSrc,
    Timeout,
    Mark,
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
    MarkMask,
    Labels,
    LabelsMask,
    Synproxy,
    Filter,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrTupleTbl"]
pub enum CtattrTuple {
    Unspec	= 0,
    Ip,
    Proto,
    Zone,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrIpTbl"]
pub enum CtattrIp {
    Unspec	= 0,

    #[nla_type([u8; 4], v4src)]
    V4Src,

    #[nla_type([u8; 4], v4dst)]
    V4Dst,

    #[nla_type([u16; 8], v6src)]
    V6Src,

    #[nla_type([u16; 8], v6dst)]
    V6Dst,

    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrL4ProtoTbl"]
pub enum CtattrL4proto {
    Unspec	= 0,
    Num,
    SrcPort,
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoTbl"]
pub enum CtattrProtoinfo {
    Unspec	= 0,
    Tcp,
    Dccp,
    Sctp,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
pub enum CtattrProtoinfoTcp {
    Unspec		= 0,
    State,
    WscaleOriginal,
    WscaleReply,
    FlagsOriginal,
    FlagsReply,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoDccpTbl"]
pub enum CtattrProtoinfoDccp {
    Unspec		= 0,
    State,
    Role,
    HandshakeSeq,
    Pad,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtoinfoSctpTbl"]
pub enum CtattrProtoinfoSctp {
    Unspec		= 0,
    State,
    VtagOriginal,
    VtagReply,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrCountersTbl"]
pub enum CtattrCounters {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrTstampTbl"]
pub enum CtattrTstamp {
    Unspec	= 0,
    Start	= 1,
    Stop	= 2,
    Pad		= 3,
    _MAX	= 4,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrNatTbl"]
pub enum CtattrNat {
    Unspec	= 0,
    V4Minip,
    V4Maxip,
    Proto,
    V6Minip,
    V6Maxip,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrProtonatTbl"]
pub enum CtattrProtonat {
    Unspec	= 0,
    PortMin	= 1,
    PortMax	= 2,
    _MAX	= 3,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrSeqadjTbl"]
pub enum CtattrSeqadj {
    Unspec		= 0,
    CorrectionPos,
    OffsetBefore,
    OffsetAfter,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrNatseqTbl"]
pub enum CtattrNatseq {
    Unspec		= 0,
    CorrectionPos,
    OffsetBefore,
    OffsetAfter,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrSynproxyTbl"]
pub enum CtattrSynproxy {
    Unspec	= 0,
    Isn,
    Its,
    Tsoff,
    _MAX,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrExpectTbl"]
pub enum CtattrExpect {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrExpectNatTbl"]
pub enum CtattrExpectNat {
    Unspec	= 0,
    Dir,
    Tuple,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrHelpTbl"]
pub enum CtattrHelp {
    Unspec	= 0,
    Name,
    Info,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrSecctxTbl"]
pub enum CtattrSecctx {
    Unspec	= 0,
    Name,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrStatsCpuTbl"]
pub enum CtattrStatsCpu {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrStatsGlobalTbl"]
pub enum CtattrStatsGlobal { 
    Unspec	= 0,
    Entries,
    MaxEntries,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrExpectStatsTbl"]
pub enum CtattrExpectStats {
    Unspec	= 0,
    New,
    Create,
    Delete,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtattrFilterTbl"]
pub enum CtattrFilter {
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
