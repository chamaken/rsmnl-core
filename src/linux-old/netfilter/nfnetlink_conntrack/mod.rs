// use crate::{Attr, AttrSet};
// use crate::mnl_attr_table;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum CtnlMsgTypes {
    NEW			= 0,
    GET			= 1,
    DELETE		= 2,
    GET_CTRZERO		= 3,
    GET_STATS_CPU	= 4,
    GET_STATS		= 5,
    GET_DYING		= 6,
    GET_UNCONFIRMED	= 7,
    MAX			= 8,
}
pub const IPCTNL_MSG_CT_NEW: u16		= CtnlMsgTypes::NEW as u16;
pub const IPCTNL_MSG_CT_GET: u16		= CtnlMsgTypes::GET as u16;
pub const IPCTNL_MSG_CT_DELETE: u16		= CtnlMsgTypes::DELETE as u16;
pub const IPCTNL_MSG_CT_GET_CTRZERO: u16	= CtnlMsgTypes::GET_CTRZERO as u16;
pub const IPCTNL_MSG_CT_GET_STATS_CPU: u16	= CtnlMsgTypes::GET_STATS_CPU as u16;
pub const IPCTNL_MSG_CT_GET_STATS: u16		= CtnlMsgTypes::GET_STATS as u16;
pub const IPCTNL_MSG_CT_GET_DYING: u16		= CtnlMsgTypes::GET_DYING as u16;
pub const IPCTNL_MSG_CT_GET_UNCONFIRMED: u16	= CtnlMsgTypes::GET_UNCONFIRMED as u16;
pub const IPCTNL_MSG_MAX: u16			= CtnlMsgTypes::MAX as u16;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum CtnlExpMsgTypes {
    NEW			= 0,
    GET			= 1,
    DELETE		= 2,
    GET_STATS_CPU	= 3,
    MAX			= 4,
}
pub const IPCTNL_MSG_EXP_NEW: u16		= CtnlExpMsgTypes::NEW as u16;
pub const IPCTNL_MSG_EXP_GET: u16		= CtnlExpMsgTypes::GET as u16;
pub const IPCTNL_MSG_EXP_DELETE: u16		= CtnlExpMsgTypes::DELETE as u16;
pub const IPCTNL_MSG_EXP_GET_STATS_CPU: u16	= CtnlExpMsgTypes::GET_STATS_CPU as u16;
pub const IPCTNL_MSG_EXP_MAX: u16		= CtnlExpMsgTypes::MAX as u16;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA { // pub enum CtattrType {
    UNSPEC		= 0,
    TUPLE_ORIG		= 1,
    TUPLE_REPLY		= 2,
    STATUS		= 3,
    PROTOINFO		= 4,
    HELP		= 5,
    NAT_SRC		= 6,
    TIMEOUT		= 7,
    MARK		= 8,
    COUNTERS_ORIG	= 9,
    COUNTERS_REPLY	= 10,
    USE			= 11,
    ID			= 12,
    NAT_DST		= 13,
    TUPLE_MASTER	= 14,
    SEQ_ADJ_ORIG	= 15,
    SEQ_ADJ_REPLY	= 16,
    SECMARK		= 17,	// obsolete
    ZONE		= 18,
    SECCTX		= 19,
    TIMESTAMP		= 20,
    MARK_MASK		= 21,
    LABELS		= 22,
    LABELS_MASK		= 23,
    _MAX		= 24,    
}
// mnl_attr_table!(CTASet, CTA, CTA::_MAX as usize - 1);

pub const CTA_UNSPEC: u16		= CTA::UNSPEC as u16;
pub const CTA_TUPLE_ORIG: u16		= CTA::TUPLE_ORIG as u16;
pub const CTA_TUPLE_REPLY: u16		= CTA::TUPLE_REPLY as u16;
pub const CTA_STATUS: u16		= CTA::STATUS as u16;
pub const CTA_PROTOINFO: u16		= CTA::PROTOINFO as u16;
pub const CTA_HELP: u16			= CTA::HELP as u16;
pub const CTA_NAT_SRC: u16		= CTA::NAT_SRC as u16;
pub const CTA_NAT: u16			= CTA_NAT_SRC;			// backwards compatibility
pub const CTA_TIMEOUT: u16		= CTA::TIMEOUT as u16;
pub const CTA_MARK: u16			= CTA::MARK as u16;
pub const CTA_COUNTERS_ORIG: u16	= CTA::COUNTERS_ORIG as u16;
pub const CTA_COUNTERS_REPLY: u16	= CTA::COUNTERS_REPLY as u16;
pub const CTA_USE: u16			= CTA::USE as u16;
pub const CTA_ID: u16			= CTA::ID as u16;
pub const CTA_NAT_DST: u16		= CTA::NAT_DST as u16;
pub const CTA_TUPLE_MASTER: u16		= CTA::TUPLE_MASTER as u16;
pub const CTA_SEQ_ADJ_ORIG: u16		= CTA::SEQ_ADJ_ORIG as u16;
pub const CTA_NAT_SEQ_ADJ_ORIG:u16	= CTA_SEQ_ADJ_ORIG;
pub const CTA_SEQ_ADJ_REPLY: u16	= CTA::SEQ_ADJ_REPLY as u16;
pub const CTA_NAT_SEQ_ADJ_REPLY: u16	= CTA_SEQ_ADJ_REPLY;
pub const CTA_SECMARK: u16		= CTA::SECMARK as u16;
pub const CTA_ZONE: u16			= CTA::ZONE as u16;
pub const CTA_SECCTX: u16		= CTA::SECCTX as u16;
pub const CTA_TIMESTAMP: u16		= CTA::TIMESTAMP as u16;
pub const CTA_MARK_MASK: u16		= CTA::MARK_MASK as u16;
pub const CTA_LABELS: u16		= CTA::LABELS as u16;
pub const CTA_LABELS_MASK: u16		= CTA::LABELS_MASK as u16;
pub const __CTA_MAX: u16 		= CTA::_MAX as u16;
pub const CTA_MAX: u16 			= __CTA_MAX - 1;


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_TUPLE { // CtattrTuple {
    UNSPEC	= 0,
    IP		= 1,
    PROTO	= 2,
    ZONE	= 3,
    _MAX = 4,
}
pub const CTA_TUPLE_UNSPEC: u16	= CTA_TUPLE::UNSPEC as u16;
pub const CTA_TUPLE_IP: u16	= CTA_TUPLE::IP as u16;
pub const CTA_TUPLE_PROTO: u16	= CTA_TUPLE::PROTO as u16;
pub const CTA_TUPLE_ZONE: u16	= CTA_TUPLE::ZONE as u16;
pub const __CTA_TUPLE_MAX: u16	= CTA_TUPLE::_MAX as u16;
pub const CTA_TUPLE_MAX: u16	= __CTA_TUPLE_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_IP { // CtattrIp
    UNSPEC	= 0,
    V4_SRC	= 1,
    V4_DST	= 2,
    V6_SRC	= 3,
    V6_DST	= 4,
    _MAX	= 5,
}
pub const CTA_IP_UNSPEC: u16	= CTA_IP::UNSPEC as u16;
pub const CTA_IP_V4_SRC: u16	= CTA_IP::V4_SRC as u16;
pub const CTA_IP_V4_DST: u16	= CTA_IP::V4_DST as u16;
pub const CTA_IP_V6_SRC: u16	= CTA_IP::V6_SRC as u16;
pub const CTA_IP_V6_DST: u16	= CTA_IP::V6_DST as u16;
pub const __CTA_IP_MAX: u16	= CTA_IP::_MAX as u16;
pub const CTA_IP_MAX: u16	= __CTA_IP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_PROTO { // CtattrL4proto
    UNSPEC	= 0,
    NUM		= 1,
    SRC_PORT	= 2,
    DST_PORT	= 3,
    ICMP_ID	= 4,
    ICMP_TYPE	= 5,
    ICMP_CODE	= 6,
    ICMPV6_ID	= 7,
    ICMPV6_TYPE	= 8,
    ICMPV6_CODE	= 9,
    _MAX	= 10,
}
pub const CTA_PROTO_UNSPEC: u16		= CTA_PROTO::UNSPEC as u16;
pub const CTA_PROTO_NUM: u16		= CTA_PROTO::NUM as u16;
pub const CTA_PROTO_SRC_PORT: u16	= CTA_PROTO::SRC_PORT as u16;
pub const CTA_PROTO_DST_PORT: u16	= CTA_PROTO::DST_PORT as u16;
pub const CTA_PROTO_ICMP_ID: u16	= CTA_PROTO::ICMP_ID as u16;
pub const CTA_PROTO_ICMP_TYPE: u16	= CTA_PROTO::ICMP_TYPE as u16;
pub const CTA_PROTO_ICMP_CODE: u16	= CTA_PROTO::ICMP_CODE as u16;
pub const CTA_PROTO_ICMPV6_ID: u16	= CTA_PROTO::ICMPV6_ID as u16;
pub const CTA_PROTO_ICMPV6_TYPE: u16	= CTA_PROTO::ICMPV6_TYPE as u16;
pub const CTA_PROTO_ICMPV6_CODE: u16	= CTA_PROTO::ICMPV6_CODE as u16;
pub const __CTA_PROTO_MAX: u16		= CTA_PROTO::_MAX as u16;
pub const CTA_PROTO_MAX: u16		= __CTA_PROTO_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_PROTOINFO { // CtattrProtoinfo
    UNSPEC	= 0,
    TCP		= 1,
    DCCP	= 2,
    SCTP	= 3,
    _MAX	= 4,
}
pub const CTA_PROTOINFO_UNSPEC: u16	= CTA_PROTOINFO::UNSPEC as u16;
pub const CTA_PROTOINFO_TCP: u16	= CTA_PROTOINFO::TCP as u16;
pub const CTA_PROTOINFO_DCCP: u16	= CTA_PROTOINFO::DCCP as u16;
pub const CTA_PROTOINFO_SCTP: u16	= CTA_PROTOINFO::SCTP as u16;
pub const __CTA_PROTOINFO_MAX: u16	= CTA_PROTOINFO::_MAX as u16;
pub const CTA_PROTOINFO_MAX: u16	= __CTA_PROTOINFO_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_PROTOINFO_TCP { // CtattrProtoinfoTcp
    UNSPEC		= 0,
    STATE		= 1,
    WSCALE_ORIGINAL	= 2,
    WSCALE_REPLY	= 3,
    FLAGS_ORIGINAL	= 4,
    FLAGS_REPLY		= 5,
    _MAX		= 6,
}
pub const CTA_PROTOINFO_TCP_UNSPEC: u16			= CTA_PROTOINFO_TCP::UNSPEC as u16;
pub const CTA_PROTOINFO_TCP_STATE: u16			= CTA_PROTOINFO_TCP::STATE as u16;
pub const CTA_PROTOINFO_TCP_WSCALE_ORIGINAL: u16	= CTA_PROTOINFO_TCP::WSCALE_ORIGINAL as u16;
pub const CTA_PROTOINFO_TCP_WSCALE_REPLY: u16		= CTA_PROTOINFO_TCP::WSCALE_REPLY as u16;
pub const CTA_PROTOINFO_TCP_FLAGS_ORIGINAL: u16		= CTA_PROTOINFO_TCP::FLAGS_ORIGINAL as u16;
pub const CTA_PROTOINFO_TCP_FLAGS_REPLY: u16		= CTA_PROTOINFO_TCP::FLAGS_REPLY as u16;
pub const __CTA_PROTOINFO_TCP_MAX: u16			= CTA_PROTOINFO_TCP::_MAX as u16;
pub const CTA_PROTOINFO_TCP_MAX: u16			= __CTA_PROTOINFO_TCP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_PROTOINFO_DCCP { // CtattrProtoinfoDccp
    UNSPEC		= 0,
    STATE		= 1,
    ROLE		= 2,
    HANDSHAKE_SEQ	= 3,
    PAD			= 4,
    _MAX		= 5,
}
pub const CTA_PROTOINFO_DCCP_UNSPEC: u16	= CTA_PROTOINFO_DCCP::UNSPEC as u16;
pub const CTA_PROTOINFO_DCCP_STATE: u16		= CTA_PROTOINFO_DCCP::STATE as u16;
pub const CTA_PROTOINFO_DCCP_ROLE: u16		= CTA_PROTOINFO_DCCP::ROLE as u16;
pub const CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ: u16	= CTA_PROTOINFO_DCCP::HANDSHAKE_SEQ as u16;
pub const CTA_PROTOINFO_DCCP_PAD: u16		= CTA_PROTOINFO_DCCP::PAD as u16;
pub const __CTA_PROTOINFO_DCCP_MAX: u16		= CTA_PROTOINFO_DCCP::_MAX as u16;
pub const CTA_PROTOINFO_DCCP_MAX: u16		= __CTA_PROTOINFO_DCCP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_PROTOINFO_SCTP { // CtattrProtoinfoSctp
    UNSPEC		= 0,
    STATE		= 1,
    VTAG_ORIGINAL	= 2,
    VTAG_REPLY		= 3,
    _MAX		= 4,
}
pub const CTA_PROTOINFO_SCTP_UNSPEC: u16	= CTA_PROTOINFO_SCTP::UNSPEC as u16;
pub const CTA_PROTOINFO_SCTP_STATE: u16		= CTA_PROTOINFO_SCTP::STATE as u16;
pub const CTA_PROTOINFO_SCTP_VTAG_ORIGINAL: u16	= CTA_PROTOINFO_SCTP::VTAG_ORIGINAL as u16;
pub const CTA_PROTOINFO_SCTP_VTAG_REPLY: u16	= CTA_PROTOINFO_SCTP::VTAG_REPLY as u16;
pub const __CTA_PROTOINFO_SCTP_MAX: u16		= CTA_PROTOINFO_SCTP::_MAX as u16;
pub const CTA_PROTOINFO_SCTP_MAX: u16		= __CTA_PROTOINFO_SCTP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_COUNTERS { // CtattrCounters
    UNSPEC	= 0,
    PACKETS	= 1,	// 64bit counters
    BYTES	= 2,    // 64bit counters
    PACKETS32	= 3,    // old 32bit counters, unused
    BYTES32	= 4,    // old 32bit counters, unused
    PAD		= 5,
    _MAX	= 6,
}
pub const CTA_COUNTERS_UNSPEC: u16	= CTA_COUNTERS::UNSPEC as u16;
pub const CTA_COUNTERS_PACKETS: u16	= CTA_COUNTERS::PACKETS as u16;
pub const CTA_COUNTERS_BYTES: u16	= CTA_COUNTERS::BYTES as u16;
pub const CTA_COUNTERS32_PACKETS: u16	= CTA_COUNTERS::PACKETS32 as u16;
pub const CTA_COUNTERS32_BYTES: u16	= CTA_COUNTERS::BYTES32 as u16;
pub const CTA_COUNTERS_PAD: u16		= CTA_COUNTERS::PAD as u16;
pub const __CTA_COUNTERS_MAX: u16	= CTA_COUNTERS::_MAX as u16;
pub const CTA_COUNTERS_MAX: u16		= __CTA_COUNTERS_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_TIMESTAMP { // CtattrTstamp
    UNSPEC	= 0,
    START	= 1,
    STOP	= 2,
    PAD		= 3,
    _MAX	= 4,
}
pub const CTA_TIMESTAMP_UNSPEC: u16	= CTA_TIMESTAMP::UNSPEC as u16;
pub const CTA_TIMESTAMP_START: u16	= CTA_TIMESTAMP::START as u16;
pub const CTA_TIMESTAMP_STOP: u16	= CTA_TIMESTAMP::STOP as u16;
pub const CTA_TIMESTAMP_PAD: u16	= CTA_TIMESTAMP::PAD as u16;
pub const __CTA_TIMESTAMP_MAX: u16	= CTA_TIMESTAMP::_MAX as u16;
pub const CTA_TIMESTAMP_MAX: u16	= __CTA_TIMESTAMP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_NAT { // CtattrNat
    UNSPEC	= 0,
    V4_MINIP	= 1,
    V4_MAXIP	= 2,
    PROTO	= 3,
    V6_MINIP	= 4,
    V6_MAXIP	= 5,
    _MAX	= 6,
}
pub const CTA_NAT_UNSPEC: u16	= CTA_NAT::UNSPEC as u16;
pub const CTA_NAT_V4_MINIP: u16	= CTA_NAT::V4_MINIP as u16;
pub const CTATTR_NAT_MINIP: u16	= CTA_NAT_V4_MINIP;
pub const CTA_NAT_V4_MAXIP: u16	= CTA_NAT::V4_MAXIP as u16;
pub const CTATTR_NAT_MAXIP: u16	= CTA_NAT_V4_MAXIP;
pub const CTA_NAT_PROTO: u16	= CTA_NAT::PROTO as u16;
pub const CTA_NAT_V6_MINIP: u16	= CTA_NAT::V6_MINIP as u16;
pub const CTA_NAT_V6_MAXIP: u16	= CTA_NAT::V6_MAXIP as u16;
pub const __CTA_NAT_MAX: u16	= CTA_NAT::_MAX as u16;
pub const CTA_NAT_MAX: u16	= __CTA_NAT_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_PROTONAT { // CtattrProtonat
    UNSPEC	= 0,
    PORT_MIN	= 1,
    PORT_MAX	= 2,
    _MAX	= 3,
}
pub const CTA_PROTONAT_UNSPEC: u16	= CTA_PROTONAT::UNSPEC as u16;
pub const CTA_PROTONAT_PORT_MIN: u16	= CTA_PROTONAT::PORT_MIN as u16;
pub const CTA_PROTONAT_PORT_MAX: u16	= CTA_PROTONAT::PORT_MAX as u16;
pub const __CTA_PROTONAT_MAX: u16	= CTA_PROTONAT::_MAX as u16;
pub const CTA_PROTONAT_MAX: u16		= __CTA_PROTONAT_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_SEQADJ { // CtattrSeqadj
    UNSPEC		= 0,
    CORRECTION_POS	= 1,
    OFFSET_BEFORE	= 2,
    OFFSET_AFTER	= 3,
    _MAX		= 4,
}
pub const CTA_SEQADJ_UNSPEC: u16		= CTA_SEQADJ::UNSPEC as u16;
pub const CTA_SEQADJ_CORRECTION_POS: u16	= CTA_SEQADJ::CORRECTION_POS as u16;
pub const CTA_SEQADJ_OFFSET_BEFORE: u16		= CTA_SEQADJ::OFFSET_BEFORE as u16;
pub const CTA_SEQADJ_OFFSET_AFTER: u16		= CTA_SEQADJ::OFFSET_AFTER as u16;
pub const __CTA_SEQADJ_MAX: u16			= CTA_SEQADJ::_MAX as u16;
pub const CTA_SEQADJ_MAX: u16			= __CTA_SEQADJ_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_NAT_SEQ { // CtattrNatseq
    UNSPEC		= 0,
    CORRECTION_POS	= 1,
    OFFSET_BEFORE	= 2,
    OFFSET_AFTER	= 3,
    _MAX		= 4,
}
pub const CTA_NAT_SEQ_UNSPEC: u16		= CTA_NAT_SEQ::UNSPEC as u16;
pub const CTA_NAT_SEQ_CORRECTION_POS: u16	= CTA_NAT_SEQ::CORRECTION_POS as u16;
pub const CTA_NAT_SEQ_OFFSET_BEFORE: u16	= CTA_NAT_SEQ::OFFSET_BEFORE as u16;
pub const CTA_NAT_SEQ_OFFSET_AFTER: u16		= CTA_NAT_SEQ::OFFSET_AFTER as u16;
pub const __CTA_NAT_SEQ_MAX: u16		= CTA_NAT_SEQ::_MAX as u16;
pub const CTA_NAT_SEQ_MAX: u16			= __CTA_NAT_SEQ_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_EXPECT { // CtattrExpect
    UNSPEC	= 0,
    MASTER	= 1,
    TUPLE	= 2,
    MASK	= 3,
    TIMEOUT	= 4,
    ID		= 5,
    HELP_NAME	= 6,
    ZONE	= 7,
    FLAGS	= 8,
    CLASS	= 9,
    NAT		= 10,
    FN		= 11,
    _MAX	= 12,
}
pub const CTA_EXPECT_UNSPEC: u16	= CTA_EXPECT::UNSPEC as u16;
pub const CTA_EXPECT_MASTER: u16	= CTA_EXPECT::MASTER as u16;
pub const CTA_EXPECT_TUPLE: u16		= CTA_EXPECT::TUPLE as u16;
pub const CTA_EXPECT_MASK: u16		= CTA_EXPECT::MASK as u16;
pub const CTA_EXPECT_TIMEOUT: u16	= CTA_EXPECT::TIMEOUT as u16;
pub const CTA_EXPECT_ID: u16		= CTA_EXPECT::ID as u16;
pub const CTA_EXPECT_HELP_NAME: u16	= CTA_EXPECT::HELP_NAME as u16;
pub const CTA_EXPECT_ZONE: u16		= CTA_EXPECT::ZONE as u16;
pub const CTA_EXPECT_FLAGS: u16		= CTA_EXPECT::FLAGS as u16;
pub const CTA_EXPECT_CLASS: u16		= CTA_EXPECT::CLASS as u16;
pub const CTA_EXPECT_NAT: u16		= CTA_EXPECT::NAT as u16;
pub const CTA_EXPECT_FN: u16		= CTA_EXPECT::FN as u16;
pub const __CTA_EXPECT_MAX: u16		= CTA_EXPECT::_MAX as u16;
pub const CTA_EXPECT_MAX: u16		= __CTA_EXPECT_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_EXPECT_NAT { // CtattrExpectNat
    UNSPEC	= 0,
    DIR		= 1,
    TUPLE	= 2,
    _MAX	= 3,
}
pub const CTA_EXPECT_NAT_UNSPEC: u16	= CTA_EXPECT_NAT::UNSPEC as u16;
pub const CTA_EXPECT_NAT_DIR: u16	= CTA_EXPECT_NAT::DIR as u16;
pub const CTA_EXPECT_NAT_TUPLE: u16	= CTA_EXPECT_NAT::TUPLE as u16;
pub const __CTA_EXPECT_NAT_MAX: u16	= CTA_EXPECT_NAT::_MAX as u16;
pub const CTA_EXPECT_NAT_MAX: u16	= __CTA_EXPECT_NAT_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_HELP { // CtattrHelp
    UNSPEC	= 0,
    NAME	= 1,
    INFO	= 2,
    _MAX	= 3,
}
pub const CTA_HELP_UNSPEC: u16	= CTA_HELP::UNSPEC as u16;
pub const CTA_HELP_NAME: u16	= CTA_HELP::NAME as u16;
pub const CTA_HELP_INFO: u16	= CTA_HELP::INFO as u16;
pub const __CTA_HELP_MAX: u16	= CTA_HELP::_MAX as u16;
pub const CTA_HELP_MAX: u16	= __CTA_HELP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_SECCTX { // CtattrSecctx
    UNSPEC	= 0,
    NAME	= 1,
    _MAX	= 2,
}
pub const CTA_SECCTX_UNSPEC: u16	= CTA_SECCTX::UNSPEC as u16;
pub const CTA_SECCTX_NAME: u16		= CTA_SECCTX::NAME as u16;
pub const __CTA_SECCTX_MAX: u16		= CTA_SECCTX::_MAX as u16;
pub const CTA_SECCTX_MAX: u16		= __CTA_SECCTX_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_STATS { // CtattrStatsCpu
    UNSPEC		= 0,
    SEARCHED		= 1,	// no longer used
    FOUND		= 2,
    NEW			= 3,	// no longer used
    INVALID		= 4,
    IGNORE		= 5,
    DELETE		= 6,	// no longer used
    DELETE_LIST		= 7,	// no longer used
    INSERT		= 8,
    INSERT_FAILED 	= 9,
    DROP		= 10,
    EARLY_DROP		= 11,
    ERROR		= 12,
    SEARCH_RESTART	= 13,
    _MAX		= 14,
}
pub const CTA_STATS_UNSPEC: u16		= CTA_STATS::UNSPEC as u16;
pub const CTA_STATS_SEARCHED: u16	= CTA_STATS::SEARCHED as u16;
pub const CTA_STATS_FOUND: u16		= CTA_STATS::FOUND as u16;
pub const CTA_STATS_NEW: u16		= CTA_STATS::NEW as u16;
pub const CTA_STATS_INVALID: u16	= CTA_STATS::INVALID as u16;
pub const CTA_STATS_IGNORE: u16		= CTA_STATS::IGNORE as u16;
pub const CTA_STATS_DELETE: u16		= CTA_STATS::DELETE as u16;
pub const CTA_STATS_DELETE_LIST: u16	= CTA_STATS::DELETE_LIST as u16;
pub const CTA_STATS_INSERT: u16		= CTA_STATS::INSERT as u16;
pub const CTA_STATS_INSERT_FAILED: u16	= CTA_STATS::INSERT_FAILED as u16;
pub const CTA_STATS_DROP: u16		= CTA_STATS::DROP as u16;
pub const CTA_STATS_EARLY_DROP: u16	= CTA_STATS::EARLY_DROP as u16;
pub const CTA_STATS_ERROR: u16		= CTA_STATS::ERROR as u16;
pub const CTA_STATS_SEARCH_RESTART: u16	= CTA_STATS::SEARCH_RESTART as u16;
pub const __CTA_STATS_MAX: u16		= CTA_STATS::_MAX as u16;
pub const CTA_STATS_MAX: u16		= __CTA_STATS_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_STATS_GLOBAL { // CtattrStatsGlobal
    UNSPEC	= 0,
    ENTRIES	= 1,
    _MAX	= 2,
}
pub const CTA_STATS_GLOBAL_UNSPEC: u16	= CTA_STATS_GLOBAL::UNSPEC as u16;
pub const CTA_STATS_GLOBAL_ENTRIES: u16	= CTA_STATS_GLOBAL::ENTRIES as u16;
pub const __CTA_STATS_GLOBAL: u16	= CTA_STATS_GLOBAL::_MAX as u16;
pub const CTA_STATS_GLOBAL: u16		= __CTA_STATS_GLOBAL - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, MnlAttrConvert)]
#[repr(u16)]
pub enum CTA_STATS_EXP { // CtattrExpectStats
    UNSPEC	= 0,
    NEW		= 1,
    CREATE	= 2,
    DELETE	= 3,
    _MAX	= 4,
}
pub const CTA_STATS_EXP_UNSPEC: u16	= CTA_STATS_EXP::UNSPEC as u16;
pub const CTA_STATS_EXP_NEW: u16	= CTA_STATS_EXP::NEW as u16;
pub const CTA_STATS_EXP_CREATE: u16	= CTA_STATS_EXP::CREATE as u16;
pub const CTA_STATS_EXP_DELETE: u16	= CTA_STATS_EXP::DELETE as u16;
pub const __CTA_STATS_EXP_MAX: u16	= CTA_STATS_EXP::_MAX as u16;
pub const CTA_STATS_EXP_MAX: u16	= __CTA_STATS_EXP_MAX - 1;

// XXX: copy only NF_NETLINK_ from nfnetlink_compat.h
// Old nfnetlink macros for userspace */
// nfnetlink groups: Up to 32 maximum
pub const NF_NETLINK_CONNTRACK_NEW: u32		= 0x00000001;
pub const NF_NETLINK_CONNTRACK_UPDATE: u32	= 0x00000002;
pub const NF_NETLINK_CONNTRACK_DESTROY: u32	= 0x00000004;
pub const NF_NETLINK_CONNTRACK_EXP_NEW: u32	= 0x00000008;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE: u32	= 0x00000010;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32	= 0x00000020;
