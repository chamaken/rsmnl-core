use std::mem;

extern crate libc;
extern crate errno;

use libc::{ c_int, c_uint };
use errno::Errno;

use { Attr, AttrTbl, MsgVec, Result };

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Route		= 0,	// Routing/device hook
    Unused		= 1,	// Unused number
    Usersock		= 2,	// Reserved for user mode socket protocols
    Firewall		= 3,	// Unused number, formerly ip_queue
    SockDiag		= 4,	// socket monitoring
    Nflog		= 5,	// netfilter/iptables ULOG
    Xfrm		= 6,	// ipsec
    Selinux		= 7,	// SELinux event notifications
    Iscsi		= 8,	// Open-iSCSI
    Audit		= 9,	// auditing
    FibLookup		= 10,
    Connector		= 11,
    Netfilter		= 12,	// netfilter subsystem
    Ip6Fw		= 13,
    Dnrtmsg		= 14,	// DECnet routing messages
    KobjectUevent	= 15,   // Kernel messages to userspace
    Generic		= 16,

    Scsitransport	= 18,   // SCSI Transports
    Ecryptfs		= 19,
    Rdma		= 20,
    Crypto		= 21,	// Crypto layer
    Smc			= 22, 	// SMC monitoring

    InetDiag,	       		// #define NETLINK_INET_DIAG NETLINK_SOCK_DIAG
}

impl Into<c_int> for Family {
    fn into(self) -> c_int {
        if self == Family::InetDiag {
            return Family::SockDiag as c_int;
        }
        self as c_int
    }
}

pub const MAX_LINKS: c_int		= 32;

// refer libc - pub type sa_family_t = u16;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockaddrNl {
    pub nl_family: u16,
    nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32
}

impl Default for SockaddrNl {
    fn default() -> SockaddrNl {
        SockaddrNl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

// Flags values
pub const NLM_F_REQUEST: u16		= 0x01;	// It is request message.
pub const NLM_F_MULTI: u16		= 0x02;	// Multipart message, terminated by NLMSG_DONE
pub const NLM_F_ACK: u16		= 0x04;	// Reply with ack, with zero or error code
pub const NLM_F_ECHO: u16		= 0x08;	// Echo this request
pub const NLM_F_DUMP_INTR: u16		= 0x10;	// Dump was inconsistent due to sequence change
pub const NLM_F_DUMP_FILTERED: u16	= 0x20;	// Dump was filtered as requested

// Modifiers to GET request
pub const NLM_F_ROOT: u16	= 0x100;	// specify tree	root
pub const NLM_F_MATCH: u16	= 0x200;	// return all matching
pub const NLM_F_ATOMIC: u16	= 0x400;	// atomic GET
pub const NLM_F_DUMP: u16	= NLM_F_ROOT|NLM_F_MATCH;

// Modifiers to NEW request
pub const NLM_F_REPLACE: u16	= 0x100;	// Override existing
pub const NLM_F_EXCL: u16	= 0x200;	// Do not touch, if it exists
pub const NLM_F_CREATE: u16	= 0x400;	// Create, if it does not exist
pub const NLM_F_APPEND: u16	= 0x800;	// Add to end of list

// Modifiers to DELETE request
pub const NLM_F_NONREC:u16	= 0x100;	// Do not delete recursively

// Flags for ACK message
pub const NLM_F_CAPPED: u16	= 0x100;	// request was capped
pub const NLM_F_ACK_TLVS: u16	= 0x200;	// extended ACK TVLs were included


// 4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
// 4.4BSD CHANGE	NLM_F_REPLACE
//
// True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
// Append		NLM_F_CREATE
// Check		NLM_F_EXCL

pub const NLMSG_ALIGNTO: u32	= 4;
pub const fn nlmsg_align(len: u32) -> u32 {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}
pub const NLMSG_HDRLEN: u32 = nlmsg_align(mem::size_of::<Nlmsghdr>() as u32);
pub const fn nlmsg_length(len: u32) -> u32 {
    len + NLMSG_HDRLEN
}
pub const fn nlmsg_space(len: u32) -> u32 {
    nlmsg_align(nlmsg_length(len))
}
pub unsafe fn nlmsg_data<T>(nlh: &mut Nlmsghdr) -> &mut T {
    &mut *((nlh as *mut _ as *mut u8)
     .offset(nlmsg_length(0) as isize) as *mut T)
}
pub unsafe fn nlmsg_next<'a>(nlh: &'a mut Nlmsghdr, len: &mut u32) -> &'a mut Nlmsghdr {
    *len -= nlmsg_align(nlh.nlmsg_len);
    &mut *((nlh as *mut _ as *mut u8)
     .offset(nlmsg_align(nlh.nlmsg_len) as isize) as *mut Nlmsghdr)
}
pub fn nlmsg_ok(nlh: &Nlmsghdr, len: u32) -> bool {
    len >= mem::size_of::<Nlmsghdr>() as u32 &&
	nlh.nlmsg_len >= mem::size_of::<Nlmsghdr>() as u32 &&
	nlh.nlmsg_len <= len
}
pub const fn nlmsg_payload(nlh: &Nlmsghdr, len: u32) -> u32 {
    nlh.nlmsg_len - nlmsg_space(len)
}

#[derive(PartialEq, Eq, Hash)]
pub enum MsgType {
    Noop,	// 0x1: Nothing.
    Error,	// 0x2: Error
    Done,	// 0x3: End of a dump
    Overrun,	// 0x4: Data lost
    Other(u16),
}
pub const NLMSG_MIN_TYPE: u16 = 0x10; // < 0x10: reserved control messages

impl Into<u16> for MsgType {
    fn into(self) -> u16 {
        match self {
            Self::Noop		=> 0x1,
            Self::Error		=> 0x2,
            Self::Done		=> 0x3,
            Self::Overrun	=> 0x4,
            Self::Other(v)	=> v,
        }
    }
}

impl std::convert::TryFrom<u16> for MsgType {
    type Error = Errno;

    fn try_from(v: u16) -> std::result::Result<Self, Errno> {
        match v {
            0x1 => Ok(Self::Noop),
            0x2 => Ok(Self::Error),
            0x3 => Ok(Self::Done),
            0x4 => Ok(Self::Overrun),
            n if n < NLMSG_MIN_TYPE => Err(Errno(libc::ERANGE)),
            _ => Ok(Self::Other(v))
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Nlmsgerr {		// pub struct Nlmsgerr <'a> {
    pub error: c_int,
    pub msg: Nlmsghdr,		// pub msg: Nlmsghdr<'a>,
    //followed by the message contents unless NETLINK_CAP_ACK was set
    //or the ACK indicates success (error == 0)
    // message length is aligned with NLMSG_ALIGN()

    // followed by TLVs defined in enum nlmsgerr_attrs
    // if NETLINK_EXT_ACK was set
}

// enum nlmsgerr_attrs - nlmsgerr attributes
// @NLMSGERR_ATTR_UNUSED: unused
// @NLMSGERR_ATTR_MSG: error message string (string)
// @NLMSGERR_ATTR_OFFS: offset of the invalid attribute in the original
//      message, counting from the beginning of the header (u32)
// @NLMSGERR_ATTR_COOKIE: arbitrary subsystem specific cookie to
//     be used - in the success case - to identify a created
//     object or operation or similar (binary)
// @__NLMSGERR_ATTR_MAX: number of attributes
// @NLMSGERR_ATTR_MAX: highest attribute number
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NlmsgerrAttrs {
    Unused	= 0,
    Msg		= 1,
    Offs	= 2,
    Cookie	= 3,
    _MAX	= 4,
}

pub const NETLINK_ADD_MEMBERSHIP: c_int		= 1;
pub const NETLINK_DROP_MEMBERSHIP: c_int	= 2;
pub const NETLINK_PKTINFO: c_int		= 3;
pub const NETLINK_BROADCAST_ERROR: c_int	= 4;
pub const NETLINK_NO_ENOBUFS: c_int		= 5;
// pub const NETLINK_RX_RING: c_int		= 6;
// pub const NETLINK_TX_RING: c_int		= 7;
pub const NETLINK_LISTEN_ALL_NSID: c_int	= 8;
pub const NETLINK_LIST_MEMBERSHIPS: c_int	= 9;
pub const NETLINK_CAP_ACK: c_int		= 10;
pub const NETLINK_EXT_ACK: c_int		= 11;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlPktinfo {
    group: u32,
}

pub const NET_MAJOR: c_uint	= 36;	// Major 36 is reserved for networking

// struct sock_common.skc_state;
pub const NETLINK_UNCONNECTED: u8	= 0;
pub const NETLINK_CONNECTED: u8		= 1;


//  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
// +---------------------+- - -+- - - - - - - - - -+- - -+
// |        Header       | Pad |     Payload       | Pad |
// |   (struct nlattr)   | ing |                   | ing |
// +---------------------+- - -+- - - - - - - - - -+- - -+
//  <-------------- nlattr->nla_len -------------->
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Nlattr {
    pub nla_len: u16,
    pub nla_type: u16,
}


// nla_type (16 bits)
// +---+---+-------------------------------+
// | N | O | Attribute Type                |
// +---+---+-------------------------------+
// N := Carries nested attributes
// O := Payload stored in network byte order
//
// Note: The N and O flag are mutually exclusive.
pub const NLA_F_NESTED: u16		= 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16	= 1 << 14;
pub const NLA_TYPE_MASK: u16		= !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

pub const NLA_ALIGNTO: u16		= 4;

pub const fn nla_align(len: u16) -> u16 {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

pub const NLA_HDRLEN: u16 = nla_align(mem::size_of::<Nlattr>() as u16);

// Generic 32 bitflags attribute content sent to the kernel.
//
// The value is a bitmap that defines the values being set
// The selector is a bitmask that defines which value is legit
//
// Examples:
//  value = 0x0, and selector = 0x1
//  implies we are selecting bit 1 and we want to set its value to 0.
//
//  value = 0x2, and selector = 0x2
//  implies we are selecting bit 2 and we want to set its value to 1.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlaBitfield32 { // struct nla_bitfield32
    pub value: u32,
    pub selector: u32,
}


// policy descriptions - it's specific to each family how this is used
// Normally, it should be retrieved via a dump inside another attribute
// specifying where it applies.

// enum netlink_attribute_type - type of an attribute
// @NL_ATTR_TYPE_INVALID: unused
// @NL_ATTR_TYPE_FLAG: flag attribute (present/not present)
// @NL_ATTR_TYPE_U8: 8-bit unsigned attribute
// @NL_ATTR_TYPE_U16: 16-bit unsigned attribute
// @NL_ATTR_TYPE_U32: 32-bit unsigned attribute
// @NL_ATTR_TYPE_U64: 64-bit unsigned attribute
// @NL_ATTR_TYPE_S8: 8-bit signed attribute
// @NL_ATTR_TYPE_S16: 16-bit signed attribute
// @NL_ATTR_TYPE_S32: 32-bit signed attribute
// @NL_ATTR_TYPE_S64: 64-bit signed attribute
// @NL_ATTR_TYPE_BINARY: binary data, min/max length may be specified
// @NL_ATTR_TYPE_STRING: string, min/max length may be specified
// @NL_ATTR_TYPE_NUL_STRING: NUL-terminated string,
//      min/max length may be specified
// @NL_ATTR_TYPE_NESTED: nested, i.e. the content of this attribute
//      consists of sub-attributes. The nested policy and maxtype
//      inside may be specified.
// @NL_ATTR_TYPE_NESTED_ARRAY: nested array, i.e. the content of this
//      attribute contains sub-attributes whose type is irrelevant
//      (just used to separate the array entries) and each such array
//      entry has attributes again, the policy for those inner ones
//      and the corresponding maxtype may be specified.
// @NL_ATTR_TYPE_BITFIELD32: &struct nla_bitfield32 attribute
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetlinkAttributeType { // NL_ATTR_TYPE_
    Invalid,
    Flag,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    Binary,
    String,
    NulString,
    Nested,
    NestedArray,
    Bitfield32,
}
pub const NL_ATTR_TYPE_INVALID: u32		= NetlinkAttributeType::Invalid as u32;
pub const NL_ATTR_TYPE_FLAG: u32		= NetlinkAttributeType::Flag as u32;
pub const NL_ATTR_TYPE_U8: u32			= NetlinkAttributeType::U8 as u32;
pub const NL_ATTR_TYPE_U16: u32			= NetlinkAttributeType::U16 as u32;
pub const NL_ATTR_TYPE_U32: u32			= NetlinkAttributeType::U32 as u32;
pub const NL_ATTR_TYPE_U64: u32			= NetlinkAttributeType::U64 as u32;
pub const NL_ATTR_TYPE_S8: u32			= NetlinkAttributeType::S8 as u32;
pub const NL_ATTR_TYPE_S16: u32			= NetlinkAttributeType::S16 as u32;
pub const NL_ATTR_TYPE_S32: u32			= NetlinkAttributeType::S32 as u32;
pub const NL_ATTR_TYPE_S64: u32			= NetlinkAttributeType::S64 as u32;
pub const NL_ATTR_TYPE_BINARY: u32		= NetlinkAttributeType::Binary as u32;
pub const NL_ATTR_TYPE_STRING: u32		= NetlinkAttributeType::String as u32;
pub const NL_ATTR_TYPE_NUL_STRING: u32		= NetlinkAttributeType::NulString as u32;
pub const NL_ATTR_TYPE_NESTED: u32		= NetlinkAttributeType::Nested as u32;
pub const NL_ATTR_TYPE_NESTED_ARRAY: u32	= NetlinkAttributeType::NestedArray as u32;
pub const NL_ATTR_TYPE_BITFIELD32: u32		= NetlinkAttributeType::Bitfield32 as u32;

// enum netlink_policy_type_attr - policy type attributes
// @NL_POLICY_TYPE_ATTR_UNSPEC: unused
// @NL_POLICY_TYPE_ATTR_TYPE: type of the attribute,
//      &enum netlink_attribute_type (U32)
// @NL_POLICY_TYPE_ATTR_MIN_VALUE_S: minimum value for signed
//      integers (S64)
// @NL_POLICY_TYPE_ATTR_MAX_VALUE_S: maximum value for signed
//      integers (S64)
// @NL_POLICY_TYPE_ATTR_MIN_VALUE_U: minimum value for unsigned
//      integers (U64)
// @NL_POLICY_TYPE_ATTR_MAX_VALUE_U: maximum value for unsigned
//      integers (U64)
// @NL_POLICY_TYPE_ATTR_MIN_LENGTH: minimum length for binary
//      attributes, no minimum if not given (U32)
// @NL_POLICY_TYPE_ATTR_MAX_LENGTH: maximum length for binary
//      attributes, no maximum if not given (U32)
// @NL_POLICY_TYPE_ATTR_POLICY_IDX: sub policy for nested and
//      nested array types (U32)
// @NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE: maximum sub policy
//      attribute for nested and nested array types, this can
//      in theory be < the size of the policy pointed to by
//      the index, if limited inside the nesting (U32)
// @NL_POLICY_TYPE_ATTR_BITFIELD32_MASK: valid mask for the
//      bitfield32 type (U32)
// @NL_POLICY_TYPE_ATTR_PAD: pad attribute for 64-bit alignment
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="NetlinkPolicyTypeAttrTbl"]
pub enum NetlinkPolicyTypeAttr { // NL_POLICY_TYPE_ATTR_
    Unspec,

    #[nla_type(u32, atype)]
    Type,

    #[nla_type(i64, min_value_s)]
    MinValueS,

    #[nla_type(i64, max_value_s)]
    MaxValueS,


    #[nla_type(u64, min_value_u)]
    MinValueU,


    #[nla_type(u64, max_value_u)]
    MaxValueU,

    #[nla_type(u32, min_length)]
    MinLength,

    #[nla_type(u32, max_length)]
    MaxLength,

    #[nla_type(u32, policy_idx)]
    PolicyIdx,

    #[nla_type(u32, policy_max_type)]
    PolicyMaxtype,

    #[nla_type(u32, bitfield32_mask)]
    Bitfield32Mask,

    Pad,
    
    // keep last
    _MAX,
}
