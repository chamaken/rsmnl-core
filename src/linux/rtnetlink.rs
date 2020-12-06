use std::{
    mem::size_of,
    os::raw::{
        c_int,
        c_uint,
        c_ushort,
        c_uchar,
    }
};

use libc::sa_family_t;
use errno::Errno;

use { Attr, AttrTbl };
use linux::netlink;
use linux::netlink::Nlmsghdr;

// rtnetlink families. Values up to 127 are reserved for real address
// families, values above 128 may be used arbitrarily.
pub const RTNL_FAMILY_IPMR: u8	= 128;
pub const RTNL_FAMILY_IP6MR: u8	= 129;
pub const RTNL_FAMILY_MAX: u8	= 129;

// Routing/neighbour discovery messages.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rtm {
    // BASE		= 16,
    Newlink		= 16,
    Dellink		= 17,
    Getlink		= 18,
    Tbllink		= 19,
    Newaddr		= 20,
    Deladdr		= 21,
    Getaddr		= 22,
    Newroute		= 24,
    Delroute		= 25,
    Getroute		= 26,
    Newneigh		= 28,
    Delneigh		= 29,
    Getneigh		= 30,
    Newrule		= 32,
    Delrule		= 33,
    Getrule		= 34,
    Newqdisc		= 36,
    Delqdisc		= 37,
    Getqdisc		= 38,
    Newtclass		= 40,
    Deltclass		= 41,
    Gettclass		= 42,
    Newtfilter		= 44,
    Deltfilter		= 45,
    Gettfilter		= 46,
    Newaction		= 48,
    Delaction		= 49,
    Getaction		= 50,
    Newprefix		= 52,
    Getmulticast	= 58,
    Getanycast		= 62,
    Newneightbl		= 64,
    Getneightbl		= 66,
    Tblneightbl		= 67,
    Newnduseropt	= 68,
    Newaddrlabel	= 72,
    Deladdrlabel	= 73,
    Getaddrlabel	= 74,
    Getdcb		= 78,
    Tbldcb		= 79,
    Newnetconf		= 80,
    Delnetconf		= 81,
    Getnetconf		= 82,
    Newmdb		= 84,
    Delmdb		= 85,
    Getmdb		= 86,
    Newnsid		= 88,
    Delnsid		= 89,
    Getnsid		= 90,
    Newstats		= 92,
    Getstats		= 94,
    Newcachereport	= 96,
    Newchain		= 100,
    Delchain		= 101,
    Getchain		= 102,
    Newnexthop		= 104,
    Delnexthop		= 105,
    Getnexthop		= 106,
    Newlinkprop		= 108,
    Dellinkprop		= 109,
    Getlinkprop		= 110,
    Newvlan		= 112,
    Delvlan		= 113,
    Getvlan		= 114,
    _MAX,
}
pub const RTM_BASE: u16			= Rtm::Newlink as u16;	// XXX
pub const RTM_NEWLINK: u16		= Rtm::Newlink as u16;
pub const RTM_DELLINK: u16		= Rtm::Dellink as u16;
pub const RTM_GETLINK: u16		= Rtm::Getlink as u16;
pub const RTM_SETLINK: u16		= Rtm::Tbllink as u16;
pub const RTM_NEWADDR: u16		= Rtm::Newaddr as u16;
pub const RTM_DELADDR: u16		= Rtm::Deladdr as u16;
pub const RTM_GETADDR: u16		= Rtm::Getaddr as u16;
pub const RTM_NEWROUTE: u16		= Rtm::Newroute as u16;
pub const RTM_DELROUTE: u16		= Rtm::Delroute as u16;
pub const RTM_GETROUTE: u16		= Rtm::Getroute as u16;
pub const RTM_NEWNEIGH: u16		= Rtm::Newneigh as u16;
pub const RTM_DELNEIGH: u16		= Rtm::Delneigh as u16;
pub const RTM_GETNEIGH: u16		= Rtm::Getneigh as u16;
pub const RTM_NEWRULE: u16		= Rtm::Newrule as u16;
pub const RTM_DELRULE: u16		= Rtm::Delrule as u16;
pub const RTM_GETRULE: u16		= Rtm::Getrule as u16;
pub const RTM_NEWQDISC: u16		= Rtm::Newqdisc as u16;
pub const RTM_DELQDISC: u16		= Rtm::Delqdisc as u16;
pub const RTM_GETQDISC: u16		= Rtm::Getqdisc as u16;
pub const RTM_NEWTCLASS: u16		= Rtm::Newtclass as u16;
pub const RTM_DELTCLASS: u16		= Rtm::Deltclass as u16;
pub const RTM_GETTCLASS: u16		= Rtm::Gettclass as u16;
pub const RTM_NEWTFILTER: u16		= Rtm::Newtfilter as u16;
pub const RTM_DELTFILTER: u16		= Rtm::Deltfilter as u16;
pub const RTM_GETTFILTER: u16		= Rtm::Gettfilter as u16;
pub const RTM_NEWACTION: u16		= Rtm::Newaction as u16;
pub const RTM_DELACTION: u16		= Rtm::Delaction as u16;
pub const RTM_GETACTION: u16		= Rtm::Getaction as u16;
pub const RTM_NEWPREFIX: u16		= Rtm::Newprefix as u16;
pub const RTM_GETMULTICAST: u16		= Rtm::Getmulticast as u16;
pub const RTM_GETANYCAST: u16		= Rtm::Getanycast as u16;
pub const RTM_NEWNEIGHTBL: u16		= Rtm::Newneightbl as u16;
pub const RTM_GETNEIGHTBL: u16		= Rtm::Getneightbl as u16;
pub const RTM_SETNEIGHTBL: u16		= Rtm::Tblneightbl as u16;
pub const RTM_NEWNDUSEROPT: u16		= Rtm::Newnduseropt as u16;
pub const RTM_NEWADDRLABEL: u16		= Rtm::Newaddrlabel as u16;
pub const RTM_DELADDRLABEL: u16		= Rtm::Deladdrlabel as u16;
pub const RTM_GETADDRLABEL: u16		= Rtm::Getaddrlabel as u16;
pub const RTM_GETDCB: u16		= Rtm::Getdcb as u16;
pub const RTM_SETDCB: u16		= Rtm::Tbldcb as u16;
pub const RTM_NEWNETCONF: u16		= Rtm::Newnetconf as u16;
pub const RTM_DELNETCONF: u16		= Rtm::Delnetconf as u16;
pub const RTM_GETNETCONF: u16		= Rtm::Getnetconf as u16;
pub const RTM_NEWMDB: u16		= Rtm::Newmdb as u16;
pub const RTM_DELMDB: u16		= Rtm::Delmdb as u16;
pub const RTM_GETMDB: u16		= Rtm::Getmdb as u16;
pub const RTM_NEWNSID: u16		= Rtm::Newnsid as u16;
pub const RTM_DELNSID: u16		= Rtm::Delnsid as u16;
pub const RTM_GETNSID: u16		= Rtm::Getnsid as u16;
pub const RTM_NEWSTATS: u16		= Rtm::Newstats as u16;
pub const RTM_GETSTATS: u16		= Rtm::Getstats as u16;
pub const RTM_NEWCACHEREPORT: u16	= Rtm::Newcachereport as u16;
pub const RTM_NEWCHAIN: u16		= Rtm::Newchain as u16;
pub const RTM_DELCHAIN: u16		= Rtm::Delchain as u16;
pub const RTM_GETCHAIN: u16		= Rtm::Getchain as u16;
pub const RTM_NEWNEXTHOP: u16		= Rtm::Newnexthop as u16;
pub const RTM_DELNEXTHOP: u16		= Rtm::Delnexthop as u16;
pub const RTM_GETNEXTHOP: u16		= Rtm::Getnexthop as u16;
pub const RTM_NEWLINKPROP: u16		= Rtm::Newlinkprop as u16;
pub const RTM_DELLINKPROP: u16		= Rtm::Dellinkprop as u16;
pub const RTM_GETLINKPROP: u16		= Rtm::Getlinkprop as u16;
pub const RTM_NEWNVLAN: u16		= Rtm::Newvlan as u16;
pub const RTM_DELVLAN: u16		= Rtm::Delvlan as u16;
pub const RTM_GETVLAN: u16		= Rtm::Getvlan as u16;
pub const __RTM_MAX: u16		= Rtm::_MAX as u16;
pub const RTM_MAX: u16			= ((__RTM_MAX as u16 + 3) & !3) - 1;

pub const RTM_NR_MSGTYPES: u16		= RTM_MAX + 1 - RTM_BASE;
pub const RTM_NR_FAMILIES: u16		= RTM_NR_MSGTYPES >> 2;
pub const fn rtm_fam(cmd: u16) -> u16 {
    (cmd - RTM_BASE) >> 2
}

// Generic structure for encapsulation of optional route information.
// It is reminiscent of sockaddr, but with sa_family replaced
// with attribute type.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rtattr {
    pub rta_len: u16,	// ::std::os::raw::c_ushort,
    pub rta_type: u16,	// ::std::os::raw::c_ushort,
}

// Macros to handle rtattributes
pub const RTA_ALIGNTO: u16	= 4;
pub const fn rta_align(len: u16) -> u16 {
    (len + RTA_ALIGNTO -1) & !(RTA_ALIGNTO - 1)
}
pub const fn rta_ok(rta: &Rtattr, len: u16) -> bool {
    len >= size_of::<Rtattr>() as u16 &&
        rta.rta_len >= size_of::<Rtattr>() as u16 &&
        rta.rta_len <= len
}
pub unsafe fn rta_next<'a>(rta: &'a mut Rtattr, attrlen: &mut u16) -> &'a mut Rtattr {
    *attrlen -= rta_align(rta.rta_len);
    &mut *((rta as *mut _ as *mut u8)
       .offset(rta.rta_len as isize) as *mut Rtattr)
}
pub const fn rta_length(len: u16) -> u16 {
    rta_align(size_of::<Rtattr>() as u16 + len)
}
pub const fn rta_space(len: u16) -> u16 {
    rta_align(rta_length(len))
}
pub unsafe fn rta_data<T>(rta: &mut Rtattr) -> &mut T {
    &mut *((rta as *mut _ as *mut u8)
       .offset(rta_length(0) as isize) as *mut T)
}
pub const fn rta_payload(rta: &Rtattr) -> u16 {
    rta.rta_len - rta_length(0)
}

// Definitions used in routing table administration.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rtmsg {
    pub rtm_family: u8, 	// 				::std::os::raw::c_uchar,
    pub rtm_dst_len: u8,	// 				::std::os::raw::c_uchar,
    pub rtm_src_len: u8,	// 				::std::os::raw::c_uchar,
    pub rtm_tos: u8,		// 				::std::os::raw::c_uchar,
    pub rtm_table: u8, 		// Routing table id		::std::os::raw::c_uchar,
    pub rtm_protocol: u8, 	// Routing protocol; see below	::std::os::raw::c_uchar,
    pub rtm_scope: u8, 		// See below			::std::os::raw::c_uchar,
    pub rtm_type: u8,		// See below			::std::os::raw::c_uchar,
    pub rtm_flags: u32,		// 				::std::os::raw::c_uint,
}

// rtm_type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rtn {
    Unspec	= 0,
    Unicast,		// Gateway or direct route
    Local,		// Accept locally
    Broadcast,		// Accept locally as broadcast,
    			// send as broadcast
    Anycast,		// Accept locally as broadcast,
                	// but send as unicast
    Multicast,		// Multicast route
    Blackhole,		// Drop
    Unreachable,	// Destination is unreachable
    Prohibit,		// Administratively prohibited
    Throw,		// Not in this table
    Nat,		// Translate this address
    Xresolve,		// Use external resolver
    _MAX
}
pub const RTN_UNSPEC: u8	= Rtn::Unspec as u8;
pub const RTN_UNICAST: u8	= Rtn::Unicast as u8;
pub const RTN_LOCAL: u8		= Rtn::Local as u8;
pub const RTN_BROADCAST: u8	= Rtn::Broadcast as u8;
pub const RTN_ANYCAST: u8	= Rtn::Anycast as u8;
pub const RTN_MULTICAST: u8	= Rtn::Multicast as u8;
pub const RTN_BLACKHOLE: u8	= Rtn::Blackhole as u8;
pub const RTN_UNREACHABLE: u8	= Rtn::Unreachable as u8;
pub const RTN_PROHIBIT: u8	= Rtn::Prohibit as u8;
pub const RTN_THROW: u8		= Rtn::Throw as u8;
pub const RTN_NAT: u8		= Rtn::Nat as u8;
pub const RTN_XRESOLVE: u8	= Rtn::Xresolve as u8;
pub const __RTN_MAX: u8		= Rtn::_MAX as u8;
pub const RTN_MAX: u8		= __RTN_MAX - 1;

// rtm_protocol
pub const RTPROT_UNSPEC: u8	= 0;
pub const RTPROT_REDIRECT: u8	= 1;	// Route installed by ICMP redirects;
				  	// not used by current IPv4
pub const RTPROT_KERNEL: u8	= 2;	// Route installed by kernel
pub const RTPROT_BOOT: u8	= 3;	// Route installed during boot
pub const RTPROT_STATIC: u8	= 4;	// Route installed by administrator

// Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
// they are just passed from user and back as is.
// It will be used by hypothetical multiple routing daemons.
// Note that protocol values should be standardized in order to
// avoid conflicts.

pub const RTPROT_GATED: u8	= 8;	// Apparently, GateD
pub const RTPROT_RA: u8		= 9;	// RDISC/ND router advertisements
pub const RTPROT_MRT: u8	= 10;	// Merit MRT
pub const RTPROT_ZEBRA: u8	= 11;	// Zebra
pub const RTPROT_BIRD: u8	= 12;	// BIRD
pub const RTPROT_DNROUTED: u8	= 13;	// DECnet routing daemon
pub const RTPROT_XORP: u8	= 14;	// XORP
pub const RTPROT_NTK: u8	= 15;	// Netsukuku
pub const RTPROT_DHCP: u8	= 16;   // DHCP client
pub const RTPROT_MROUTED: u8	= 17;   // Multicast daemon
pub const RTPROT_BABEL: u8	= 42;   // Babel daemon

// rtm_scope
//
// Really it is not scope, but sort of distance to the destination.
// NOWHERE are reserved for not existing destinations, HOST is our
// local addresses, LINK are destinations, located on directly attached
// link and UNIVERSE is everywhere in the Universe.
//
// Intermediate values are also possible f.e. interior routes
// could be assigned a value between UNIVERSE and LINK.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtScope {
    Universe	= 0,
    // User defined values
    Site	= 200,
    Link	= 253,
    Host	= 254,
    Nowhere	= 255,
}
pub const RT_SCOPE_UNIVERSE: u8	= RtScope::Universe as u8;
pub const RT_SCOPE_SITE: u8	= RtScope::Site as u8;
pub const RT_SCOPE_LINK: u8	= RtScope::Link as u8;
pub const RT_SCOPE_HOST: u8	= RtScope::Host as u8;
pub const RT_SCOPE_NOWHERE: u8	= RtScope::Nowhere as u8;

// rtm_flags
pub const RTM_F_NOTIFY: u32		= 0x100;	// Notify user of route change
pub const RTM_F_CLONED: u32		= 0x200;	// This route is cloned
pub const RTM_F_EQUALIZE: u32		= 0x400;	// Multipath equalizer: NI
pub const RTM_F_PREFIX: u32		= 0x800;	// Prefix addresses
pub const RTM_F_LOOKUP_TABLE: u32	= 0x1000;	// set rtm_table to FIB lookup result
pub const RTM_F_FIB_MATCH: u32		= 0x2000;	// return full fib lookup match

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtClass {
    Unspec	= 0,
    // User defined values
    Compat	= 252,
    Default	= 253,
    Main	= 254,
    Local	= 255,
    Max		= 0xFFFFFFFF,
}
pub const RT_TABLE_UNSPEC: u32	= RtClass::Unspec as u32;
pub const RT_TABLE_COMPAT: u32	= RtClass::Compat as u32;
pub const RT_TABLE_DEFAULT: u32	= RtClass::Default as u32;
pub const RT_TABLE_MAIN: u32	= RtClass::Main as u32;
pub const RT_TABLE_LOCAL: u32	= RtClass::Local as u32;
pub const RT_TABLE_MAX: u32	= RtClass::Max as u32;

// Routing message attributes
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
pub enum RtattrType {
    Unspec		= 0,
    Dst,
    Src,
    Iif,
    Oif,
    Gateway,
    Priority,
    Prefsrc,
    Metrics,
    Multipath,
    Protoinfo,		// no longer used
    Flow,
    Cacheinfo,
    Session,		// no longer used
    MpAlgo,		// no longer used
    Table,
    Mark,
    MfcStats,
    Via,
    Newdst,
    Pref,
    EncapType,
    Encap,
    Expires,
    Pad,
    Uid,
    TtlPropagate,
    IpProto,
    Sport,
    Dport,
    NhId,
    _MAX
}

pub unsafe fn rtm_rta(r: &mut Rtmsg) -> &mut Rtattr {
    &mut *((r as *mut _ as *mut u8)
           .offset(netlink::nlmsg_align(size_of::<Rtmsg>() as u32) as isize) as *mut Rtattr)
}
pub const fn rtm_payload(n: &Nlmsghdr) -> u32 {
    netlink::nlmsg_payload(n, size_of::<Rtmsg>() as u32)
}

// RTM_MULTIPATH --- array of struct rtnexthop.
//
// "struct rtnexthop" describes all necessary nexthop information,
// i.e. parameters of path to a destination via this nexthop.
//
// At the moment it is impossible to set different prefsrc, mtu, window
// and rtt for different paths from multipath.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rtnexthop {
    pub rtnh_len: u16,		// ::std::os::raw::c_ushort,
    pub rtnh_flags: u8,		// ::std::os::raw::c_uchar,
    pub rtnh_hops: u8,		// ::std::os::raw::c_uchar,
    pub rtnh_ifindex: c_int,
}

// rtnh_flags
pub const RTNH_F_DEAD: u8	= 1;	// Nexthop is dead (used by multipath)
pub const RTNH_F_PERVASIVE: u8	= 2;	// Do recursive gateway lookup
pub const RTNH_F_ONLINK: u8	= 4;	// Gateway is forced on link
pub const RTNH_F_OFFLOAD: u8	= 8;	// offloaded route
pub const RTNH_F_LINKDOWN: u8	= 16;	// carrier-down on nexthop
pub const RTNH_F_UNRESOLVED: u8	= 32;	// The entry is unresolved (ipmr)

pub const RTNH_COMPARE_MASK: u8	= RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_OFFLOAD;

// Macros to handle hexthops
pub const RTNH_ALIGNTO: u16	= 4;
pub const fn rtnh_align(len: u16) -> u16 {
    (len + RTNH_ALIGNTO - 1) & !(RTNH_ALIGNTO - 1)
}
pub const fn rtnh_ok(rtnh: &Rtnexthop, len: u16) -> bool {
    rtnh.rtnh_len >= size_of::<Rtnexthop>() as u16 &&
        rtnh.rtnh_len <= len
}
pub unsafe fn rtnh_next(rtnh: &mut Rtnexthop) -> &mut Rtnexthop {
    &mut *((rtnh as *mut _ as *mut u8)
       .offset(rtnh_align(rtnh.rtnh_len) as isize) as *mut Rtnexthop)
}
pub const fn rtnh_length(len: u16) -> u16 {
    rtnh_align(size_of::<Rtnexthop>() as u16 + len)
}
pub const fn rtnh_space(len: u16) -> u16 {
    rtnh_align(rtnh_length(len))
}
pub unsafe fn rtnh_data(rtnh: &mut Rtnexthop) -> &mut Rtattr {
    &mut *((rtnh as *mut _ as *mut u8)
       .offset(rtnh_length(0) as isize) as *mut Rtattr)
}

// RTA_VIA
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rtvia {
    pub rtvia_family: sa_family_t,
    pub rtvia_addr: [u8; 0],
}

// RTM_CACHEINFO
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtaCacheinfo {
    pub rta_clntref: u32,
    pub rta_lastuse: u32,
    pub rta_expires: i32,
    pub rta_error: u32,
    pub rta_used: u32,
    pub rta_id: u32,
    pub rta_ts: u32,
    pub rta_tsage: u32,
}
pub const RTNETLINK_HAVE_PEERINFO: u32	= 1;	// XXX: ???

// RTM_METRICS --- array of struct rtattr with types of RTAX_*
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rtax {
    Unspec		= 0,
    Lock,
    Mtu,
    Window,
    Rtt,
    Rttvar,
    Ssthresh,
    Cwnd,
    Advmss,
    Reordering,
    Hoplimit,
    Initcwnd,
    Features,
    RtoMin,
    Initrwnd,
    Quickack,
    CcAlgo,
    FastopenNoCookie,
    _MAX
}
pub const RTAX_UNSPEC: c_int			= Rtax::Unspec as c_int;
pub const RTAX_LOCK: c_int			= Rtax::Lock as c_int;
pub const RTAX_MTU: c_int			= Rtax::Mtu as c_int;
pub const RTAX_WINDOW: c_int			= Rtax::Window as c_int;
pub const RTAX_RTT: c_int			= Rtax::Rtt as c_int;
pub const RTAX_RTTVAR: c_int			= Rtax::Rttvar as c_int;
pub const RTAX_SSTHRESH: c_int			= Rtax::Ssthresh as c_int;
pub const RTAX_CWND: c_int			= Rtax::Cwnd as c_int;
pub const RTAX_ADVMSS: c_int			= Rtax::Advmss as c_int;
pub const RTAX_REORDERING: c_int		= Rtax::Reordering as c_int;
pub const RTAX_HOPLIMIT: c_int			= Rtax::Hoplimit as c_int;
pub const RTAX_INITCWND: c_int			= Rtax::Initcwnd as c_int;
pub const RTAX_FEATURES: c_int			= Rtax::Features as c_int;
pub const RTAX_RTO_MIN: c_int			= Rtax::RtoMin as c_int;
pub const RTAX_INITRWND: c_int			= Rtax::Initrwnd as c_int;
pub const RTAX_QUICKACK: c_int			= Rtax::Quickack as c_int;
pub const RTAX_CC_ALGO: c_int			= Rtax::CcAlgo as c_int;
pub const RTAX_FASTOPEN_NO_COOKIE: c_int	= Rtax::FastopenNoCookie as c_int;
pub const __RTAX_MAX: c_int			= Rtax::_MAX as c_int;
pub const RTAX_MAX: c_int		= __RTAX_MAX - 1;

pub const RTAX_FEATURE_ECN: u32		= 1 << 0;
pub const RTAX_FEATURE_SACK: u32	= 1 << 1;
pub const RTAX_FEATURE_TIMESTAMP: u32	= 1 << 2;
pub const RTAX_FEATURE_ALLFRAG: u32	= 1 << 3;
pub const RTAX_FEATURE_MASK: u32	= RTAX_FEATURE_ECN | RTAX_FEATURE_SACK |
                                          RTAX_FEATURE_TIMESTAMP | RTAX_FEATURE_ALLFRAG;
#[repr(C)]
// #[derive(Debug, Clone, Copy)]
#[derive(Clone, Copy)]
pub struct RtaSession {
    pub proto: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub u: _RtaSesseionUnion
}
#[repr(C)]
// #[derive(Debug, Clone, Copy)]
#[derive(Clone, Copy)]
pub union _RtaSesseionUnion {
    pub ports: _RtaSessionUnionPorts,
    pub icmpt: _RtaSesseionUnionIcmpt,
    pub spi: u32,
}
#[derive(Debug, Clone, Copy)]
pub struct _RtaSessionUnionPorts {
        sport: u16,
        dport: u16
}
#[derive(Debug, Clone, Copy)]
pub struct _RtaSesseionUnionIcmpt {
        itype: u8,
        code: u8,
        ident: u16
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtaMfcStats {
    pub mfcs_packets: u64,
    pub mfcs_bytes: u64,
    pub mfcs_wrong_if: u64,
}

// General form of address family dependent message.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rtgenmsg {
    pub rtgen_family: u8, // ::std::os::raw::c_uchar,
}

// Link layer specific messages.

// struct ifinfomsg
// passes link level specific information, not dependent
// on network protocol.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ifinfomsg {
    pub ifi_family: c_uchar,
    pub __ifi_pad: c_uchar,
    pub ifi_type: c_ushort,	// ARPHRD_*
    pub ifi_index: c_int,	// Link index
    pub ifi_flags: c_uint,	// IFF_* flags
    pub ifi_change: c_uint,	// IFF_* change mask
}

// prefix information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct prefixmsg {
    pub prefix_family: c_uchar,
    pub prefix_pad1: c_uchar,
    pub prefix_pad2: c_ushort,
    pub prefix_ifindex: c_int,
    pub prefix_type: c_uchar,
    pub prefix_len: c_uchar,
    pub prefix_flags: c_uchar,
    pub prefix_pad3: c_uchar,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="PrefixTbl"]
pub enum Prefix {
    Unspec	= 0,
    Address	= 1,
    Cacheinfo	= 2,
    _MAX	= 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrefixCacheinfo {
    pub preferred_time: u32,
    pub valid_time: u32,
}

// Traffic control messages.
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tcmsg {
    pub tcm_family: c_uchar,
    pub tcm__pad1: c_uchar,
    pub tcm__pad2: c_uchar,
    pub tcm_ifindex: c_uint,
    pub tcm_handle: u32,

    // XXX: tcm_block_index is used instead of tcm_parent
    // in case tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK
    // macro_rules! tcm_block_index { tcm_parent }
    pub tcm_parent: u32,

    pub tcm_info: u32,
}

// For manipulation of filters in shared block, tcm_ifindex is set to
// TCM_IFINDEX_MAGIC_BLOCK, and tcm_parent is aliased to tcm_block_index
// which is the block index.
// XXX: #define TCM_IFINDEX_MAGIC_BLOCK (0xFFFFFFFFU)
pub const TCM_IFINDEX_MAGIC_BLOCK: c_int	= -1;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="TcaTbl"]
pub enum Tca {
    Unspec		= 0,
    Kind,
    Options,
    Stats,
    Xstats,
    Rate,
    Fcnt,
    Stats2,
    Stab,
    Pad,
    DumpInvisible,
    Chain,
    HwOffload,
    IngressBlock,
    EgressBlock,
    DumpFlags,
    _MAX
}

pub const TCA_DUMP_FLAGS_TERSE: u32	= 1 << 0;	// Means that in dump user gets only basic
							// data necessary to identify the objects
							// (handle, cookie, etc.) and stats.

pub unsafe fn tca_rta(r: &mut Tcmsg)  -> &mut Rtattr {
    &mut *((r as *mut _ as *mut u8)
     .offset(netlink::nlmsg_align(size_of::<Tcmsg>() as u32) as isize) as *mut Rtattr)
}

pub fn tca_payload(n: &netlink::Nlmsghdr) -> u32 {
    netlink::nlmsg_payload(n, size_of::<Tcmsg>() as u32)
}

// Neighbor Discovery userland options
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nduseroptmsg {
    pub nduseropt_family: c_uchar,
    pub nduseropt_pad1: c_uchar,
    pub nduseropt_opts_len: c_ushort,	// Total length of options
    pub nduseropt_ifindex: c_int,
    pub nduseropt_icmp_type: u8,
    pub nduseropt_icmp_code: u8,
    pub nduseropt_pad2: c_ushort,
    pub nduseropt_pad3: c_uint,
    // Followed by one or more ND options
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="NduseportTbl"]
pub enum Nduseropt {
    Unspec	= 0,
    Srcaddr,
    _MAX
}

// RTnetlink multicast groups - backwards compatibility for userspace
pub const RTMGRP_LINK: u32		= 1;
pub const RTMGRP_NOTIFY: u32		= 2;
pub const RTMGRP_NEIGH: u32		= 4;
pub const RTMGRP_TC: u32		= 8;
pub const RTMGRP_IPV4_IFADDR: u32	= 0x10;
pub const RTMGRP_IPV4_MROUTE: u32	= 0x20;
pub const RTMGRP_IPV4_ROUTE: u32	= 0x40;
pub const RTMGRP_IPV4_RULE: u32		= 0x80;
pub const RTMGRP_IPV6_IFADDR: u32	= 0x100;
pub const RTMGRP_IPV6_MROUTE: u32	= 0x200;
pub const RTMGRP_IPV6_ROUTE: u32	= 0x400;
pub const RTMGRP_IPV6_IFINFO: u32	= 0x800;
#[allow(non_upper_case_globals)]
pub const RTMGRP_DECnet_IFADDR: u32	= 0x1000;
#[allow(non_upper_case_globals)]
pub const RTMGRP_DECnet_ROUTE: u32	= 0x4000;
pub const RTMGRP_IPV6_PREFIX: u32	= 0x20000;

// RTnetlink multicast groups
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtnetlinkGroups {
    None		= 0,
    Link,
    Notify,
    Neigh,
    Tc,
    Ipv4Ifaddr,
    Ipv4Mroute,
    Ipv4Route,
    Ipv4Rule,
    Ipv6Ifaddr,
    Ipv6Mroute,
    Ipv6Route,
    Ipv6Ifinfo,
    DecnetIfaddr,
    Nop2,
    DecnetRoute,
    DecnetRule,
    Nop4,
    Ipv6Prefix,
    Ipv6Rule,
    NdUseropt,
    PhonetIfaddr,
    PhonetRoute,
    Dcb,
    Ipv4Netconf,
    Ipv6Netconf,
    Mdb,
    MplsRoute,
    Nsid,
    MplsNetconf,
    Ipv4MrouteR,
    Ipv6MrouteR,
    Nexthop,
    Brvlan,
    _MAX
}
pub const RTNLGRP_NONE: u32		= RtnetlinkGroups::None as u32;
pub const RTNLGRP_LINK: u32		= RtnetlinkGroups::Link as u32;
pub const RTNLGRP_NOTIFY: u32		= RtnetlinkGroups::Notify as u32;
pub const RTNLGRP_NEIGH: u32		= RtnetlinkGroups::Neigh as u32;
pub const RTNLGRP_TC: u32		= RtnetlinkGroups::Tc as u32;
pub const RTNLGRP_IPV4_IFADDR: u32	= RtnetlinkGroups::Ipv4Ifaddr as u32;
pub const RTNLGRP_IPV4_MROUTE: u32	= RtnetlinkGroups::Ipv4Mroute as u32;
pub const RTNLGRP_IPV4_ROUTE: u32	= RtnetlinkGroups::Ipv4Route as u32;
pub const RTNLGRP_IPV4_RULE: u32	= RtnetlinkGroups::Ipv4Rule as u32;
pub const RTNLGRP_IPV6_IFADDR: u32	= RtnetlinkGroups::Ipv6Ifaddr as u32;
pub const RTNLGRP_IPV6_MROUTE: u32	= RtnetlinkGroups::Ipv6Mroute as u32;
pub const RTNLGRP_IPV6_ROUTE: u32	= RtnetlinkGroups::Ipv6Route as u32;
pub const RTNLGRP_IPV6_IFINFO: u32	= RtnetlinkGroups::Ipv6Ifinfo as u32;
#[allow(non_upper_case_globals)]
pub const RTNLGRP_DECnet_IFADDR: u32	= RtnetlinkGroups::DecnetIfaddr as u32;
pub const RTNLGRP_NOP2: u32		= RtnetlinkGroups::Nop2 as u32;
#[allow(non_upper_case_globals)]
pub const RTNLGRP_DECnet_ROUTE: u32	= RtnetlinkGroups::DecnetRoute as u32;
#[allow(non_upper_case_globals)]
pub const RTNLGRP_DECnet_RULE: u32	= RtnetlinkGroups::DecnetRule as u32;
pub const RTNLGRP_NOP4: u32		= RtnetlinkGroups::Nop4 as u32;
pub const RTNLGRP_IPV6_PREFIX: u32	= RtnetlinkGroups::Ipv6Prefix as u32;
pub const RTNLGRP_IPV6_RULE: u32	= RtnetlinkGroups::Ipv6Rule as u32;
pub const RTNLGRP_ND_USEROPT: u32	= RtnetlinkGroups::NdUseropt as u32;
pub const RTNLGRP_PHONET_IFADDR: u32	= RtnetlinkGroups::PhonetIfaddr as u32;
pub const RTNLGRP_PHONET_ROUTE: u32	= RtnetlinkGroups::PhonetRoute as u32;
pub const RTNLGRP_DCB: u32		= RtnetlinkGroups::Dcb as u32;
pub const RTNLGRP_IPV4_NETCONF: u32	= RtnetlinkGroups::Ipv4Netconf as u32;
pub const RTNLGRP_IPV6_NETCONF: u32	= RtnetlinkGroups::Ipv6Netconf as u32;
pub const RTNLGRP_MDB: u32		= RtnetlinkGroups::Mdb as u32;
pub const RTNLGRP_MPLS_ROUTE: u32	= RtnetlinkGroups::MplsRoute as u32;
pub const RTNLGRP_NSID: u32		= RtnetlinkGroups::Nsid as u32;
pub const RTNLGRP_MPLS_NETCONF: u32	= RtnetlinkGroups::MplsNetconf as u32;
pub const RTNLGRP_IPV4_MROUTE_R: u32	= RtnetlinkGroups::Ipv4MrouteR as u32;
pub const RTNLGRP_IPV6_MROUTE_R: u32	= RtnetlinkGroups::Ipv6MrouteR as u32;
pub const RTNLGRP_NEXTHOP: u32		= RtnetlinkGroups::Nexthop as u32;
pub const RTNLGRP_BRVLAN: u32		= RtnetlinkGroups::Brvlan as u32;
pub const __RTNLGRP_MAX: u32		= RtnetlinkGroups::_MAX as u32;
pub const RTNLGRP_MAX: u32		= __RTNLGRP_MAX - 1;

// TC action piece
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tcamsg {
    pub tca_family: c_uchar,
    pub tca__pad1: c_uchar,
    pub tca__pad2: c_uchar,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
pub enum TcaRoot {
    Unspec	= 0,
    Tab,
    Flags,
    Count,
    TimeDelta,
    _MAX
}

pub unsafe fn ta_rta(r: &mut Tcamsg) -> &mut Rtattr {
    &mut *((r as *mut _ as *mut u8)
     .offset(netlink::nlmsg_align(size_of::<Tcamsg>() as u32) as isize) as *mut Rtattr)
}
pub fn ta_payload(n: &netlink::Nlmsghdr) -> u32 {
    netlink::nlmsg_payload(n, size_of::<Tcamsg>() as u32)
}

// tcamsg flags stored in attribute TCA_ROOT_FLAGS
//
// TCA_FLAG_LARGE_DUMP_ON user->kernel to request for larger than TCA_ACT_MAX_PRIO
// actions in a dump. All dump responses will contain the number of actions
// being dumped stored in for user app's consumption in TCA_ROOT_COUNT
pub const TCA_FLAG_LARGE_DUMP_ON: u32	= 1 << 0;

// New extended info filters for IFLA_EXT_MASK
pub const RTEXT_FILTER_VF: u32			= 1 << 0;
pub const RTEXT_FILTER_BRVLAN: u32		= 1 << 1;
pub const RTEXT_FILTER_BRVLAN_COMPRESSED: u32	= 1 << 2;
pub const RTEXT_FILTER_SKIP_STATS: u32		= 1 << 3;

// End of information exported to user level
