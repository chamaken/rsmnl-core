use std::net::{Ipv4Addr, Ipv6Addr};

#[repr(C)]
pub struct Ifaddrmsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

// Important comment:
// IFA_ADDRESS is prefix address, rather than local interface address.
// It makes no difference for normally configured broadcast interfaces,
// but for point-to-point IFA_ADDRESS is DESTINATION address,
// local address is supplied in IFA_LOCAL attribute.
//
// IFA_FLAGS is a u32 attribute that extends the u8 field ifa_flags.
// If present, the value from struct ifaddrmsg will be ignored.
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="IfAddrSet"]
pub enum IfAddr {
    Unspec	= 0,

    #[nla_type(Ipv4Addr, address4)]
    #[nla_type(Ipv6Addr, address6)]
    Address	= 1,

    #[nla_type(Ipv4Addr, local4)]
    #[nla_type(Ipv6Addr, local6)]
    // others u8 for phonet, u16 decnet
    Local	= 2,

    #[nla_type(str, label)]
    Label	= 3,

    #[nla_type(Ipv4Addr, broadcast)]
    Broadcast	= 4,

    #[nla_type(Ipv6Addr, anycast)]
    Anycast	= 5,

    #[nla_type(IfaCacheinfo, cacheinfo)]
    CacheInfo	= 6,

    #[nla_type(Ipv6Addr, multicast)]
    Multicast	= 7,

    #[nla_type(u32, flags)]
    Flags	= 8,

    #[nla_type(u32, rt_priority)]
    RtPriority	= 9,
    
    #[nla_type(i32, target_netnsid)]
    TargetNetnsid	= 10,

    _MAX	= 11,
}

//ifa_flags
pub const IFA_F_SECONDARY: u32		= 0x01;
pub const IFA_F_TEMPORARY: u32		= IFA_F_SECONDARY;
pub const IFA_F_NODAD: u32		= 0x02;
pub const IFA_F_OPTIMISTIC: u32		= 0x04;
pub const IFA_F_DADFAILED: u32		= 0x08;
pub const IFA_F_HOMEADDRESS: u32	= 0x10;
pub const IFA_F_DEPRECATED: u32		= 0x20;
pub const IFA_F_TENTATIVE: u32		= 0x40;
pub const IFA_F_PERMANENT: u32		= 0x80;
pub const IFA_F_MANAGETEMPADDR: u32	= 0x100;
pub const IFA_F_NOPREFIXROUTE: u32	= 0x200;
pub const IFA_F_MCAUTOJOIN: u32		= 0x400;
pub const IFA_F_STABLE_PRIVACY: u32	= 0x800;

#[repr(C)]
pub struct IfaCacheinfo {
    pub ifa_prefered: u32,
    pub ifa_valid: u32,
    pub cstamp: u32,
    pub tstamp: u32,
}
