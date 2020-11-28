extern crate libc;
extern crate errno;
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
pub enum IFA {
    UNSPEC	= 0,
    ADDRESS	= 1,
    LOCAL	= 2,
    LABEL	= 3,
    BROADCAST	= 4,
    ANYCAST	= 5,
    CACHEINFO	= 6,
    MULTICAST	= 7,
    FLAGS	= 8,
    _MAX	= 9,
}
pub const IFA_UNSPEC: u16	= IFA::UNSPEC as u16;
pub const IFA_ADDRESS: u16	= IFA::ADDRESS as u16;
pub const IFA_LOCAL: u16	= IFA::LOCAL as u16;
pub const IFA_LABEL: u16	= IFA::LABEL as u16;
pub const IFA_BROADCAST: u16	= IFA::BROADCAST as u16;
pub const IFA_ANYCAST: u16	= IFA::ANYCAST as u16;
pub const IFA_CACHEINFO: u16	= IFA::CACHEINFO as u16;
pub const IFA_MULTICAST: u16	= IFA::MULTICAST as u16;
pub const IFA_FLAGS: u16	= IFA::FLAGS as u16;
pub const __IFA_MAX: u16	= IFA::_MAX as u16;
pub const IFA_MAX: u16		= __IFA_MAX - 1;

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IfAddr {
    Unspec	= 0,
    Address	= 1,
    Local	= 2,
    Label	= 3,
    Broadcast	= 4,
    Anycast	= 5,
    CacheInfo	= 6,
    Multicast	= 7,
    Flags	= 8,
    _MAX	= 9,
}

impl std::convert::TryFrom<u16> for IfAddr {
    type Error = errno::Errno;
    
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        if v >= Self::_MAX as u16 {
            Err(errno::Errno(libc::ERANGE))
        } else {
            unsafe { Ok(::std::mem::transmute::<u16, Self>(v)) }
        }
    }
}
impl std::convert::Into<usize> for IfAddr {
    fn into(self) -> usize {
        self as usize
    }
}
impl std::convert::Into<u16> for IfAddr {
    fn into(self) -> u16 {
        self as u16
    }
}

pub struct IfAddrSet<'a> ([Option<&'a crate::Attr<'a>>; IfAddr::_MAX as usize]);

impl <'a> std::ops::Index<IfAddr> for IfAddrSet<'a> {
    type Output = Option<&'a crate::Attr<'a>>;
 
    fn index(&self, a: IfAddr) -> &Self::Output {
        &self.0[a as usize]
    }
}

impl <'a> std::ops::IndexMut<IfAddr> for IfAddrSet<'a> {
    fn index_mut(&mut self, a: IfAddr) -> &mut Self::Output {
        &mut self.0[a as usize]
    }
}

impl <'a> crate::attr::AttrSet<'a> for IfAddrSet<'a> {
    type AttrType = IfAddr;
    
    fn new() -> Self {
        Self(Default::default())
    }
    fn len() -> usize {
        IfAddr::_MAX as usize - 1
    }
    fn atype(attr: &crate::Attr) -> Result<IfAddr, errno::Errno> {
        use std::convert::TryFrom;
        IfAddr::try_from(attr.atype())
    }
    fn get(&self, atype: IfAddr) -> Option<&crate::Attr> {
        self[atype]
    }
    fn set(&mut self, atype: IfAddr, attr: &'a crate::Attr) {
        self[atype] = Some(attr)
    }

    // pub fn from_nlmsg(nlh: &'a crate::Nlmsg, offset: usize) -> Result<Self, crate::GenError> {
    //     let mut tb = Self::new();
    //     nlh.parse(offset, |attr: &crate::Attr| {
    //         // tb[Self::atype(attr)?] = Some(attr);
    //         tb.set(Self::atype(attr)?, attr);
    //         Ok(crate::CbStatus::Ok)
    //     })?;
    //     Ok(tb)
    // }

    // pub fn from_nest(nest: &'a crate::Attr) -> Result<Self, crate::GenError> {
    //     nest.validate(crate::AttrDataType::Nested)?;
    //     let mut tb = Self::new();
    //     nest.parse_nested(|attr: &'a crate::Attr| {
    //         // tb[Self::atype(attr)?] = Some(attr);
    //         tb.set(Self::atype(attr)?, attr);
    //         Ok(crate::CbStatus::Ok)
    //     })?;
    //     Ok(tb)
    // }
}

impl <'a> IfAddrSet<'a> {
    pub fn address4(&self) -> crate::Result<Option<Ipv4Addr>> {
        if let Some(attr) = self[IfAddr::Address] {
            Ok(Some(attr.value::<Ipv4Addr>()?))
        } else {
            Ok(None)
        }
    }
    pub fn address6(&self) -> crate::Result<Option<Ipv6Addr>> {
        if let Some(attr) = self[IfAddr::Address] {
            Ok(Some(attr.value::<Ipv6Addr>()?))
        } else {
            Ok(None)
        }
    }
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
