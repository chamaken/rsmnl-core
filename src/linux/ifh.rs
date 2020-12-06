use libc::{c_uint, c_ulong, c_ushort, c_uchar};

pub const IFNAMSIZ: usize	= 16;
pub const IFALIASZ: usize	= 256;
pub const ALTIFNAMSIZ: usize	= 128;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetDeviceFlags { // IFF_
    Up				= 1<<0,  // sysfs
    Broadcast			= 1<<1,  // volatile
    Debug			= 1<<2,  // sysfs
    Loopback			= 1<<3,  // volatile
    Pointopoint			= 1<<4,  // volatile
    Notrailers			= 1<<5,  // sysfs
    Running			= 1<<6,  // volatile
    Noarp			= 1<<7,  // sysfs
    Promisc			= 1<<8,  // sysfs
    Allmulti			= 1<<9,  // sysfs
    Master			= 1<<10, // volatile
    Slave			= 1<<11, // volatile
    Multicast			= 1<<12, // sysfs
    Portsel			= 1<<13, // sysfs
    Automedia			= 1<<14, // sysfs
    Dynamic			= 1<<15, // sysfs
    LowerUp			= 1<<16, // volatile
    Dormant			= 1<<17, // volatile
    Echo			= 1<<18, // volatile
}
pub const IFF_UP: c_uint			= NetDeviceFlags::Up as c_uint;
pub const IFF_BROADCAST: c_uint			= NetDeviceFlags::Broadcast as c_uint;
pub const IFF_DEBUG: c_uint			= NetDeviceFlags::Debug as c_uint;
pub const IFF_LOOPBACK: c_uint			= NetDeviceFlags::Loopback as c_uint;
pub const IFF_POINTOPOINT: c_uint		= NetDeviceFlags::Pointopoint as c_uint;
pub const IFF_NOTRAILERS: c_uint		= NetDeviceFlags::Notrailers as c_uint;
pub const IFF_RUNNING: c_uint			= NetDeviceFlags::Running as c_uint;
pub const IFF_NOARP: c_uint			= NetDeviceFlags::Noarp as c_uint;
pub const IFF_PROMISC: c_uint			= NetDeviceFlags::Promisc as c_uint;
pub const IFF_ALLMULTI: c_uint			= NetDeviceFlags::Allmulti as c_uint;
pub const IFF_MASTER: c_uint			= NetDeviceFlags::Master as c_uint;
pub const IFF_SLAVE: c_uint			= NetDeviceFlags::Slave as c_uint;
pub const IFF_MULTICAST: c_uint			= NetDeviceFlags::Multicast as c_uint;
pub const IFF_PORTSEL: c_uint			= NetDeviceFlags::Portsel as c_uint;
pub const IFF_AUTOMEDIA: c_uint			= NetDeviceFlags::Automedia as c_uint;
pub const IFF_DYNAMIC: c_uint			= NetDeviceFlags::Dynamic as c_uint;
pub const IFF_LOWER_UP: c_uint			= NetDeviceFlags::LowerUp as c_uint;
pub const IFF_DORMANT: c_uint			= NetDeviceFlags::Dormant as c_uint;
pub const IFF_ECHO: c_uint			= NetDeviceFlags::Echo as c_uint;
pub const IFF_VOLATILE: c_uint			= IFF_LOOPBACK|IFF_POINTOPOINT|
						  IFF_BROADCAST|IFF_ECHO|
						  IFF_MASTER|IFF_SLAVE|
						  IFF_RUNNING|IFF_LOWER_UP|
						  IFF_DORMANT;

pub const IF_GET_IFACE: c_uint			= 0x0001;	// for querying only
pub const IF_GET_PROTO: c_uint			= 0x0002;

// For definitions see hdlc.h
pub const IF_IFACE_V35: c_uint			= 0x1000;	// V.35 serial interface
pub const IF_IFACE_V24: c_uint			= 0x1001;	// V.24 serial interface
pub const IF_IFACE_X21: c_uint			= 0x1002;	// X.21 serial interface
pub const IF_IFACE_T1: c_uint			= 0x1003;	// T1 telco serial interface
pub const IF_IFACE_E1: c_uint			= 0x1004;	// E1 telco serial interface
pub const IF_IFACE_SYNC_SERIAL: c_uint		= 0x1005;	// can't be set by software
pub const IF_IFACE_X21D: c_uint			= 0x1006;	// X.21 Dual Clocking (FarSite)

// For definitions see hdlc.h
pub const IF_PROTO_HDLC: c_uint			= 0x2000;	// raw HDLC protocol		*/
pub const IF_PROTO_PPP: c_uint			= 0x2001;	// PPP protocol			*/
pub const IF_PROTO_CISCO: c_uint		= 0x2002;	// Cisco HDLC protocol		*/
pub const IF_PROTO_FR: c_uint			= 0x2003;	// Frame Relay protocol		*/
pub const IF_PROTO_FR_ADD_PVC: c_uint		= 0x2004;	//    Create FR PVC		*/
pub const IF_PROTO_FR_DEL_PVC: c_uint		= 0x2005;	//    Delete FR PVC		*/
pub const IF_PROTO_X25: c_uint			= 0x2006;	// X.25				*/
pub const IF_PROTO_HDLC_ETH: c_uint		= 0x2007;	// raw HDLC, Ethernet emulation	*/
pub const IF_PROTO_FR_ADD_ETH_PVC: c_uint	= 0x2008;	//  Create FR Ethernet-bridged PVC */
pub const IF_PROTO_FR_DEL_ETH_PVC: c_uint	= 0x2009;	//  Delete FR Ethernet-bridged PVC */
pub const IF_PROTO_FR_PVC: c_uint		= 0x200A;	// for reading PVC status	*/
pub const IF_PROTO_FR_ETH_PVC: c_uint		= 0x200B;
pub const IF_PROTO_RAW: c_uint			= 0x200C;       // RAW Socket                   */

// RFC 2863 operational status */
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IfOper { // IF_OPER_
    Unknown,
    Notpresent,
    Down,
    Lowerlayerdown,
    Testing,
    Dormant,
    Up,
}
pub const IF_OPER_UNKNOWN: u8		= IfOper::Unknown as u8;
pub const IF_OPER_NOTPRESENT: u8	= IfOper::Notpresent as u8;
pub const IF_OPER_DOWN: u8		= IfOper::Down as u8;
pub const IF_OPER_LOWERLAYERDOWN: u8	= IfOper::Lowerlayerdown as u8;
pub const IF_OPER_TESTING: u8		= IfOper::Testing as u8;
pub const IF_OPER_DORMANT: u8		= IfOper::Dormant as u8;
pub const IF_OPER_UP: u8		= IfOper::Up as u8;

// link modes */
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IfLinkMode { // IF_LINK_MODE_
    Default	= 0,
    Dormant,	// limit upward transition to dormant */
    Testing,	// limit upward transition to testing */
}
pub const IF_LINK_MODE_DEFAULT: u8	= IfLinkMode::Default as u8;
pub const IF_LINK_MODE_DORMANT: u8	= IfLinkMode::Dormant as u8;
pub const IF_LINK_MODE_TESTING: u8	= IfLinkMode::Testing as u8;

// Device mapping structure. I'd just gone off and designed a
// beautiful scheme using only loadable modules with arguments
// for driver options and along come the PCMCIA people 8)
//
// Ah well. The get() side of this is good for WDSETUP, and it'll
// be handy for debugging things. The set side is fine for now and
// being very small might be worth keeping for clean configuration.

// for compatibility with glibc net/if.h
// seems to be same as if_link.h::struct rtnl_link_ifmap
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ifmap {
    mem_start: c_ulong,
    mem_end: c_ulong,
    base_addr: c_ushort,
    irq: c_uchar,
    dma: c_uchar,
    port: c_uchar
    // 3 bytes spare
}

// XXX: then the rest has raw ...
//   struct if_settings
//   struct ifreq and its unit handling
//   struct ifconf
