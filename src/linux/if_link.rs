// name conversion rule:
// struct - translate snake to camel
// anon enum - remove IFLA_ and to camel, excluding just IFLA
use libc::c_int;
use errno::Errno;

use { Msghdr, Attr, AttrTbl, Result };
// use linux::ipv6;

// This struct should be in sync with struct rtnl_link_stats64
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtnlLinkStats {
    pub rx_packets: u32,		// total packets received
    pub tx_packets: u32,                // total packets transmitted
    pub rx_bytes: u32,                  // total bytes received
    pub tx_bytes: u32,                  // total bytes transmitted
    pub rx_errors: u32,                 // bad packets received
    pub tx_errors: u32,                 // packet transmit problems
    pub rx_dropped: u32,                // no space in linux buffers
    pub tx_dropped: u32,                // no space available in linux
    pub multicast: u32,                 // multicast packets received
    pub collisions: u32,

    // detailed rx_errors:
    pub rx_length_errors: u32,
    pub rx_over_errors: u32,		// receiver ring buff overflow
    pub rx_crc_errors: u32,             // recved pkt with crc error
    pub rx_frame_errors: u32,           // recv'd frame alignment error
    pub rx_fifo_errors: u32,            // recv'r fifo overrun
    pub rx_missed_errors: u32,          // receiver missed packet

    // detailed tx_errors
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,

    // for cslip etc
    pub rx_compressed: u32,
    pub tx_compressed: u32,
    pub rx_nohandler: u32,		// dropped, no handler found
}

// The main device statistics structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtnlLinkStats64 {
    pub rx_packets: u64,		// total packets received
    pub tx_packets: u64,                // total packets transmitted
    pub rx_bytes: u64,                  // total bytes received
    pub tx_bytes: u64,                  // total bytes transmitted
    pub rx_errors: u64,                 // bad packets received
    pub tx_errors: u64,                 // packet transmit problems
    pub rx_dropped: u64,                // no space in linux buffers
    pub tx_dropped: u64,                // no space available in linux
    pub multicast: u64,                 // multicast packets received
    pub collisions: u64,

    // detailed rx_errors:
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,		// receiver ring buff overflow
    pub rx_crc_errors: u64,             // recved pkt with crc error
    pub rx_frame_errors: u64,           // recv'd frame alignment error
    pub rx_fifo_errors: u64,            // recv'r fifo overrun
    pub rx_missed_errors: u64,          // receiver missed packet

    // detailed tx_errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,

    // for cslip etc
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,		// dropped, no handler found
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtnlLinkIfmap {
    pub mem_start: u64,
    pub mem_end: u64,
    pub base_addr: u64,
    pub irq: u16,
    pub dma: u8,
    pub port: u8,
}

// IFLA_AF_SPEC
//   Contains nested attributes for address family specific attributes.
//   Each address family may create a attribute with the address family
//   number as type and create its own attribute structure in it.
//
//   Example:
//   [IFLA_AF_SPEC] = {
//       [AF_INET] = {
//           [IFLA_INET_CONF] = ...,
//       },
//       [AF_INET6] = {
//           [IFLA_INET6_FLAGS] = ...,
//           [IFLA_INET6_CONF] = ...,
//       }
//   }
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="IflaTbl"]
pub enum Ifla { // IFLA_
    Unspec		= 0,
    #[nla_type(bytes, address)]
    Address,

    #[nla_type(bytes, broadcast)]
    Broadcast,

    #[nla_type(str, ifname)]
    Ifname,

    #[nla_type(u32, mtu)]
    Mtu,

    #[nla_type(u32, link)]
    Link,

    #[nla_type(str, qdisc)]
    Qdisc,

    #[nla_type(RtnlLinkStats, stats)]
    Stats,

    Cost,

    Priority,

    #[nla_type(u32, master)]
    Master,

    #[nla_type(bytes, wireless)]
    Wireless,

    Protinfo,
    Txqlen,
    Map,
    Weight,
    Operstate,
    Linkmode,
    Linkinfo,
    NetNsPid,
    Ifalias,
    NumVf,
    VfinfoList,
    Stats64,
    VfPorts,
    PortSelf,
    AfSpec,
    Group,
    NetNsFd,
    ExtMask,
    Promiscuity,
    NumTxQueues,
    NumRxQueues,
    Carrier,
    PhysPortId,
    CarrierChanges,
    PhysSwitchId,
    LinkNetnsid,
    PhysPortName,
    ProtoDown,
    GsoMaxSegs,
    GsoMaxSize,
    Pad,
    Xdp,
    Event,
    NewNetnsid,
    IfNetnsid,
    CarrierUpCount,
    CarrierDownCount,
    NewIfindex,
    MinMtu,
    MaxMtu,
    PropList,
    AltIfname,
    PermAddress,
    ProtoDownReason,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
pub enum ProtoDownReason { // IFLA_PROTO_DOWN_REASON_
    Unspec,
    Mask,	/* u32, mask for reason bits */
    Value,	/* u32, reason bit value */
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="InetTbl"]
pub enum Inet { // IFLA_INET_
    Unspec	= 0,
    Conf,
    _MAX
}

// ifi_flags.
//
//   IFF_* flags.
//
//   The only change is:
//   IFF_LOOPBACK, IFF_BROADCAST and IFF_POINTOPOINT are
//   more not changeable by user. They describe link media
//   characteristics and set by device driver.
//
//   Comments:
//   - Combination IFF_BROADCAST|IFF_POINTOPOINT is invalid
//   - If neither of these three flags are set;
//     the interface is NBMA.
//
//   - IFF_MULTICAST does not mean anything special:
//   multicasts can be used on all not-NBMA links.
//   IFF_MULTICAST means that this media uses special encapsulation
//   for multicast frames. Apparently, all IFF_POINTOPOINT and
//   IFF_BROADCAST devices are able to use multicasts too.
//

// IFLA_LINK.
//   For usual devices it is equal ifi_index.
//   If it is a "virtual interface" (f.e. tunnel), ifi_link
//   can point to real physical interface (f.e. for bandwidth calculations),
//   or maybe 0, what means, that real media is unknown (usual
//   for IPIP tunnels, when route to endpoint is allowed to change)

// Subtype attributes for IFLA_PROTINFO
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="IflaInet6Tbl"]
pub enum Inet6 { // IFLA_INET6_
    Unspec		= 0,

    #[nla_type(u32, flags)]
    Flags,			// link flags

    Conf,			// sysctl parameters
    Stats,		    	// statistics
    Mcast,		    	// MC things. What of them?

    #[nla_type(IflaCacheinfo, cacheinfo)]
    Cacheinfo,		    	// time values and max reasm size
    Icmp6stats,		    	// statistics (icmpv6)
    Token,		    	// device token
    AddrGenMode,	    	// implicit address generator mode
    _MAX
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum In6AddrGenMode { // IN6_ADDR_GEN_MODE_
    Eui64		= 0,
    None,
    StablePrivacy,
    Random,
}
pub const IN6_ADDR_GEN_MODE_EUI64: u32		= In6AddrGenMode::Eui64 as u32;
pub const IN6_ADDR_GEN_MODE_NONE: u32		= In6AddrGenMode::None as u32;
pub const IN6_ADDR_GEN_MODE_STABLE_PRIVACY: u32	= In6AddrGenMode::StablePrivacy as u32;
pub const IN6_ADDR_GEN_MODE_RANDOM: u32		= In6AddrGenMode::Random as u32;

// Bridge section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="BrTbl"]
pub enum Br { // IFLA_BR_
    Unspec 			= 0,
    ForwardDelay,
    HelloTime,
    MasAge,
    AgeingTime,
    StpState,
    Priority,
    VlanFiltering,
    VlanProtocol,
    GroupFwdMask,
    RootId,
    BridgeId,
    RootPort,
    RootPathCost,
    TopologyChange,
    TopologyChangeDetedted,
    HelloTimer,
    TcnTimer,
    TopologyChangeTimer,
    GcTimer,
    GroupAddr,
    FdbFlush,
    McastRouter,
    McastSnooping,
    McastQueryUseIfaddr,
    McastQuerier,
    McastHashElasticity,
    McastHashMax,
    McastLastMemberCnt,
    McastStartupQueryCnt,
    McastLastMemberIntvl,
    McastMembershipIntvl,
    McastQuerierIntvl,
    McastQueryIntvl,
    McastQueryResponseIntvl,
    McastStartupQueryIntvl,
    NfCallIptables,
    NfCallIp6Tables,
    NfCallArptables,
    VlanDefaultPvid,
    Pad,
    VlanStatsEnabled,
    McastStatsEnabled,
    McastIgmpVersion,
    McastMldVersion,
    VlanStatsPerPort,
    MultiBoolopt,
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaBridgeId {
    pub prio: [u8; 2usize],
    pub addr: [u8; 6usize],
}

// XXX: unused?
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum BridgeMode { // BRIDGE_MODE_
    Unspec	= 0,
    Hairpin	= 1,
}
pub const BRIDGE_MODE_UNSPEC: c_int	= BridgeMode::Unspec as c_int;
pub const BRIDGE_MODE_HAIRPIN: c_int	= BridgeMode::Hairpin as c_int;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="BrportTbl"]
pub enum Brport { // IFLA_BRPORT_
    Unspec		= 0,

    #[nla_type(u8, state)]
    State,			// Spanning tree state

    #[nla_type(u16, priority)]
    Priority,			// "             priority

    #[nla_type(u32, cost)]
    Cost,			// "             cost

    #[nla_type(u8, mode)]
    Mode,			// mode (hairpin)

    #[nla_type(u8, guard)]
    Guard,			// bpdu guard

    #[nla_type(u8, protect)]
    Protect,			// root port protection

    #[nla_type(u8, fast_leave)]
    FastLeave,			// multicast fast leave

    #[nla_type(u8, learning)]
    Learning,			// mac learning

    #[nla_type(u8, flood)]
    UnicastFlood,		// flood unicast traffic

    #[nla_type(u8, proxyarp)]
    Proxyarp,			// proxy ARP

    LearningSync,		// mac learning sync from device

    #[nla_type(u8, proxyarp_wifi)]
    ProxyarpWifi,		// proxy ARP for Wi-Fi

    #[nla_type(IflaBridgeId, root_id)]
    RootId,			// designated root

    #[nla_type(IflaBridgeId, bridge_id)]
    BridgeId,			// designated bridge

    #[nla_type(u16, designated_port)]
    DesignatedPort,

    #[nla_type(u16, designated_cost)]
    DesignatedCost,

    #[nla_type(u16, id)]
    Id,

    #[nla_type(u16, no)]
    No,

    #[nla_type(u8, topology_change_ack)]
    TopologyChangeAck,

    #[nla_type(u8, config_pending)]
    ConfigPending,

    #[nla_type(u64, message_age_timer)]
    MessageAgeTimer,

    #[nla_type(u64, forward_delay_timer)]
    ForwardDelayTimer,

    #[nla_type(u64, hold_timer)]
    HoldTimer,

    Flush,

    #[nla_type(u8, multicast_router)]
    MulticastRouter,

    Pad,

    #[nla_type(u8, mcast_flood)]
    McastFlood,

    #[nla_type(u8, mcast_to_unicast)]
    McastToUnicast,

    #[nla_type(u8, vlan_tunnel)]
    VlanTunnel,

    #[nla_type(u8, bcast_flood)]
    BcastFlood,

    #[nla_type(u16, group_fwd_mask)]
    GroupFwdMask,

    #[nla_type(u8, neigh_suppress)]
    NeighSuppress,

    #[nla_type(u8, isolated)]
    Isolated,

    #[nla_type(u32, backup_port)]
    BackupPort,

    #[nla_type(u8, mrp_ring_open)]
    MrpRingOpen,

    #[nla_type(u8, mrp_in_open)]
    MrpInOpen,

    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaCacheinfo {
    pub max_reasm_len: u32,
    pub tstamp: u32,
    pub reachable_time: u32,
    pub retrans_time: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="InfoTbl"]
pub enum Info { // IFLA_INFO_
    Unspec	= 0,
    Kind,
    Data,
    Xstats,
    SlaveKind,
    SlaveData,
    _MAX
}

// VLAN section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VlanTbl"]
pub enum Vlan { // IFLA_VLAN_
    Unspec	= 0,
    Id,
    Flags,
    EgressQos,
    IngressQos,
    Protocol,
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVlanFlags {
    pub flags: u32,
    pub mask: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VlanQosTbl"]
pub enum VlanQos { // IFLA_VLAN_QOS_
    Unspec	= 0,
    Mapping,
    _MAX,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVlanQosMapping {
    pub from: u32,
    pub to: u32,
}

// MACVLAN section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="MacvlanTbl"]
pub enum Macvlan { // IFLA_MACVLAN_
    Unspec		= 0,
    Mode,
    Flags,
    MacaddrMode,
    Macaddr,
    MacaddrData,
    MacaddrCount,
    _MAX,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacvlanMode { // MACVLAN_MODE_
    Private	= 1,	// don't talk to other macvlans
    Vepa	= 2,    // talk to other ports through ext bridge
    Bridge	= 4,    // talk to bridge ports directly
    Passthru	= 8,    // take over the underlying device
    Source	= 16,   // use source MAC address list to assign
}
pub const MACVLAN_MODE_PRIVATE: u32	= MacvlanMode::Private as u32;
pub const MACVLAN_MODE_VEPA   : u32	= MacvlanMode::Vepa    as u32;
pub const MACVLAN_MODE_BRIDGE : u32	= MacvlanMode::Bridge  as u32;
pub const MACVLAN_MODE_PASSTHRU: u32	= MacvlanMode::Passthru as u32;
pub const MACVLAN_MODE_SOURCE : u32	= MacvlanMode::Source  as u32;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacvlanMacaddrMode { // MACVLAN_MACADDR_
    Add		= 0,
    Del,
    Flush,
    Set,
}
pub const MACVLAN_MACADDR_ADD: u32	= MacvlanMacaddrMode::Add as u32;
pub const MACVLAN_MACADDR_DEL: u32	= MacvlanMacaddrMode::Del as u32;
pub const MACVLAN_MACADDR_FLUSH: u32	= MacvlanMacaddrMode::Flush as u32;
pub const MACVLAN_MACADDR_SET: u32	= MacvlanMacaddrMode::Set as u32;

// VRF section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VrfTbl"]
pub enum Vrf { // IFLA_VRF_
    Unspec,
    Table,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VrfPortTbl"]
pub enum VrfPort { // IFLA_VRF_PORT_
    Unspec	= 0,
    Table,
    _MAX
}

// MACSEC section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="MacsecTbl"]
pub enum Macsec { // IFLA_MACSEC_
    Unspec		= 0,
    Sci,
    Port,
    IcvLen,
    CipherSuite,
    Window,
    EncodingSa,
    Encrypt,
    Protect,
    IncSci,
    Es,
    Scb,
    ReplayProtect,
    Validation,
    Pad,
    Offload,
    _MAX
}

// XFRM section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="XfrmTbl"]
pub enum Xfrm { // IFLA_XFRM_
    Unspec = 0,
    Link,
    IfId,
    _MAX
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacsecValidationType { // MACSEC_VALIDATE_
    Disabled	= 0,
    Check	= 1,
    Strict	= 2,
    _END
}
pub const MACSEC_VALIDATE_DISABLED: u8	= MacsecValidationType::Disabled as u8;
pub const MACSEC_VALIDATE_CHECK: u8	= MacsecValidationType::Check as u8;
pub const MACSEC_VALIDATE_STRICT: u8	= MacsecValidationType::Strict as u8;
pub const __MACSEC_VALIDATE_END: u8	= MacsecValidationType::_END as u8;
pub const MACSEC_VALIDATE_MAX: u8	= __MACSEC_VALIDATE_END - 1;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacsecOffload { // MACSEC_OFFLOAD_
    Off = 0,
    Phy = 1,
    Mac = 2,
    _END
}
pub const MACSEC_OFFLOAD_OFF: c_int	= MacsecOffload::Off as c_int;
pub const MACSEC_OFFLOAD_PHY: c_int	= MacsecOffload::Phy as c_int;
pub const MACSEC_OFFLOAD_MAC: c_int	= MacsecOffload::Mac as c_int;
pub const __MACSEC_OFFLOAD_END: c_int	= MacsecOffload::_END as c_int;
pub const MACSEC_OFFLOAD_MAX: c_int	= __MACSEC_OFFLOAD_END - 1;

// IPVLAN section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="IpvlanTbl"]
pub enum Ipvlan { // IFLA_IPVLAN_
    Unspec	= 0,
    Mode,
    Flags,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpvlanMode { // IPVLAN_MODE_
    L2		= 0,
    L3,
    L3S,
    MAX,
}
pub const IPVLAN_MODE_L2: u16	= IpvlanMode::L2 as u16;
pub const IPVLAN_MODE_L3: u16	= IpvlanMode::L3 as u16;
pub const IPVLAN_MODE_L3S: u16	= IpvlanMode::L3S as u16;
pub const IPVLAN_MODE_MAX: u16	= IpvlanMode::MAX as u16;

pub const IPVLAN_F_PRIVATE: u16	= 0x01;
pub const IPVLAN_F_VEPA: u16	= 0x02;

// VXLAN section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VxlanTbl"]
pub enum Vxlan { // IFLA_VXLAN_
    Unspec		= 0,
    Id,
    Group,		// group or remote address
    Link,
    Local,
    Ttl,
    Tos,
    Learning,
    Ageing,
    Limit,
    PortRange,		// source port
    Proxy,
    Rsc,
    L2Miss,
    L3Miss,
    Port,		// destination port
    Group6,
    Local6,
    UdpCsum,
    UdpZeroCsum6Tx,
    UdpZeroCsum6Rx,
    RemcsumTx,
    RemcsumRx,
    Gbp,
    RemcsumNopartial,
    CollectMetadata,
    Label,
    Gpe,
    TtlInherit,
    Df,
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVxlanPortRange {
    pub low: u16,
    pub high: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IflaVxlanDf { // VXLAN_DF_
    Unset = 0,
    Set,
    Inherit,
    _END,
}
pub const VXLAN_DF_UNSET: c_int		= IflaVxlanDf::Unset as c_int;
pub const VXLAN_DF_SET: c_int		= IflaVxlanDf::Set as c_int;
pub const VXLAN_DF_INHERIT: c_int	= IflaVxlanDf::Inherit as c_int;
pub const __VXLAN_DF_END: c_int		= IflaVxlanDf::_END as c_int;
pub const VXLAN_DF_MAX: c_int		= __VXLAN_DF_END - 1;

// GENEVE section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="GeneveTbl"]
pub enum Geneve { // IFLA_GENEVE_
    Unspec		= 0,
    Id,
    Remote,
    Ttl,
    Tos,
    Port,
    CollectMetadata,
    Remote6,
    UdpCsum,
    UdpZeroCsum6Tx,
    UdpZeroCsum6Rx,
    Label,
    TtlInherit,
    Df,
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum IflaGeneveDf { // GENEVE_DF_
    Unset = 0,
    Set,
    Inherit,
    _END,
}
pub const GENEVE_DF_UNSET: c_int	= IflaGeneveDf::Unset as c_int;
pub const GENEVE_DF_SET: c_int		= IflaGeneveDf::Set as c_int;
pub const GENEVE_DF_INHERIT: c_int	= IflaGeneveDf::Inherit as c_int;
pub const __GENEVE_DF_END: c_int	= IflaGeneveDf::_END as c_int;
pub const GENEVE_DF_MAX: c_int		= __GENEVE_DF_END - 1;

// Bareudp section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="BareUdpTbl"]
enum BareUdp { // IFLA_BAREUDP_
    Unspec,
    Port,
    Ethertype,
    SrcportMin,
    MultiprotoMode,
    _MAX
}

// PPP section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="PppTbl"]
pub enum Ppp { // IFLA_PPP_
    Unspec	= 0,
    DevFd,
    _MAX
}

// GTP section
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IflaGtpRole {
    Ggsn	= 0,
    Sgsn,
}
pub const GTP_ROLE_GGSN: u32	= IflaGtpRole::Ggsn as u32;
pub const GTP_ROLE_SGSN: u32	= IflaGtpRole::Sgsn as u32;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="GtpTbl"]
pub enum Gtp { // IFLA_GTP_
    Unspec		= 0,
    Fd0,
    Fd1,
    PdpHashsize,
    Role,
    _MAX
}

// Bonding section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="BondTbl"]
pub enum Bond { // IFLA_BOND_
    Unspec		= 0,
    Mode,
    ActiveSlave,
    Miimon,
    Updelay,
    Downdelay,
    UseCarrier,
    ArpInterval,
    ArpIpTarget,
    ArpValidate,
    ArpAllTargets,
    Primary,
    PrimaryReselect,
    FailOverMac,
    XmitHashPolicy,
    ResendIgmp,
    NumPeerNotif,
    AllSlavesActive,
    MinLinks,
    LpInterval,
    PacketsPerSlave,
    AdLacpRate,
    AdSelect,
    AdInfo,
    AdActorSysPrio,
    AdUserPortKey,
    AdActorSystem,
    TlbDynamicLb,
    PeerNotifDelay,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="BondAdInfoTbl"]
pub enum BondAdInfo { // IFLA_BOND_AD_INFO_
    Unspec	= 0,
    Aggregator,
    NumPorts,
    ActorKey,
    PartnerKey,
    PartnerMac,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="BondSlaveTbl"]
pub enum BondBondSlave { // IFLA_BOND_SLAVE_
    Unspec			= 0,
    State,
    MiiStatus,
    LinkFailureCount,
    PermHwaddr,
    QueueId,
    AdAggregatorId,
    AdActorOperPortState,
    AdPartnerOperPortState,
    _MAX
}

// SR-IOV virtual function management section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfInfoTbl"]
pub enum VfInfo { // IFLA_VF_INFO_
    Unspec	= 0,
    Info	= 1, // XXX: origin - IFLA_VF_INFO
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfTbl"]
pub enum Vf { // IFLA_VF_
    Unspec		= 0,
    Mac,		// Hardware queue specific attributes
    Vlan,		// VLAN ID and QoS
    TxRate,		// Max TX Bandwidth Allocation
    Spoofchk,		// Spoof Checking on/off switch
    LinkState,		// link state enable/disable/auto switch
    Rate,		// Min and Max TX Bandwidth Allocation
    RssQueryEn,		// RSS Redirection Table and Hash Key query
	        	// on/off switch
    Stats,		// network device statistics
    Trust,		// Trust VF
    IbNodeGuid,		// VF Infiniband node GUID
    IbPortGuid,		// VF Infiniband port GUID
    VlanList,		// nested list of vlans, option for QinQ
    Broadcast,		// VF broadcast
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfMac {
    pub vf: u32,
    pub mac: [u8; 32usize],	// MAX_ADDR_LEN
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfBroadcast {
    pub broadcast: [u8; 32usize],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfVlan {
    pub vf: u32,
    pub vlan: u32,	// 0 - 4095, 0 disables VLAN filter
    pub qos: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfVlanInfoTbl"]
pub enum VfVlanInfo { // IFLA_VF_VLAN_INFO_
    Unspec	= 0,
    Info,		// VLAN ID, QoS and VLAN protocol
    			// XXX: original - IFLA_VF_VLAN_INFO
    _MAX
}

pub const MAX_VLAN_LIST_LEN: usize = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfVlanInfo {
    pub vf: u32,
    pub vlan: u32,		// 0 - 4095, 0 disables VLAN filter
    pub qos: u32,
    pub vlan_proto: u16,	// VLAN protocol either 802.1Q or 802.1ad
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfTxRate {
    pub vf: u32,
    pub rate: u32,	// Max TX bandwidth in Mbps, 0 disables throttling
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfRate {
    pub vf: u32,
    pub min_tx_rate: u32,	// Min Bandwidth in Mbps
    pub max_tx_rate: u32,	// Max Bandwidth in Mbps
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfSpoofchk {
    pub vf: u32,
    pub setting: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfGuid {
    pub vf: u32,
    pub guid: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VfLinkState {	// IFLA_VF_LINK_STATE_
    Auto	= 0,	// link state of the uplink
    Enable,		// link always up
    Disable,		// link always down
    _MAX
}
pub const IFLA_VF_LINK_STATE_AUTO: u32		= VfLinkState::Auto as u32;
pub const IFLA_VF_LINK_STATE_ENABLE: u32	= VfLinkState::Enable as u32;
pub const IFLA_VF_LINK_STATE_DISABLE: u32	= VfLinkState::Disable as u32;
pub const __IFLA_VF_LINK_STATE_MAX: u32		= VfLinkState::_MAX as u32;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfLinkState {
    pub vf: u32,
    pub link_state: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaVfRssQueryEn {
    pub vf: u32,
    pub setting: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfStatsTbl"]
pub enum VfStats { // IFLA_VF_STATS_
    RxPackets	= 0,
    TxPackets,
    RxBytes,
    TxBytes,
    Broadcast,
    Multicast,
    Pad,
    RxDropped,
    TxDropped,
    _MAX
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ifla_vf_trust {
    pub vf: u32,
    pub setting: u32,
}

// XXXXXXXX: here

// VF ports management section
//
//	Nested layout of set/get msg is:
//
//		[IFLA_NUM_VF]
//		[IFLA_VF_PORTS]
//			[IFLA_VF_PORT]
//				[IFLA_PORT_*], ...
//			[IFLA_VF_PORT]
//				[IFLA_PORT_*], ...
//			...
//		[IFLA_PORT_SELF]
//			[IFLA_PORT_*], ...
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfPortTbl"]
pub enum VfPort { // IFLA_VF_PORT_
    Unspec,
    Port,	// nest
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="PortTbl"]
pub enum Port { // IFLA_PORT_
    Unspec		= 0,
    Vf,			// __u32
    Profile,		// string
    VsiType,		// 802.1Qbg (pre-)standard VDP
    InstanceUuid,	// binary UUID
    HostUuid,		// binary UUID
    Request,		// __u8
    Response,		// __u16, output only
    _MAX		= 8,
}
pub const PORT_PROFILE_MAX: usize	= 40;
pub const PORT_UUID_MAX: usize		= 16;
pub const PORT_SELF_VF: c_int		= -1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortRequest { // PORT_REQUEST_
    Preassociate = 0,
    PreassociateRr,
    Associate,
    Disassociate,
}
pub const PORT_REQUEST_PREASSOCIATE: u8		= PortRequest::Preassociate as u8;
pub const PORT_REQUEST_PREASSOCIATE_RR: u8	= PortRequest::PreassociateRr as u8;
pub const PORT_REQUEST_ASSOCIATE: u8		= PortRequest::Associate as u8;
pub const PORT_REQUEST_DISASSOCIATE: u8		= PortRequest::Disassociate as u8;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortResponse { // PORT_VDP_RESPONSE_, PORT_PROFILE_RESPONSE
    VdpSuccess = 0,
    VdpInvalidFormat,
    VdpInsufficientResources,
    VdpUnusedVtid,
    VdpVtidViolation,
    VdpVtidVersionVioaltion,
    VdpOutOfSync,
    // 0x08-0xFF reserved for future VDP use
    ProfileSuccess = 0x100,
    ProfileInprogress,
    ProfileInvalid,
    ProfileBadstate,
    ProfileInsufficientResources,
    ProfileError,
}
pub const PORT_VDP_RESPONSE_SUCCESS: u16		= PortResponse::VdpSuccess as u16;
pub const PORT_VDP_RESPONSE_INVALID_FORMAT: u16		= PortResponse::VdpInvalidFormat as u16;
pub const PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES: u16	= PortResponse::VdpInsufficientResources as u16;
pub const PORT_VDP_RESPONSE_UNUSED_VTID: u16		= PortResponse::VdpUnusedVtid as u16;
pub const PORT_VDP_RESPONSE_VTID_VIOLATION: u16		= PortResponse::VdpVtidViolation as u16;
pub const PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION: u16	= PortResponse::VdpVtidVersionVioaltion as u16;
pub const PORT_VDP_RESPONSE_OUT_OF_SYNC: u16		= PortResponse::VdpOutOfSync as u16;
pub const PORT_PROFILE_RESPONSE_SUCCESS: u16		= PortResponse::ProfileSuccess as u16;
pub const PORT_PROFILE_RESPONSE_INPROGRESS: u16		= PortResponse::ProfileInprogress as u16;
pub const PORT_PROFILE_RESPONSE_INVALID: u16		= PortResponse::ProfileInvalid as u16;
pub const PORT_PROFILE_RESPONSE_BADSTATE: u16		= PortResponse::ProfileBadstate as u16;
pub const PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES: u16	= PortResponse::ProfileInsufficientResources as u16;
pub const PORT_PROFILE_RESPONSE_ERROR: u16		= PortResponse::ProfileError as u16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ifla_port_vsi {
    pub vsi_mgr_id: u8,
    pub vsi_type_id: [u8; 3usize],
    pub vsi_type_version: u8,
    pub pad: [u8; 3usize],
}

// IPoIB section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="IopbTbl"]
pub enum Ipoib { // IFLA_IPOIB_
    Unspec,
    Pkey,
    Mode,
    Umcast,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpoibMode { // IPOIB_MODE_
    Datagram	= 0, // using unreliable datagram QPs
    Connected	= 1, // using connected QPs
}
pub const IPOIB_MODE_DATAGRAM: u16	= IpoibMode::Datagram as u16;
pub const IPOIB_MODE_CONNECTED: u16	= IpoibMode::Connected as u16;

// HSR/PRP section, both uses same interface */
// Different redundancy protocols for hsr device */
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HsrProtocol { // HSR_PROTOCOL_
    Hsr,
    Prp,
    MAX
}
pub const HSR_PROTOCOL_HSR: u8	= HsrProtocol::Hsr as u8;
pub const HSR_PROTOCOL_PRP: u8	= HsrProtocol::Prp as u8;
pub const HSR_PROTOCOL_MAX: u8	= HsrProtocol::MAX as u8;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="HsrTbl"]
pub enum Hsr {
    Unspec,
    Slave1,
    Slave2,
    MulticastSpec,		// Last byte of supervision addr
    SupervisionAddr,		// Supervision frame multicast addr
    SeqNr,
    Version,			// HSR version
    _MAX
}

// STATS section
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfStatsMsg {
    pub family: u8,
    _pad1: u8,
    _pad2: u16,
    pub ifindex: u32,
    pub filter_mask: u32,
}

// A stats attribute can be netdev specific or a global stat.
// For netdev stats, lets use the prefix IFLA_STATS_LINK_
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="StatsTbl"]
pub enum Stats { // IFLA_STATS_
    Unspec,			// also used as 64bit pad attribute
    Link64,
    LinkXstats,
    LinkXstatsSlave,
    LinkOffloadXstats,
    AfSpec,
    _MAX
}

pub const fn ifla_stats_filter_bit(attr: u16) -> u16 {
    1 << (attr - 1)
}

// These are embedded into IFLA_STATS_LINK_XSTATS:
// [IFLA_STATS_LINK_XSTATS]
// -> [LINK_XSTATS_TYPE_xxx]
//    -> [rtnl link type specific attributes]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="LinkXstatsTyepTbl"]
pub enum LinkXstatsType { // LINK_XSTATS_
    Unspec,
    Bridge,
    Bond,
    _MAX,
}

// These are stats embedded into IFLA_STATS_LINK_OFFLOAD_XSTATS
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="OffloadXstatsTbl"]
pub enum OffloadXstats { // IFLA_OFFLOAD_XSTATS_
    Unspec,
    CpuHit,	// struct rtnl_link_stats64
    _MAX
}

// XDP section
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32	= 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32		= 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32		= 1 << 2;
pub const XDP_FLAGS_HW_MODE: u32		= 1 << 3;
pub const XDP_FLAGS_MODES: u32			= XDP_FLAGS_SKB_MODE |
						  XDP_FLAGS_DRV_MODE |
					          XDP_FLAGS_HW_MODE;
pub const XDP_FLAGS_MASK: u32			= XDP_FLAGS_UPDATE_IF_NOEXIST |
                                                  XDP_FLAGS_MODES;

// These are stored into IFLA_XDP_ATTACHED on dump.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpAttached {
    None	= 0,
    Drv,
    Skb,
    Hw,
    Multi,
}
pub const XDP_ATTACHED_NONE: u8		= XdpAttached::None as u8;
pub const XDP_ATTACHED_DRV: u8		= XdpAttached::Drv as u8;
pub const XDP_ATTACHED_SKB: u8		= XdpAttached::Skb as u8;
pub const XDP_ATTACHED_HW: u8		= XdpAttached::Hw as u8;
pub const XDP_ATTACHED_MULTI: u8	= XdpAttached::Multi as u8;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="XdpTbl"]
pub enum Xdp { // IFLA_XDP_
    Unspec,
    Fd,
    Attached,
    Flags,
    ProgId,
    DrvProgId,
    SkbProgId,
    HwProgId,
    ExpectedFd,
    _MAX
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event { // IFLA_EVENT_
    None,
    Reboot,		// internal reset / reboot
    Features,		// change in offload features
    BondingFailover,	// change in active slave
    NotifyPeers,	// re-sent grat. arp/ndisc
    IgmpResend,		// re-sent IGMP JOIN
    BondingOptions,	// change in bonding options
}
pub const IFLA_EVENT_NONE: u32			= Event::None as u32;
pub const IFLA_EVENT_REBOOT: u32		= Event::Reboot as u32;
pub const IFLA_EVENT_FEATURES: u32		= Event::Features as u32;
pub const IFLA_EVENT_BONDING_FAILOVER: u32	= Event::BondingFailover as u32;
pub const IFLA_EVENT_NOTIFY_PEERS: u32		= Event::NotifyPeers as u32;
pub const IFLA_EVENT_IGMP_RESEND: u32		= Event::IgmpResend as u32;
pub const IFLA_EVENT_BONDING_OPTIONS: u32	= Event::BondingOptions as u32;

// tun section
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="TunTbl"]
pub enum Tun { // IFLA_TUN_
    Unspec,
    Owner,
    Group,
    Type,
    Pi,
    VnetHdr,
    Persist,
    MultiQueue,
    NumQueues,
    NumDisabledQueues,
    _MAX,
}

// rmnet section
pub const RMNET_FLAGS_INGRESS_DEAGGREGATION: u32         = 1 << 0;
pub const RMNET_FLAGS_INGRESS_MAP_COMMANDS: u32          = 1 << 1;
pub const RMNET_FLAGS_INGRESS_MAP_CKSUMV4: u32           = 1 << 2;
pub const RMNET_FLAGS_EGRESS_MAP_CKSUMV4: u32            = 1 << 3;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="RmnetTbl"]
pub enum Rmnet { // IFLA_RMNET_
    Unspec,
    MuxId,
    Flags,
    _MAX,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IflaRmnetFlags {
    flags: u32,
    mask: u32
}
