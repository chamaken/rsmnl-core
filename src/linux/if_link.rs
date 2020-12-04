// name conversion rule:
// struct - translate snake to camel
// enum - remove IFLA_ and to camel, excluding just IFLA
use libc::c_int;
use errno::Errno;

use { Msghdr, Attr, AttrTbl, Result };
// use linux::ipv6;

// This struct should be in sync with struct rtnl_link_stats64
#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="IflaTbl"]
pub enum Ifla {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="InetTbl"]
pub enum Inet {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="Inet6Tbl"]
pub enum Inet6 {
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
pub enum In6AddrGenMode {
    Eui64		= 0,
    None,
    StablePrivacy,
    Random,
}

// Bridge section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="BrTbl"]
pub enum Br {
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
#[derive(Clone, Copy)]
pub struct IflaBridgeId {
    pub prio: [u8; 2usize],
    pub addr: [u8; 6usize],
}

// XXX: unused?
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum BridgeMode {
    Unspec	= 0,
    Hairpin	= 1,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="BrportTbl"]
pub enum Brport {
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
#[derive(Clone, Copy)]
pub struct IflaCacheinfo {
    pub max_reasm_len: u32,
    pub tstamp: u32,
    pub reachable_time: u32,
    pub retrans_time: u32,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="InfoTbl"]
pub enum Info {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VlanTbl"]
pub enum Vlan {
    Unspec	= 0,
    Id,
    Flags,
    EgressQos,
    IngressQos,
    Protocol,
    _MAX
}

#[repr(C)]
pub struct IflaVlanFlags {
    pub flags: u32,
    pub mask: u32,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VlanQosTbl"]
pub enum VlanQos {
    Unspec	= 0,
    Mapping,
    _MAX,
}

#[repr(C)]
pub struct IflaVlanQosMapping {
    pub from: u32,
    pub to: u32,
}

// MACVLAN section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="MacvlanTbl"]
pub enum Macvlan {
    Unspec		= 0,
    Mode,
    Flags,
    MacaddrMode,
    Macaddr,
    MacaddrData,
    MacaddrCount,
    _MAX,
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum MacvlanMode {
    Private	= 1,	// don't talk to other macvlans
    Vepa	= 2,    // talk to other ports through ext bridge
    Bridge	= 4,    // talk to bridge ports directly
    Passthru	= 8,    // take over the underlying device
    Source	= 16,   // use source MAC address list to assign
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum MacvlanMacaddrMode {
    Add		= 0,
    Del,
    Flush,
    Tbl,
}

// VRF section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VrfTbl"]
pub enum Vrf {
    Unspec,
    Table,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VrfPortTbl"]
pub enum VrfPort {
    Unspec	= 0,
    Table,
    _MAX
}

// MACSEC section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="MacsecTbl"]
pub enum Macsec {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="XfrmTbl"]
pub enum Xfrm {
    Unspec = 0,
    Link,
    IfId,
    _MAX
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum MacsecValidationType {
    Disabled	= 0,
    Check,
    Strict,
    _END
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum MacsecOffload {
    Off = 0,
    Phy,
    Mac,
    _END
}

// IPVLAN section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="IpvlanTbl"]
pub enum Ipvlan {
    Unspec	= 0,
    Mode,
    Flags,
    _MAX
}

#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum IpvlanMode {
    L2		= 0,
    L3,
    L3S,
    MAX,
}

pub const IPVLAN_F_PRIVATE: u16	= 0x01;
pub const IPVLAN_F_VEPA: u16	= 0x02;

// VXLAN section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VxlanTbl"]
pub enum Vxlan {
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
pub struct IflaVxlanPortRange {
    pub low: u16,
    pub high: u16,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum VxlanDf {
    Unset = 0,
    Tbl,
    Inherit,
    _END,
}

// GENEVE section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="GeneveTbl"]
pub enum Geneve {
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

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum GeneveDf {
    Unset = 0,
    Tbl,
    Inherit,
    _END,
}

// PPP section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="PppTbl"]
pub enum Ppp {
    Unspec	= 0,
    DevFd,
    _MAX
}

// GTP section
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum GtpRole {
    Ggsn	= 0,
    Sgsn	= 1,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="GtpTbl"]
pub enum Gtp {
    Unspec		= 0,
    Fd0,
    Fd1,
    PdpHashsize,
    Role,
    _MAX
}

// Bonding section
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="BondTbl"]
pub enum Bond {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="BondAdInfoTbl"]
pub enum BondAdInfo {
    Unspec	= 0,
    Aggregator,
    NumPorts,
    ActorKey,
    PartnerKey,
    PartnerMac,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="BondSlaveTbl"]
pub enum BondBondSlave {
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfInfoTbl"]
pub enum VfInfo {
    Unspec	= 0,
    Info	= 1, // XXX: origin - IFLA_VF_INFO
    _MAX
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfTbl"]
pub enum Vf {
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
pub struct IflaVfMac {
    pub vf: u32,
    pub mac: [u8; 32usize],	// MAX_ADDR_LEN
}

#[repr(C)]
pub struct IflaVfBroadcast {
    pub broadcast: [u8; 32usize],
}

#[repr(C)]
pub struct IflaVfVlan {
    pub vf: u32,
    pub vlan: u32,	// 0 - 4095, 0 disables VLAN filter
    pub qos: u32,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfVlanInfoTbl"]
pub enum VfVlanInfo { // XXX: naming, IflaVaVlanInfo is a struct, just below
    Unspec	= 0,
    Info,		// VLAN ID, QoS and VLAN protocol
    			// XXX: original - IFLA_VF_VLAN_INFO
    _MAX
}

pub const MAX_VLAN_LIST_LEN: usize = 1;

#[repr(C)]
pub struct IflaVfVlanInfo {
    pub vf: u32,
    pub vlan: u32,		// 0 - 4095, 0 disables VLAN filter
    pub qos: u32,
    pub vlan_proto: u16,	// VLAN protocol either 802.1Q or 802.1ad
}

#[repr(C)]
pub struct IflaVfTxRate {
    pub vf: u32,
    pub rate: u32,	// Max TX bandwidth in Mbps, 0 disables throttling
}

#[repr(C)]
pub struct IflaVfRate {
    pub vf: u32,
    pub min_tx_rate: u32,	// Min Bandwidth in Mbps
    pub max_tx_rate: u32,	// Max Bandwidth in Mbps
}

#[repr(C)]
pub struct IflaVfSpoofchk {
    pub vf: u32,
    pub setting: u32,
}

#[repr(C)]
pub struct IflaVfGuid {
    pub vf: u32,
    pub guid: u64,
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum VfLinkState {	// XXX: naming
    Auto	= 0,	// link state of the uplink
    Enable,		// link always up
    Disable,		// link always down
    _MAX
}

#[repr(C)]
pub struct IflaVfLinkState {
    pub vf: u32,
    pub link_state: u32,
}

#[repr(C)]
pub struct IflaVfRssQueryEn {
    pub vf: u32,
    pub setting: u32,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="VfStatsTbl"]
pub enum VfStats {
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
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VfPort { // XXX: naming
    UNSPEC	= 0,
    PORT	= 1,
    _MAX	= 2,
}
pub const IFLA_VF_PORT_UNSPEC: u16	= VfPort::UNSPEC as u16;
pub const IFLA_VF_PORT: u16		= VfPort::PORT as u16;	// nest
pub const __IFLA_VF_PORT_MAX: u16	= VfPort::_MAX as u16;
pub const IFLA_VF_PORT_MAX: u16		= __IFLA_VF_PORT_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VfPortInfo { // XXX: naming
    UNSPEC		= 0,
    VF			= 1,	// __u32
    PROFILE		= 2,	// string
    VSI_TYPE		= 3,	// 802.1Qbg (pre-)standard VDP
    INSTANCE_UUID	= 4,	// binary UUID
    HOST_UUID		= 5,	// binary UUID
    REQUEST		= 6,	// __u8
    RESPONSE		= 7,	// __u16, output only
    _MAX		= 8,
}
pub const IFLA_PORT_UNSPEC: u16		= VfPortInfo::UNSPEC as u16;
pub const IFLA_PORT_VF: u16		= VfPortInfo::VF as u16;
pub const IFLA_PORT_PROFILE: u16	= VfPortInfo::PROFILE as u16;
pub const IFLA_PORT_VSI_TYPE: u16	= VfPortInfo::VSI_TYPE as u16;
pub const IFLA_PORT_INSTANCE_UUID: u16	= VfPortInfo::INSTANCE_UUID as u16;
pub const IFLA_PORT_HOST_UUID: u16	= VfPortInfo::HOST_UUID as u16;
pub const IFLA_PORT_REQUEST: u16	= VfPortInfo::REQUEST as u16;
pub const IFLA_PORT_RESPONSE: u16	= VfPortInfo::RESPONSE as u16;
pub const __IFLA_PORT_MAX: u16		= VfPortInfo::_MAX as u16;
pub const IFLA_PORT_MAX: u16		= __IFLA_PORT_MAX - 1;

pub const PORT_PROFILE_MAX: usize	= 40;
pub const PORT_UUID_MAX: usize		= 16;
pub const PORT_SELF_VF: c_int		= -1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Enum_Unnamed30 { // enoc only?
    PORT_REQUEST_PREASSOCIATE = 0,
    PORT_REQUEST_PREASSOCIATE_RR = 1,
    PORT_REQUEST_ASSOCIATE = 2,
    PORT_REQUEST_DISASSOCIATE = 3,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Enum_Unnamed31 { // not used, just defined?
    PORT_VDP_RESPONSE_SUCCESS = 0,
    PORT_VDP_RESPONSE_INVALID_FORMAT = 1,
    PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES = 2,
    PORT_VDP_RESPONSE_UNUSED_VTID = 3,
    PORT_VDP_RESPONSE_VTID_VIOLATION = 4,
    PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION = 5,
    PORT_VDP_RESPONSE_OUT_OF_SYNC = 6,
    // 0x08-0xFF reserved for future VDP use
    PORT_PROFILE_RESPONSE_SUCCESS = 256,
    PORT_PROFILE_RESPONSE_INPROGRESS = 257,
    PORT_PROFILE_RESPONSE_INVALID = 258,
    PORT_PROFILE_RESPONSE_BADSTATE = 259,
    PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES = 260,
    PORT_PROFILE_RESPONSE_ERROR = 261,
}

#[repr(C)]
pub struct ifla_port_vsi {
    pub vsi_mgr_id: u8,
    pub vsi_type_id: [u8; 3usize],
    pub vsi_type_version: u8,
    pub pad: [u8; 3usize],
}

// IPoIB section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Ipoib {
    UNSPEC	= 0,
    PKEY	= 1,
    MODE	= 2,
    UMCAST	= 3,
    _MAX	= 4,
}

pub const IFLA_IPOIB_UNSPEC: u16	= Ipoib::UNSPEC as u16;
pub const IFLA_IPOIB_PKEY: u16		= Ipoib::PKEY as u16;
pub const IFLA_IPOIB_MODE: u16		= Ipoib::MODE as u16;
pub const IFLA_IPOIB_UMCAST: u16	= Ipoib::UMCAST as u16;
pub const __IFLA_IPOIB_MAX: u16		= Ipoib::_MAX as u16;
pub const IFLA_IPOIB_MAX: u16		= __IFLA_IPOIB_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum IpoibMode {
    DATAGRAM	= 0, // using unreliable datagram QPs
    CONNECTED	= 1, // using connected QPs
}

// HSR section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Hsr {
    UNSPEC		= 0,
    SLAVE1		= 1,
    SLAVE2		= 2,
    MULTICAST_SPEC	= 3,	// Last byte of supervision addr
    SUPERVISION_ADDR	= 4,	// Supervision frame multicast addr
    SEQ_NR		= 5,
    VERSION		= 6,	// HSR version
    _MAX		= 7,
}
pub const IFLA_HSR_UNSPEC: u16			= Hsr::UNSPEC as u16;
pub const IFLA_HSR_SLAVE1: u16			= Hsr::SLAVE1 as u16;
pub const IFLA_HSR_SLAVE2: u16			= Hsr::SLAVE2 as u16;
pub const IFLA_HSR_MULTICAST_SPEC: u16		= Hsr::MULTICAST_SPEC as u16;
pub const IFLA_HSR_SUPERVISION_ADDR: u16	= Hsr::SUPERVISION_ADDR as u16;
pub const IFLA_HSR_SEQ_NR: u16			= Hsr::SEQ_NR as u16;
pub const IFLA_HSR_VERSION: u16			= Hsr::VERSION as u16;
pub const __IFLA_HSR_MAX: u16			= Hsr::_MAX as u16;
pub const IFLA_HSR_MAX: u16			= __IFLA_HSR_MAX - 1;

// STATS section
#[repr(C)]
pub struct IfStatsMsg {
    pub family: u8,
    _pad1: u8,
    _pad2: u16,
    pub ifindex: u32,
    pub filter_mask: u32,
}

// A stats attribute can be netdev specific or a global stat.
// For netdev stats, lets use the prefix IFLA_STATS_LINK_
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)] // maybe
pub enum Stats {
    UNSPEC		= 0,	// also used as 64bit pad attribute
    LINK_64		= 1,
    LINK_XSTATS		= 2,
    LINK_XSTATS_SLAVE	= 3,
    LINK_OFFLOAD_XSTATS	= 4,
    AF_SPEC		= 5,
    _MAX		= 6,
}
pub const IFLA_STATS_UNSPEC: u16		= Stats::UNSPEC as u16;
pub const IFLA_STATS_LINK_64: u16		= Stats::LINK_64 as u16;
pub const IFLA_STATS_LINK_XSTATS: u16		= Stats::LINK_XSTATS as u16;
pub const IFLA_STATS_LINK_XSTATS_SLAVE: u16	= Stats::LINK_XSTATS_SLAVE as u16;
pub const IFLA_STATS_LINK_OFFLOAD_XSTATS: u16	= Stats::LINK_OFFLOAD_XSTATS as u16;
pub const IFLA_STATS_AF_SPEC: u16		= Stats::AF_SPEC as u16;
pub const __IFLA_STATS_MAX: u16			= Stats::_MAX as u16;
pub const IFLA_STATS_MAX: u16			= __IFLA_STATS_MAX - 1;

#[allow(non_snake_case)]
pub fn IFLA_STATS_FILTER_BIT(ATTR: u16) -> u16 {
    1 << (ATTR - 1)
}

// These are embedded into IFLA_STATS_LINK_XSTATS:
// [IFLA_STATS_LINK_XSTATS]
// -> [LINK_XSTATS_TYPE_xxx]
//    -> [rtnl link type specific attributes]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum LinkXstatsType {
    UNSPEC	= 0,
    BRIDGE	= 1,
    _MAX	= 2,
}
pub const LINK_XSTATS_TYPE_UNSPEC: u16	 = LinkXstatsType::UNSPEC as u16;
pub const LINK_XSTATS_TYPE_BRIDGE: u16	 = LinkXstatsType::BRIDGE as u16;
pub const __LINK_XSTATS_TYPE_MAX: u16	 = LinkXstatsType::_MAX as u16;
pub const LINK_XSTATS_TYPE_MAX: u16	 = __LINK_XSTATS_TYPE_MAX - 1;

// These are stats embedded into IFLA_STATS_LINK_OFFLOAD_XSTATS
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum OffloadXstats {
    UNSPEC	= 0,
    CPU_HIT	= 1,	// struct rtnl_link_stats64
    _MAX	= 2,
}
pub const IFLA_OFFLOAD_XSTATS_UNSPEC: u16	= OffloadXstats::UNSPEC as u16;
pub const IFLA_OFFLOAD_XSTATS_CPU_HIT: u16	= OffloadXstats::CPU_HIT as u16;
pub const __IFLA_OFFLOAD_XSTATS_MAX: u16	= OffloadXstats::_MAX as u16;
pub const IFLA_OFFLOAD_XSTATS_MAX: u16		= __IFLA_OFFLOAD_XSTATS_MAX - 1;

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
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum XdpAttached {
    NONE	= 0,
    DRV		= 1,
    SKB		= 2,
    HW		= 3,
}
pub const XDP_ATTACHED_NONE: u8	= XdpAttached::NONE as u8;
pub const XDP_ATTACHED_DRV: u8	= XdpAttached::DRV as u8;
pub const XDP_ATTACHED_SKB: u8	= XdpAttached::SKB as u8;
pub const XDP_ATTACHED_HW: u8	= XdpAttached::HW as u8;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Xdp {
    UNSPEC	= 0,
    FD		= 1,
    ATTACHED	= 2,
    FLAGS	= 3,
    PROG_ID	= 4,
    _MAX	= 5,
}
pub const IFLA_XDP_UNSPEC: u16		= Xdp::UNSPEC as u16;
pub const IFLA_XDP_FD: u16		= Xdp::FD as u16;
pub const IFLA_XDP_ATTACHED: u16	= Xdp::ATTACHED as u16;
pub const IFLA_XDP_FLAGS: u16		= Xdp::FLAGS as u16;
pub const IFLA_XDP_PROG_ID: u16		= Xdp::PROG_ID as u16;
pub const __IFLA_XDP_MAX: u16		= Xdp::_MAX as u16;
pub const IFLA_XDP_MAX: u16		= __IFLA_XDP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Event {
    NONE		= 0,
    REBOOT		= 1,	// internal reset / reboot
    FEATURES		= 2,	// change in offload features
    BONDING_FAILOVER	= 3,	// change in active slave
    NOTIFY_PEERS	= 4,	// re-sent grat. arp/ndisc
    IGMP_RESEND		= 5,	// re-sent IGMP JOIN
    BONDING_OPTIONS	= 6,	// change in bonding options
}
pub const IFLA_EVENT_NONE: u32			= Event::NONE as u32;
pub const IFLA_EVENT_REBOOT: u32		= Event::REBOOT as u32;
pub const IFLA_EVENT_FEATURES: u32		= Event::FEATURES as u32;
pub const IFLA_EVENT_BONDING_FAILOVER: u32	= Event::BONDING_FAILOVER as u32;
pub const IFLA_EVENT_NOTIFY_PEERS: u32		= Event::NOTIFY_PEERS as u32;
pub const IFLA_EVENT_IGMP_RESEND: u32		= Event::IGMP_RESEND as u32;
pub const IFLA_EVENT_BONDING_OPTIONS: u32	= Event::BONDING_OPTIONS as u32;
