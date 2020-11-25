// IFLA_PROTINFO
// br_getlink -> br_netlink::br_fill_ifinfo
// br_ifinfo_notify -> br_netlink::br_fill_ifinfo
// rtnetlink::ndo_dflt_bridge_getlink
pub enum IfAttr<'a> {
    Unspec,
    Address(&'a [u8]),
    Broadcast(&'a [u8]),
    Ifname(&str),
    Mtu(u32),
    Link(u32),
    Qdisc(&str),
    Stats(super::LinkStats),
    Cost(&'a [u8]),	// not used
    Priority(&'a [u8]),	// not used,
    Master(u32),
    Wireless(&'a [u8]),	// varlen
    Protinfo		// 12,
    Txqlen		// 13,
    Map			// 14,
    Weight		// 15,
    Operstate		// 16,
    Linkmode		// 17,
    Linkinfo		// 18,
    NetNsPid		// 19,
    Ifalias		// 20,
    NumVf		// 21,
    VfinfoList		// 22,
    Stats64		// 23,
    VgPorts		// 24,
    PortSelf		// 25,
    AfSpec		// 26,
    Group		// 27,
    NetNsFd		// 28,
    ExtMask		// 29,
    Promiscuity 	// 30,
    NumTxQueues 	// 31,
    NumRxQueues 	// 32,
    Carrier		// 33,
    PhysPortId		// 34,
    CarrierChanges	// 35,
    PhysSwitchId	// 36,
    LinkNetnsid		// 37,
    PhysPortName	// 38,
    ProtoDown		// 39,
    GsoMaxSegs		// 40,
    GsoMaxSize		// 41,
    Pad			// 42,
    Xdp			// 43,
    Event		// 44,
    NewNetnsid		// 45,
    IfNetnsid		// 46,
    CarrierUpCount	// 47,
    CarrierDownCount	// 48,
    NewIfindex		// 49,
}

pub struct BrportProtInfo {
    state: Some(u8),
    priority: Some(u16),
    cost: Some(u32),
    mode: Some(u8),
    guard: Some(u8),
    protect: Some(u8),
    fast_leave: Some(u8),
    learning: Some(u8),
    unicast_flood: Some(u8),
    proxyarp: Some(u8),
    learning_sync: Some(u8),
    proxyarp_wifi: Some(u8),
    root_id: Some(super::IflaBridgeId),
    bridge_id: Some(super::IflaBridgeId),
    designated_port: Some(u16),
    designated_cost: Some(u16),
    id: Some(u16),
    no: Some(u16),
    topology_change_ack: Some(u8),
    config_pending: Some(u8),
    message_age_timer: Some(u64),
    forward_delay_timer: Some(u64),
    hold_timer: Some(u64),
    flush: Some(u8), // set only
    multicast_router: Some(u8),
    // XXX: pad: ???,
    mcast_flood: Some(u8),
    mcast_to_ucast: Some(u8),
    vlan_tunnel: Some(u8),
    bcast_flood: Some(u8),
    group_fwd_mask: Some(u16),
    neigh_suppress: Some(u8),
}

pub struct Inet6ProtInfo {
}

impl From<u16> for IfType {
    fn from(v: u16) -> Self {
        unsafe { ::std::mem::transmute(v) }
    }
}

impl Into<u16> for IfType {
    fn into(self) -> u16 {
        self as u16
    }
}
