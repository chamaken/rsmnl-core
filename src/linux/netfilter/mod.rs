use libc::{ c_int, c_uint };

pub mod nfnetlink;
pub mod nfnetlink_log;
pub mod nfnetlink_conntrack;
pub mod nfnetlink_queue;
pub mod nf_conntrack_common;
pub mod nf_conntrack_tcp;

// Responses from hook functions.
pub const NF_DROP: c_uint		= 0;
pub const NF_ACCEPT: c_uint		= 1;
pub const NF_STOLEN: c_uint		= 2;
pub const NF_QUEUE: c_uint		= 3;
pub const NF_REPEAT: c_uint		= 4;
pub const NF_STOP: c_uint		= 5;	// Deprecated, for userspace nf_queue compatibility.
pub const NF_MAX_VERDICT: c_uint	= NF_STOP;

// we overload the higher bits for encoding auxiliary data such as the queue
// number or errno values. Not nice, but better than additional function
// arguments.
pub const NF_VERDICT_MASK: u32	=  0x000000ff;

// extra verdict flags have mask 0x0000ff00 */
pub const NF_VERDICT_FLAG_QUEUE_BYPASS: u32 = 0x00008000;

// queue number (NF_QUEUE) or errno (NF_DROP) */
pub const NF_VERDICT_QMASK: u32	= 0xffff0000;
pub const NF_VERDICT_QBITS: u8	= 16;

#[allow(non_snake_case)]
pub fn NF_QUEUE_NR(x: u32) -> u32 {
    (((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE
}

#[allow(non_snake_case)]
pub fn NF_DROP_ERR(x: i32) -> u32 {
    ((-x) << 16) as u32 | NF_DROP
}

// only for userspace compatibility */
//
// NF_VERDICT_BITS should be 8 now, but userspace might break if this changes */
pub const NF_VERDICT_BITS: u8	=  16;
// #endif

#[repr(u32)] // c_uint
#[derive(Debug, Copy, Clone)]
pub enum NfInetHooks { // NF_INET_
    // bitop? or u32
    PreRouting		= 0,
    LocalIn,
    Forward,
    LocalOut,
    PostRouting,
    Numhooks,
}
pub const NF_INET_PRE_ROUTING: c_uint	= NfInetHooks::PreRouting as c_uint;
pub const NF_INET_LOCAL_IN: c_uint	= NfInetHooks::LocalIn as c_uint;
pub const NF_INET_FORWARD: c_uint	= NfInetHooks::Forward as c_uint;
pub const NF_INET_LOCAL_OUT: c_uint	= NfInetHooks::LocalOut as c_uint;
pub const NF_INET_POST_ROUTING: c_uint	= NfInetHooks::PostRouting as c_uint;
pub const NF_INET_NUMHOOKS: c_uint	= NfInetHooks::Numhooks as c_uint;

#[repr(u32)] // c_uint
#[derive(Debug, Copy, Clone)]
pub enum NfDevHooks { // NF_NETDEV_
    Ingress	= 0,
    Numhooks,
}
pub const NF_NETDEV_INGRESS: c_uint	= NfDevHooks::Ingress as c_uint;
pub const NF_NETDEV_NUMHOOKS: c_uint	= NfDevHooks::Numhooks as c_uint;

#[repr(C)] // c_int
#[derive(Debug, Copy, Clone)]
pub enum NfProto { // NFPROTO_
    Unspec	=  0,
    Inet  	=  1,
    Ipv4   	=  2,
    Arp    	=  3,
    Netdev 	=  5,
    Bridge 	=  7,
    Ipv6   	= 10,
    Decnet 	= 12,
    Numproto	= 13,
}
pub const NFPROTO_UNSPEC: c_int		= NfProto::Unspec as c_int;
pub const NFPROTO_INET: c_int  		= NfProto::Inet as c_int;
pub const NFPROTO_IPV4: c_int  		= NfProto::Ipv4 as c_int;
pub const NFPROTO_ARP: c_int   		= NfProto::Arp as c_int;
pub const NFPROTO_NETDEV: c_int		= NfProto::Netdev as c_int;
pub const NFPROTO_BRIDGE: c_int		= NfProto::Bridge as c_int;
pub const NFPROTO_IPV6: c_int 		= NfProto::Ipv6 as c_int;
pub const NFPROTO_DECNET: c_int		= NfProto::Decnet as c_int;
pub const NFPROTO_NUMPROTO: c_int	= NfProto::Numproto as c_int;

// XXX: not implemented yet
// union nf_inet_addr {
// 	__u32		all[4];
// 	__be32		ip;
// 	__be32		ip6[4];
// 	struct in_addr	in;
// 	struct in6_addr	in6;
// };
