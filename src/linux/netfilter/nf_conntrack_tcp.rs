// This is exposed to userspace (ctnetlink) - ip_ct_tcp.state
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum TcpConntrack { // TCP_CONNTRACK_
    None	= 0,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Listen,	// obsolete
    Max,
    Ignore,
    Retrans,
    Unack,
    TimeoutMax,
}
pub const TCP_CONNTRACK_NONE: u8	= TcpConntrack::None as u8;
pub const TCP_CONNTRACK_SYN_SENT: u8	= TcpConntrack::SynSent as u8;
pub const TCP_CONNTRACK_SYN_RECV: u8	= TcpConntrack::SynRecv as u8;
pub const TCP_CONNTRACK_ESTABLISHED: u8	= TcpConntrack::Established as u8;
pub const TCP_CONNTRACK_FIN_WAIT: u8	= TcpConntrack::FinWait as u8;
pub const TCP_CONNTRACK_CLOSE_WAIT: u8	= TcpConntrack::CloseWait as u8;
pub const TCP_CONNTRACK_LAST_ACK: u8	= TcpConntrack::LastAck as u8;
pub const TCP_CONNTRACK_TIME_WAIT: u8	= TcpConntrack::TimeWait as u8;
pub const TCP_CONNTRACK_CLOSE: u8	= TcpConntrack::Close as u8;
pub const TCP_CONNTRACK_LISTEN: u8	= TcpConntrack::Listen as u8;
pub const TCP_CONNTRACK_SYN_SENT2: u8	= TCP_CONNTRACK_LISTEN;
pub const TCP_CONNTRACK_MAX: u8		= TcpConntrack::Max as u8;
pub const TCP_CONNTRACK_IGNORE: u8	= TcpConntrack::Ignore as u8;
pub const TCP_CONNTRACK_RETRANS: u8	= TcpConntrack::Retrans as u8;
pub const TCP_CONNTRACK_UNACK: u8	= TcpConntrack::Unack as u8;
pub const TCP_CONNTRACK_TIMEOUT_MAX: u8	= TcpConntrack::TimeoutMax as u8;


// Window scaling is advertised by the sender
pub const IP_CT_TCP_FLAG_WINDOW_SCALE: u8		= 0x01;
// SACK is permitted by the sender
pub const IP_CT_TCP_FLAG_SACK_PERM: u8			= 0x02;
// This sender sent FIN first
pub const IP_CT_TCP_FLAG_CLOSE_INIT: u8			= 0x04;
// Be liberal in window checking
pub const IP_CT_TCP_FLAG_BE_LIBERAL: u8			= 0x08;
// Has unacknowledged data
pub const IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED: u8	= 0x10;
// The field td_maxack has been set
pub const IP_CT_TCP_FLAG_MAXACK_SET: u8			= 0x20;
// Marks possibility for expected RFC5961 challenge ACK
pub const IP_CT_EXP_CHALLENGE_ACK: u8 			= 0x40;
/* Simultaneous open initialized */
pub const IP_CT_TCP_SIMULTANEOUS_OPEN: u8		= 0x80;

#[repr(C)]
pub struct NfCtTcpFlags {
    pub flags: u8,
    pub mask: u8,
}
