#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum IpConntrackInfo {
    // Part of an established connection (either direction).
    Established		= 0,

    // Like NEW, but related to an existing connection, or ICMP error
    // (in either direction).
    Related		= 1,

    // Started a new connection to track (only
    // IP_CT_DIR_ORIGINAL); may be a retransmission.
    New			= 2,

    // >= this indicates reply direction
    IsReply		= 3,

    // EstablishedReply	= 3 - Establishd(0) + IsReply(3) ?,
    // RelatedReply	= 4 - Related(1) + IsReply(3) ?,

    // Number of distinct IP_CT types.
    Number		= 5,

    // NewReply		= Number(4),
    Untracked		= 7,
}
pub const IP_CT_ESTABLISHED: u8		= IpConntrackInfo::Established as u8;
pub const IP_CT_RELATED: u8		= IpConntrackInfo::Related as u8;
pub const IP_CT_NEW: u8			= IpConntrackInfo::New as u8;
pub const IP_CT_IS_REPLY: u8		= IpConntrackInfo::IsReply as u8;
pub const IP_CT_ESTABLISHED_REPLY: u8	= IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
pub const IP_CT_RELATED_REPLY: u8	= IP_CT_RELATED + IP_CT_IS_REPLY;
pub const IP_CT_NUMBER: u8		= IpConntrackInfo::Number as u8;
pub const IP_CT_NEW_REPLY: u8		= IP_CT_NUMBER;
pub const IP_CT_UNTRACKED: u8		= IpConntrackInfo::Untracked as u8;

pub const NFCT_STATE_INVALID_BIT: u32	= 1 << 0;
#[allow(non_snake_case)]
pub const fn NF_CT_STATE_BIT(ctinfo: u8) -> u32 {
    1 << ((ctinfo) % IP_CT_IS_REPLY + 1)
}
pub const NF_CT_STATE_UNTRACKED_BIT: u32	= 1 << 6;

pub const IPS_EXPECTED_BIT: u8		= 0;
pub const IPS_SEEN_REPLY_BIT: u8	= 1;
pub const IPS_ASSURED_BIT: u8		= 2;
pub const IPS_CONFIRMED_BIT: u8		= 3;
pub const IPS_SRC_NAT_BIT: u8		= 4;
pub const IPS_DST_NAT_BIT: u8		= 5;
pub const IPS_SEQ_ADJUST_BIT: u8	= 6;
pub const IPS_SRC_NAT_DONE_BIT: u8	= 7;
pub const IPS_DST_NAT_DONE_BIT: u8	= 8;
pub const IPS_DYING_BIT: u8		= 9;
pub const IPS_FIXED_TIMEOUT_BIT: u8	= 10;
pub const IPS_TEMPLATE_BIT: u8		= 11;
pub const IPS_UNTRACKED_BIT: u8		= 12;
pub const IPS_HELPER_BIT: u8		= 13;
pub const IPS_OFFLOAD_BIT: u8		= 14;
pub const IPS_HW_OFFLOAD_BIT: u8	= 15;
pub const __IPS_MAX_BIT: u8		= 16;

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum IpConntrackStatus { // unsigned int
    // It's an expected connection: bit 0 set.  This bit never changed
    Expected		= 1 << IPS_EXPECTED_BIT,

    // We've seen packets both ways: bit 1 set.  Can be set, not unset.
    SeenReply		= 1 << IPS_SEEN_REPLY_BIT,

    // Conntrack should never be early-expired.
    Assured		= 1 << IPS_ASSURED_BIT,

    // Connection is confirmed: originating packet has left box
    Confirmed		= 1 << IPS_CONFIRMED_BIT,

    // Connection needs src nat in orig dir.  This bit never changed.
    SrcNat		= 1 << IPS_SRC_NAT_BIT,

    // Connection needs dst nat in orig dir.  This bit never changed.
    DstNat		= 1 << IPS_DST_NAT_BIT,

    // Both together.
    NatMask		= (1 << IPS_SRC_NAT_BIT) | (1 << IPS_DST_NAT_BIT),

    // Connection needs TCP sequence adjusted.
    SeqAdjust		= 1 << IPS_SEQ_ADJUST_BIT,

    // NAT initialization bits.
    SrcNatDone		= 1 << IPS_SRC_NAT_DONE_BIT,

    DstNatDone		= 1 << IPS_DST_NAT_DONE_BIT,

    // Both together
    // NatDoneMask	= (Self::DstNatDone as u32) | (Self::DstNatDone as u32),

    // Connection is dying (removed from lists), can not be unset.
    Dying		= 1 << IPS_DYING_BIT,

    // Connection has fixed timeout.
    FixedTimeout	= 1 << IPS_FIXED_TIMEOUT_BIT,

    // Conntrack is a template
    Template		= 1 << IPS_TEMPLATE_BIT,

    // Conntrack is a fake untracked entry. Obsolete and not used anymore
    Untracked		= 1 << IPS_UNTRACKED_BIT,

    // Conntrack got a helper explicitly attached via CT target.
    Helper		= 1 << IPS_HELPER_BIT,

    // Conntrack has been offloaded to flow table.
    Offload		= 1 << IPS_OFFLOAD_BIT,

    /* Conntrack has been offloaded to hardware. */
    HwOffload		= 1 << IPS_HW_OFFLOAD_BIT,

    // Be careful here, modifying these bits can make things messy,
    // so don't let users modify them directly.
    UnchangeableMask	=
        IPS_NAT_DONE_MASK as u32
        | Self::NatMask as u32
        | Self::Expected as u32
        | Self::Confirmed as u32
        | Self::Dying as u32
        | Self::SeqAdjust as u32
        | Self::Template as u32
        | Self::Untracked as u32
        | Self::Offload as u32
        | Self::HwOffload as u32,
}
pub const IPS_EXPECTED: u32		= IpConntrackStatus::Expected as u32;
pub const IPS_SEEN_REPLY: u32		= IpConntrackStatus::SeenReply as u32;
pub const IPS_ASSURED: u32		= IpConntrackStatus::Assured as u32;
pub const IPS_CONFIRMED: u32		= IpConntrackStatus::Confirmed as u32;
pub const IPS_SRC_NAT: u32		= IpConntrackStatus::SrcNat as u32;
pub const IPS_DST_NAT: u32		= IpConntrackStatus::DstNat as u32;
pub const IPS_NAT_MASK: u32		= IpConntrackStatus::NatMask as u32;
pub const IPS_SEQ_ADJUST: u32		= IpConntrackStatus::SeqAdjust as u32;
pub const IPS_SRC_NAT_DONE: u32		= IpConntrackStatus::SrcNatDone as u32;
pub const IPS_DST_NAT_DONE: u32		= IpConntrackStatus::DstNatDone as u32;
pub const IPS_NAT_DONE_MASK: u32	= IpConntrackStatus::DstNatDone as u32 | IpConntrackStatus::SrcNatDone as u32;
pub const IPS_DYING: u32		= IpConntrackStatus::Dying as u32;
pub const IPS_FIXED_TIMEOUT: u32	= IpConntrackStatus::FixedTimeout as u32;
pub const IPS_TEMPLATE: u32		= IpConntrackStatus::Template as u32;
pub const IPS_UNTRACKED: u32		= IpConntrackStatus::Untracked as u32;
pub const IPS_HELPER: u32		= IpConntrackStatus::Helper as u32;
pub const IPS_OFFLOAD: u32		= IpConntrackStatus::Offload as u32;
pub const IPS_HW_OFFLOAD: u32		= IpConntrackStatus::HwOffload as u32;
pub const IPS_UNCHANGEABLE_MASK: u32	= IpConntrackStatus::UnchangeableMask as u32;

/* Connection tracking event types */
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum IpConntrackEvents { // shift bit
    New,		// new conntrack
    Related,		// related conntrack
    Destroy,		// destroyed conntrack
    Reply,		// connection has seen two-way traffic
    Assured,		// connection status has changed to assured
    Protoinfo,		// protocol information has changed
    Helper,		// new helper has been set
    Mark,		// new mark has been set
    Seqadj,		// sequence adjustment has changed
    // NATSEQADJ	= SEQADJ
    Secmark,		// new security mark has been set
    Label,		// new connlabel has been set
    _MAX
}
pub const IPCT_NEW: u8		= IpConntrackEvents::New as u8;
pub const IPCT_RELATED: u8	= IpConntrackEvents::Related as u8;
pub const IPCT_DESTROY: u8	= IpConntrackEvents::Destroy as u8;
pub const IPCT_REPLY: u8	= IpConntrackEvents::Reply as u8;
pub const IPCT_ASSURED: u8	= IpConntrackEvents::Assured as u8;
pub const IPCT_PROTOINFO: u8	= IpConntrackEvents::Protoinfo as u8;
pub const IPCT_HELPER: u8	= IpConntrackEvents::Helper as u8;
pub const IPCT_MARK: u8		= IpConntrackEvents::Mark as u8;
pub const IPCT_SEQADJ: u8	= IpConntrackEvents::Seqadj as u8;
pub const IPCT_NATSEQADJ: u8	= IpConntrackEvents::Seqadj as u8;
pub const IPCT_SECMARK: u8	= IpConntrackEvents::Secmark as u8;
pub const IPCT_LABEL: u8	= IpConntrackEvents::Label as u8;

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum IpConntrackExpectEvents {
    New		= 0,	// new expectation
    Destroy	= 1,	// destroyed expectation
}
pub const IPEXP_NEW: u8		= IpConntrackExpectEvents::New as u8;
pub const IPEXP_DESTROY: u8	= IpConntrackExpectEvents::Destroy as u8;

// expectation flags - unsigned int
pub const NF_CT_EXPECT_PERMANENT: u32	= 0x1;
pub const NF_CT_EXPECT_INACTIVE: u32	= 0x2;
pub const NF_CT_EXPECT_USERSPACE: u32	= 0x4;
