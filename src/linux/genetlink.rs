use std::mem;
use linux::netlink;

use errno::Errno;
use { MsgVec, Attr, AttrTbl, Result };
    
pub const GENL_NAMSIZ: usize	= 16;

pub const GENL_MIN_ID: u16	= netlink::NLMSG_MIN_TYPE;
pub const GENL_MAX_ID: u16	= 1023;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Genlmsghdr {
    pub cmd: u8,
    pub version: u8,
    pub reserved: u16,
}

pub const fn genl_hdrlen() -> u32 {
    netlink::nlmsg_align(mem::size_of::<Genlmsghdr>() as u32)
}

pub const GENL_ADMIN_PERM: u8		= 0x01;
pub const GENL_CMD_CAP_DO: u8		= 0x02;
pub const GENL_CMD_CAP_DUMP: u8		= 0x04;
pub const GENL_CMD_CAP_HASPOL: u8	= 0x08;
pub const GENL_UNS_ADMIN_PERM: u8	= 0x10;

// List of reserved static generic netlink identifiers:
pub const GENL_ID_CTRL: u16		= netlink::NLMSG_MIN_TYPE;
pub const GENL_ID_VFS_DQUOT: u16	= netlink::NLMSG_MIN_TYPE + 1;
pub const GENL_ID_PMCRAID: u16		= netlink::NLMSG_MIN_TYPE + 2;
// must be last reserved + 1
pub const GENL_START_ALLOC: u16		= netlink::NLMSG_MIN_TYPE + 3;

// Controller
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtrlCmd { // CTRL_CMD_
    Unspec,
    Newfamily,
    Delfamily,
    Getfamily,
    Newops,
    Delops,
    Getops,
    NewmcastGrp,
    DelmcastGrp,
    GetmcastGrp,	// unused
    Getpolicy,
    _MAX
}
pub const CTRL_CMD_UNSPEC: u8		= CtrlCmd::Unspec as u8;
pub const CTRL_CMD_NEWFAMILY: u8	= CtrlCmd::Newfamily as u8;
pub const CTRL_CMD_DELFAMILY: u8	= CtrlCmd::Delfamily as u8;
pub const CTRL_CMD_GETFAMILY: u8	= CtrlCmd::Getfamily as u8;
pub const CTRL_CMD_NEWOPS: u8		= CtrlCmd::Newops as u8;
pub const CTRL_CMD_DELOPS: u8		= CtrlCmd::Delops as u8;
pub const CTRL_CMD_GETOPS: u8		= CtrlCmd::Getops as u8;
pub const CTRL_CMD_NEWMCAST_GRP: u8	= CtrlCmd::NewmcastGrp as u8;
pub const CTRL_CMD_DELMCAST_GRP: u8	= CtrlCmd::DelmcastGrp as u8;
pub const CTRL_CMD_GETMCAST_GRP: u8	= CtrlCmd::GetmcastGrp as u8;
pub const CTRL_CMD_GETPOLICY: u8	= CtrlCmd::Getpolicy as u8;
pub const __CTRL_CMD_MAX: u8		= CtrlCmd::_MAX as u8;
pub const CTRL_CMD_MAX: u8		= __CTRL_CMD_MAX - 1;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtrlAttrTbl"]
pub enum CtrlAttr { // CTRL_ATTR_
    Unspec,

    #[nla_type(u16, family_id)]
    FamilyId,

    // #[nla_type(nulstr, family_name)]
    #[nla_type(nulstr, family_name)]
    FamilyName,

    #[nla_type(u32, version)]
    Version,

    #[nla_type(u32, hdrsize)]
    Hdrsize,

    #[nla_type(u32, maxattr)]
    Maxattr,

    #[nla_nest([CtrlAttrOpTbl], ops)]
    Ops,

    #[nla_nest([CtrlAttrMcastGrpTbl], mcast_groups)]
    McastGroups,

    #[nla_nest(netlink::NetlinkPolicyTypeAttrTbl, policy)]
    Policy,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtrlAttrOpTbl"]
pub enum CtrlAttrOp { // CTRL_ATTR_OP_
    Unspec,

    #[nla_type(u32, id)]
    Id,

    #[nla_type(u32, flags)]
    Flags,
    _MAX
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, NlaType)]
#[tbname="CtrlAttrMcastGrpTbl"]
pub enum CtrlAttrMcastGrp { // CTRL_ATTR_MCAST_GRP_
    Unspec,

    #[nla_type(nulstr, name)]
    #[nla_type(bytes, name_bytes)]
    Name,

    #[nla_type(u32, id)]
    Id,
    _MAX
}
