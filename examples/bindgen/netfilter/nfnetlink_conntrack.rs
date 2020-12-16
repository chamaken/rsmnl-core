/* automatically generated by rust-bindgen 0.56.0 */

pub const __BITS_PER_LONG: u32 = 64;
pub const __FD_SETSIZE: u32 = 1024;
pub const NF_NETLINK_CONNTRACK_NEW: u32 = 1;
pub const NF_NETLINK_CONNTRACK_UPDATE: u32 = 2;
pub const NF_NETLINK_CONNTRACK_DESTROY: u32 = 4;
pub const NF_NETLINK_CONNTRACK_EXP_NEW: u32 = 8;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE: u32 = 16;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32 = 32;
pub const NFNL_NFA_NEST: u32 = 32768;
pub const NFA_ALIGNTO: u32 = 4;
pub const NFNETLINK_V0: u32 = 0;
pub const NFNL_SUBSYS_NONE: u32 = 0;
pub const NFNL_SUBSYS_CTNETLINK: u32 = 1;
pub const NFNL_SUBSYS_CTNETLINK_EXP: u32 = 2;
pub const NFNL_SUBSYS_QUEUE: u32 = 3;
pub const NFNL_SUBSYS_ULOG: u32 = 4;
pub const NFNL_SUBSYS_OSF: u32 = 5;
pub const NFNL_SUBSYS_IPSET: u32 = 6;
pub const NFNL_SUBSYS_ACCT: u32 = 7;
pub const NFNL_SUBSYS_CTNETLINK_TIMEOUT: u32 = 8;
pub const NFNL_SUBSYS_CTHELPER: u32 = 9;
pub const NFNL_SUBSYS_NFTABLES: u32 = 10;
pub const NFNL_SUBSYS_NFT_COMPAT: u32 = 11;
pub const NFNL_SUBSYS_COUNT: u32 = 12;
pub type __s8 = ::std::os::raw::c_schar;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __s16 = ::std::os::raw::c_short;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __s32 = ::std::os::raw::c_int;
pub type __u32 = ::std::os::raw::c_uint;
pub type __s64 = ::std::os::raw::c_longlong;
pub type __u64 = ::std::os::raw::c_ulonglong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __kernel_fd_set {
    pub fds_bits: [::std::os::raw::c_ulong; 16usize],
}
#[test]
fn bindgen_test_layout___kernel_fd_set() {
    assert_eq!(
        ::std::mem::size_of::<__kernel_fd_set>(),
        128usize,
        concat!("Size of: ", stringify!(__kernel_fd_set))
    );
    assert_eq!(
        ::std::mem::align_of::<__kernel_fd_set>(),
        8usize,
        concat!("Alignment of ", stringify!(__kernel_fd_set))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<__kernel_fd_set>())).fds_bits as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(__kernel_fd_set),
            "::",
            stringify!(fds_bits)
        )
    );
}
pub type __kernel_sighandler_t =
    ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>;
pub type __kernel_key_t = ::std::os::raw::c_int;
pub type __kernel_mqd_t = ::std::os::raw::c_int;
pub type __kernel_old_uid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_gid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_dev_t = ::std::os::raw::c_ulong;
pub type __kernel_long_t = ::std::os::raw::c_long;
pub type __kernel_ulong_t = ::std::os::raw::c_ulong;
pub type __kernel_ino_t = __kernel_ulong_t;
pub type __kernel_mode_t = ::std::os::raw::c_uint;
pub type __kernel_pid_t = ::std::os::raw::c_int;
pub type __kernel_ipc_pid_t = ::std::os::raw::c_int;
pub type __kernel_uid_t = ::std::os::raw::c_uint;
pub type __kernel_gid_t = ::std::os::raw::c_uint;
pub type __kernel_suseconds_t = __kernel_long_t;
pub type __kernel_daddr_t = ::std::os::raw::c_int;
pub type __kernel_uid32_t = ::std::os::raw::c_uint;
pub type __kernel_gid32_t = ::std::os::raw::c_uint;
pub type __kernel_size_t = __kernel_ulong_t;
pub type __kernel_ssize_t = __kernel_long_t;
pub type __kernel_ptrdiff_t = __kernel_long_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __kernel_fsid_t {
    pub val: [::std::os::raw::c_int; 2usize],
}
#[test]
fn bindgen_test_layout___kernel_fsid_t() {
    assert_eq!(
        ::std::mem::size_of::<__kernel_fsid_t>(),
        8usize,
        concat!("Size of: ", stringify!(__kernel_fsid_t))
    );
    assert_eq!(
        ::std::mem::align_of::<__kernel_fsid_t>(),
        4usize,
        concat!("Alignment of ", stringify!(__kernel_fsid_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<__kernel_fsid_t>())).val as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(__kernel_fsid_t),
            "::",
            stringify!(val)
        )
    );
}
pub type __kernel_off_t = __kernel_long_t;
pub type __kernel_loff_t = ::std::os::raw::c_longlong;
pub type __kernel_old_time_t = __kernel_long_t;
pub type __kernel_time_t = __kernel_long_t;
pub type __kernel_time64_t = ::std::os::raw::c_longlong;
pub type __kernel_clock_t = __kernel_long_t;
pub type __kernel_timer_t = ::std::os::raw::c_int;
pub type __kernel_clockid_t = ::std::os::raw::c_int;
pub type __kernel_caddr_t = *mut ::std::os::raw::c_char;
pub type __kernel_uid16_t = ::std::os::raw::c_ushort;
pub type __kernel_gid16_t = ::std::os::raw::c_ushort;
pub type __le16 = __u16;
pub type __be16 = __u16;
pub type __le32 = __u32;
pub type __be32 = __u32;
pub type __le64 = __u64;
pub type __be64 = __u64;
pub type __sum16 = __u16;
pub type __wsum = __u32;
pub type __poll_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nfattr {
    pub nfa_len: __u16,
    pub nfa_type: __u16,
}
#[test]
fn bindgen_test_layout_nfattr() {
    assert_eq!(
        ::std::mem::size_of::<nfattr>(),
        4usize,
        concat!("Size of: ", stringify!(nfattr))
    );
    assert_eq!(
        ::std::mem::align_of::<nfattr>(),
        2usize,
        concat!("Alignment of ", stringify!(nfattr))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<nfattr>())).nfa_len as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(nfattr),
            "::",
            stringify!(nfa_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<nfattr>())).nfa_type as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(nfattr),
            "::",
            stringify!(nfa_type)
        )
    );
}
pub const nfnetlink_groups_NFNLGRP_NONE: nfnetlink_groups = 0;
pub const nfnetlink_groups_NFNLGRP_CONNTRACK_NEW: nfnetlink_groups = 1;
pub const nfnetlink_groups_NFNLGRP_CONNTRACK_UPDATE: nfnetlink_groups = 2;
pub const nfnetlink_groups_NFNLGRP_CONNTRACK_DESTROY: nfnetlink_groups = 3;
pub const nfnetlink_groups_NFNLGRP_CONNTRACK_EXP_NEW: nfnetlink_groups = 4;
pub const nfnetlink_groups_NFNLGRP_CONNTRACK_EXP_UPDATE: nfnetlink_groups = 5;
pub const nfnetlink_groups_NFNLGRP_CONNTRACK_EXP_DESTROY: nfnetlink_groups = 6;
pub const nfnetlink_groups_NFNLGRP_NFTABLES: nfnetlink_groups = 7;
pub const nfnetlink_groups_NFNLGRP_ACCT_QUOTA: nfnetlink_groups = 8;
pub const nfnetlink_groups_NFNLGRP_NFTRACE: nfnetlink_groups = 9;
pub const nfnetlink_groups___NFNLGRP_MAX: nfnetlink_groups = 10;
pub type nfnetlink_groups = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nfgenmsg {
    pub nfgen_family: __u8,
    pub version: __u8,
    pub res_id: __be16,
}
#[test]
fn bindgen_test_layout_nfgenmsg() {
    assert_eq!(
        ::std::mem::size_of::<nfgenmsg>(),
        4usize,
        concat!("Size of: ", stringify!(nfgenmsg))
    );
    assert_eq!(
        ::std::mem::align_of::<nfgenmsg>(),
        2usize,
        concat!("Alignment of ", stringify!(nfgenmsg))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<nfgenmsg>())).nfgen_family as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(nfgenmsg),
            "::",
            stringify!(nfgen_family)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<nfgenmsg>())).version as *const _ as usize },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(nfgenmsg),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<nfgenmsg>())).res_id as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(nfgenmsg),
            "::",
            stringify!(res_id)
        )
    );
}
pub const nfnl_batch_attributes_NFNL_BATCH_UNSPEC: nfnl_batch_attributes = 0;
pub const nfnl_batch_attributes_NFNL_BATCH_GENID: nfnl_batch_attributes = 1;
pub const nfnl_batch_attributes___NFNL_BATCH_MAX: nfnl_batch_attributes = 2;
pub type nfnl_batch_attributes = ::std::os::raw::c_uint;
pub const cntl_msg_types_IPCTNL_MSG_CT_NEW: cntl_msg_types = 0;
pub const cntl_msg_types_IPCTNL_MSG_CT_GET: cntl_msg_types = 1;
pub const cntl_msg_types_IPCTNL_MSG_CT_DELETE: cntl_msg_types = 2;
pub const cntl_msg_types_IPCTNL_MSG_CT_GET_CTRZERO: cntl_msg_types = 3;
pub const cntl_msg_types_IPCTNL_MSG_CT_GET_STATS_CPU: cntl_msg_types = 4;
pub const cntl_msg_types_IPCTNL_MSG_CT_GET_STATS: cntl_msg_types = 5;
pub const cntl_msg_types_IPCTNL_MSG_CT_GET_DYING: cntl_msg_types = 6;
pub const cntl_msg_types_IPCTNL_MSG_CT_GET_UNCONFIRMED: cntl_msg_types = 7;
pub const cntl_msg_types_IPCTNL_MSG_MAX: cntl_msg_types = 8;
pub type cntl_msg_types = ::std::os::raw::c_uint;
pub const ctnl_exp_msg_types_IPCTNL_MSG_EXP_NEW: ctnl_exp_msg_types = 0;
pub const ctnl_exp_msg_types_IPCTNL_MSG_EXP_GET: ctnl_exp_msg_types = 1;
pub const ctnl_exp_msg_types_IPCTNL_MSG_EXP_DELETE: ctnl_exp_msg_types = 2;
pub const ctnl_exp_msg_types_IPCTNL_MSG_EXP_GET_STATS_CPU: ctnl_exp_msg_types = 3;
pub const ctnl_exp_msg_types_IPCTNL_MSG_EXP_MAX: ctnl_exp_msg_types = 4;
pub type ctnl_exp_msg_types = ::std::os::raw::c_uint;
pub const ctattr_type_CTA_UNSPEC: ctattr_type = 0;
pub const ctattr_type_CTA_TUPLE_ORIG: ctattr_type = 1;
pub const ctattr_type_CTA_TUPLE_REPLY: ctattr_type = 2;
pub const ctattr_type_CTA_STATUS: ctattr_type = 3;
pub const ctattr_type_CTA_PROTOINFO: ctattr_type = 4;
pub const ctattr_type_CTA_HELP: ctattr_type = 5;
pub const ctattr_type_CTA_NAT_SRC: ctattr_type = 6;
pub const ctattr_type_CTA_TIMEOUT: ctattr_type = 7;
pub const ctattr_type_CTA_MARK: ctattr_type = 8;
pub const ctattr_type_CTA_COUNTERS_ORIG: ctattr_type = 9;
pub const ctattr_type_CTA_COUNTERS_REPLY: ctattr_type = 10;
pub const ctattr_type_CTA_USE: ctattr_type = 11;
pub const ctattr_type_CTA_ID: ctattr_type = 12;
pub const ctattr_type_CTA_NAT_DST: ctattr_type = 13;
pub const ctattr_type_CTA_TUPLE_MASTER: ctattr_type = 14;
pub const ctattr_type_CTA_SEQ_ADJ_ORIG: ctattr_type = 15;
pub const ctattr_type_CTA_NAT_SEQ_ADJ_ORIG: ctattr_type = 15;
pub const ctattr_type_CTA_SEQ_ADJ_REPLY: ctattr_type = 16;
pub const ctattr_type_CTA_NAT_SEQ_ADJ_REPLY: ctattr_type = 16;
pub const ctattr_type_CTA_SECMARK: ctattr_type = 17;
pub const ctattr_type_CTA_ZONE: ctattr_type = 18;
pub const ctattr_type_CTA_SECCTX: ctattr_type = 19;
pub const ctattr_type_CTA_TIMESTAMP: ctattr_type = 20;
pub const ctattr_type_CTA_MARK_MASK: ctattr_type = 21;
pub const ctattr_type_CTA_LABELS: ctattr_type = 22;
pub const ctattr_type_CTA_LABELS_MASK: ctattr_type = 23;
pub const ctattr_type_CTA_SYNPROXY: ctattr_type = 24;
pub const ctattr_type_CTA_FILTER: ctattr_type = 25;
pub const ctattr_type___CTA_MAX: ctattr_type = 26;
pub type ctattr_type = ::std::os::raw::c_uint;
pub const ctattr_tuple_CTA_TUPLE_UNSPEC: ctattr_tuple = 0;
pub const ctattr_tuple_CTA_TUPLE_IP: ctattr_tuple = 1;
pub const ctattr_tuple_CTA_TUPLE_PROTO: ctattr_tuple = 2;
pub const ctattr_tuple_CTA_TUPLE_ZONE: ctattr_tuple = 3;
pub const ctattr_tuple___CTA_TUPLE_MAX: ctattr_tuple = 4;
pub type ctattr_tuple = ::std::os::raw::c_uint;
pub const ctattr_ip_CTA_IP_UNSPEC: ctattr_ip = 0;
pub const ctattr_ip_CTA_IP_V4_SRC: ctattr_ip = 1;
pub const ctattr_ip_CTA_IP_V4_DST: ctattr_ip = 2;
pub const ctattr_ip_CTA_IP_V6_SRC: ctattr_ip = 3;
pub const ctattr_ip_CTA_IP_V6_DST: ctattr_ip = 4;
pub const ctattr_ip___CTA_IP_MAX: ctattr_ip = 5;
pub type ctattr_ip = ::std::os::raw::c_uint;
pub const ctattr_l4proto_CTA_PROTO_UNSPEC: ctattr_l4proto = 0;
pub const ctattr_l4proto_CTA_PROTO_NUM: ctattr_l4proto = 1;
pub const ctattr_l4proto_CTA_PROTO_SRC_PORT: ctattr_l4proto = 2;
pub const ctattr_l4proto_CTA_PROTO_DST_PORT: ctattr_l4proto = 3;
pub const ctattr_l4proto_CTA_PROTO_ICMP_ID: ctattr_l4proto = 4;
pub const ctattr_l4proto_CTA_PROTO_ICMP_TYPE: ctattr_l4proto = 5;
pub const ctattr_l4proto_CTA_PROTO_ICMP_CODE: ctattr_l4proto = 6;
pub const ctattr_l4proto_CTA_PROTO_ICMPV6_ID: ctattr_l4proto = 7;
pub const ctattr_l4proto_CTA_PROTO_ICMPV6_TYPE: ctattr_l4proto = 8;
pub const ctattr_l4proto_CTA_PROTO_ICMPV6_CODE: ctattr_l4proto = 9;
pub const ctattr_l4proto___CTA_PROTO_MAX: ctattr_l4proto = 10;
pub type ctattr_l4proto = ::std::os::raw::c_uint;
pub const ctattr_protoinfo_CTA_PROTOINFO_UNSPEC: ctattr_protoinfo = 0;
pub const ctattr_protoinfo_CTA_PROTOINFO_TCP: ctattr_protoinfo = 1;
pub const ctattr_protoinfo_CTA_PROTOINFO_DCCP: ctattr_protoinfo = 2;
pub const ctattr_protoinfo_CTA_PROTOINFO_SCTP: ctattr_protoinfo = 3;
pub const ctattr_protoinfo___CTA_PROTOINFO_MAX: ctattr_protoinfo = 4;
pub type ctattr_protoinfo = ::std::os::raw::c_uint;
pub const ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_UNSPEC: ctattr_protoinfo_tcp = 0;
pub const ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_STATE: ctattr_protoinfo_tcp = 1;
pub const ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_WSCALE_ORIGINAL: ctattr_protoinfo_tcp = 2;
pub const ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_WSCALE_REPLY: ctattr_protoinfo_tcp = 3;
pub const ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_FLAGS_ORIGINAL: ctattr_protoinfo_tcp = 4;
pub const ctattr_protoinfo_tcp_CTA_PROTOINFO_TCP_FLAGS_REPLY: ctattr_protoinfo_tcp = 5;
pub const ctattr_protoinfo_tcp___CTA_PROTOINFO_TCP_MAX: ctattr_protoinfo_tcp = 6;
pub type ctattr_protoinfo_tcp = ::std::os::raw::c_uint;
pub const ctattr_protoinfo_dccp_CTA_PROTOINFO_DCCP_UNSPEC: ctattr_protoinfo_dccp = 0;
pub const ctattr_protoinfo_dccp_CTA_PROTOINFO_DCCP_STATE: ctattr_protoinfo_dccp = 1;
pub const ctattr_protoinfo_dccp_CTA_PROTOINFO_DCCP_ROLE: ctattr_protoinfo_dccp = 2;
pub const ctattr_protoinfo_dccp_CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ: ctattr_protoinfo_dccp = 3;
pub const ctattr_protoinfo_dccp_CTA_PROTOINFO_DCCP_PAD: ctattr_protoinfo_dccp = 4;
pub const ctattr_protoinfo_dccp___CTA_PROTOINFO_DCCP_MAX: ctattr_protoinfo_dccp = 5;
pub type ctattr_protoinfo_dccp = ::std::os::raw::c_uint;
pub const ctattr_protoinfo_sctp_CTA_PROTOINFO_SCTP_UNSPEC: ctattr_protoinfo_sctp = 0;
pub const ctattr_protoinfo_sctp_CTA_PROTOINFO_SCTP_STATE: ctattr_protoinfo_sctp = 1;
pub const ctattr_protoinfo_sctp_CTA_PROTOINFO_SCTP_VTAG_ORIGINAL: ctattr_protoinfo_sctp = 2;
pub const ctattr_protoinfo_sctp_CTA_PROTOINFO_SCTP_VTAG_REPLY: ctattr_protoinfo_sctp = 3;
pub const ctattr_protoinfo_sctp___CTA_PROTOINFO_SCTP_MAX: ctattr_protoinfo_sctp = 4;
pub type ctattr_protoinfo_sctp = ::std::os::raw::c_uint;
pub const ctattr_counters_CTA_COUNTERS_UNSPEC: ctattr_counters = 0;
pub const ctattr_counters_CTA_COUNTERS_PACKETS: ctattr_counters = 1;
pub const ctattr_counters_CTA_COUNTERS_BYTES: ctattr_counters = 2;
pub const ctattr_counters_CTA_COUNTERS32_PACKETS: ctattr_counters = 3;
pub const ctattr_counters_CTA_COUNTERS32_BYTES: ctattr_counters = 4;
pub const ctattr_counters_CTA_COUNTERS_PAD: ctattr_counters = 5;
pub const ctattr_counters___CTA_COUNTERS_MAX: ctattr_counters = 6;
pub type ctattr_counters = ::std::os::raw::c_uint;
pub const ctattr_tstamp_CTA_TIMESTAMP_UNSPEC: ctattr_tstamp = 0;
pub const ctattr_tstamp_CTA_TIMESTAMP_START: ctattr_tstamp = 1;
pub const ctattr_tstamp_CTA_TIMESTAMP_STOP: ctattr_tstamp = 2;
pub const ctattr_tstamp_CTA_TIMESTAMP_PAD: ctattr_tstamp = 3;
pub const ctattr_tstamp___CTA_TIMESTAMP_MAX: ctattr_tstamp = 4;
pub type ctattr_tstamp = ::std::os::raw::c_uint;
pub const ctattr_nat_CTA_NAT_UNSPEC: ctattr_nat = 0;
pub const ctattr_nat_CTA_NAT_V4_MINIP: ctattr_nat = 1;
pub const ctattr_nat_CTA_NAT_V4_MAXIP: ctattr_nat = 2;
pub const ctattr_nat_CTA_NAT_PROTO: ctattr_nat = 3;
pub const ctattr_nat_CTA_NAT_V6_MINIP: ctattr_nat = 4;
pub const ctattr_nat_CTA_NAT_V6_MAXIP: ctattr_nat = 5;
pub const ctattr_nat___CTA_NAT_MAX: ctattr_nat = 6;
pub type ctattr_nat = ::std::os::raw::c_uint;
pub const ctattr_protonat_CTA_PROTONAT_UNSPEC: ctattr_protonat = 0;
pub const ctattr_protonat_CTA_PROTONAT_PORT_MIN: ctattr_protonat = 1;
pub const ctattr_protonat_CTA_PROTONAT_PORT_MAX: ctattr_protonat = 2;
pub const ctattr_protonat___CTA_PROTONAT_MAX: ctattr_protonat = 3;
pub type ctattr_protonat = ::std::os::raw::c_uint;
pub const ctattr_seqadj_CTA_SEQADJ_UNSPEC: ctattr_seqadj = 0;
pub const ctattr_seqadj_CTA_SEQADJ_CORRECTION_POS: ctattr_seqadj = 1;
pub const ctattr_seqadj_CTA_SEQADJ_OFFSET_BEFORE: ctattr_seqadj = 2;
pub const ctattr_seqadj_CTA_SEQADJ_OFFSET_AFTER: ctattr_seqadj = 3;
pub const ctattr_seqadj___CTA_SEQADJ_MAX: ctattr_seqadj = 4;
pub type ctattr_seqadj = ::std::os::raw::c_uint;
pub const ctattr_natseq_CTA_NAT_SEQ_UNSPEC: ctattr_natseq = 0;
pub const ctattr_natseq_CTA_NAT_SEQ_CORRECTION_POS: ctattr_natseq = 1;
pub const ctattr_natseq_CTA_NAT_SEQ_OFFSET_BEFORE: ctattr_natseq = 2;
pub const ctattr_natseq_CTA_NAT_SEQ_OFFSET_AFTER: ctattr_natseq = 3;
pub const ctattr_natseq___CTA_NAT_SEQ_MAX: ctattr_natseq = 4;
pub type ctattr_natseq = ::std::os::raw::c_uint;
pub const ctattr_synproxy_CTA_SYNPROXY_UNSPEC: ctattr_synproxy = 0;
pub const ctattr_synproxy_CTA_SYNPROXY_ISN: ctattr_synproxy = 1;
pub const ctattr_synproxy_CTA_SYNPROXY_ITS: ctattr_synproxy = 2;
pub const ctattr_synproxy_CTA_SYNPROXY_TSOFF: ctattr_synproxy = 3;
pub const ctattr_synproxy___CTA_SYNPROXY_MAX: ctattr_synproxy = 4;
pub type ctattr_synproxy = ::std::os::raw::c_uint;
pub const ctattr_expect_CTA_EXPECT_UNSPEC: ctattr_expect = 0;
pub const ctattr_expect_CTA_EXPECT_MASTER: ctattr_expect = 1;
pub const ctattr_expect_CTA_EXPECT_TUPLE: ctattr_expect = 2;
pub const ctattr_expect_CTA_EXPECT_MASK: ctattr_expect = 3;
pub const ctattr_expect_CTA_EXPECT_TIMEOUT: ctattr_expect = 4;
pub const ctattr_expect_CTA_EXPECT_ID: ctattr_expect = 5;
pub const ctattr_expect_CTA_EXPECT_HELP_NAME: ctattr_expect = 6;
pub const ctattr_expect_CTA_EXPECT_ZONE: ctattr_expect = 7;
pub const ctattr_expect_CTA_EXPECT_FLAGS: ctattr_expect = 8;
pub const ctattr_expect_CTA_EXPECT_CLASS: ctattr_expect = 9;
pub const ctattr_expect_CTA_EXPECT_NAT: ctattr_expect = 10;
pub const ctattr_expect_CTA_EXPECT_FN: ctattr_expect = 11;
pub const ctattr_expect___CTA_EXPECT_MAX: ctattr_expect = 12;
pub type ctattr_expect = ::std::os::raw::c_uint;
pub const ctattr_expect_nat_CTA_EXPECT_NAT_UNSPEC: ctattr_expect_nat = 0;
pub const ctattr_expect_nat_CTA_EXPECT_NAT_DIR: ctattr_expect_nat = 1;
pub const ctattr_expect_nat_CTA_EXPECT_NAT_TUPLE: ctattr_expect_nat = 2;
pub const ctattr_expect_nat___CTA_EXPECT_NAT_MAX: ctattr_expect_nat = 3;
pub type ctattr_expect_nat = ::std::os::raw::c_uint;
pub const ctattr_help_CTA_HELP_UNSPEC: ctattr_help = 0;
pub const ctattr_help_CTA_HELP_NAME: ctattr_help = 1;
pub const ctattr_help_CTA_HELP_INFO: ctattr_help = 2;
pub const ctattr_help___CTA_HELP_MAX: ctattr_help = 3;
pub type ctattr_help = ::std::os::raw::c_uint;
pub const ctattr_secctx_CTA_SECCTX_UNSPEC: ctattr_secctx = 0;
pub const ctattr_secctx_CTA_SECCTX_NAME: ctattr_secctx = 1;
pub const ctattr_secctx___CTA_SECCTX_MAX: ctattr_secctx = 2;
pub type ctattr_secctx = ::std::os::raw::c_uint;
pub const ctattr_stats_cpu_CTA_STATS_UNSPEC: ctattr_stats_cpu = 0;
pub const ctattr_stats_cpu_CTA_STATS_SEARCHED: ctattr_stats_cpu = 1;
pub const ctattr_stats_cpu_CTA_STATS_FOUND: ctattr_stats_cpu = 2;
pub const ctattr_stats_cpu_CTA_STATS_NEW: ctattr_stats_cpu = 3;
pub const ctattr_stats_cpu_CTA_STATS_INVALID: ctattr_stats_cpu = 4;
pub const ctattr_stats_cpu_CTA_STATS_IGNORE: ctattr_stats_cpu = 5;
pub const ctattr_stats_cpu_CTA_STATS_DELETE: ctattr_stats_cpu = 6;
pub const ctattr_stats_cpu_CTA_STATS_DELETE_LIST: ctattr_stats_cpu = 7;
pub const ctattr_stats_cpu_CTA_STATS_INSERT: ctattr_stats_cpu = 8;
pub const ctattr_stats_cpu_CTA_STATS_INSERT_FAILED: ctattr_stats_cpu = 9;
pub const ctattr_stats_cpu_CTA_STATS_DROP: ctattr_stats_cpu = 10;
pub const ctattr_stats_cpu_CTA_STATS_EARLY_DROP: ctattr_stats_cpu = 11;
pub const ctattr_stats_cpu_CTA_STATS_ERROR: ctattr_stats_cpu = 12;
pub const ctattr_stats_cpu_CTA_STATS_SEARCH_RESTART: ctattr_stats_cpu = 13;
pub const ctattr_stats_cpu___CTA_STATS_MAX: ctattr_stats_cpu = 14;
pub type ctattr_stats_cpu = ::std::os::raw::c_uint;
pub const ctattr_stats_global_CTA_STATS_GLOBAL_UNSPEC: ctattr_stats_global = 0;
pub const ctattr_stats_global_CTA_STATS_GLOBAL_ENTRIES: ctattr_stats_global = 1;
pub const ctattr_stats_global_CTA_STATS_GLOBAL_MAX_ENTRIES: ctattr_stats_global = 2;
pub const ctattr_stats_global___CTA_STATS_GLOBAL_MAX: ctattr_stats_global = 3;
pub type ctattr_stats_global = ::std::os::raw::c_uint;
pub const ctattr_expect_stats_CTA_STATS_EXP_UNSPEC: ctattr_expect_stats = 0;
pub const ctattr_expect_stats_CTA_STATS_EXP_NEW: ctattr_expect_stats = 1;
pub const ctattr_expect_stats_CTA_STATS_EXP_CREATE: ctattr_expect_stats = 2;
pub const ctattr_expect_stats_CTA_STATS_EXP_DELETE: ctattr_expect_stats = 3;
pub const ctattr_expect_stats___CTA_STATS_EXP_MAX: ctattr_expect_stats = 4;
pub type ctattr_expect_stats = ::std::os::raw::c_uint;
pub const ctattr_filter_CTA_FILTER_UNSPEC: ctattr_filter = 0;
pub const ctattr_filter_CTA_FILTER_ORIG_FLAGS: ctattr_filter = 1;
pub const ctattr_filter_CTA_FILTER_REPLY_FLAGS: ctattr_filter = 2;
pub const ctattr_filter___CTA_FILTER_MAX: ctattr_filter = 3;
pub type ctattr_filter = ::std::os::raw::c_uint;