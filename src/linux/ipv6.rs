use errno::Errno;

use {Msghdr, Attr, AttrTbl, Result};

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, NlaType)]
#[tbname="DevconfTbl"]
pub enum Devconf {
    #[nla_type(i32, forwarding)]
    Forwarding = 0,

    #[nla_type(i32, hop_limit)]
    Hoplimit,

    #[nla_type(i32, mtu6)]
    Mtu6,

    #[nla_type(i32, accept_ra)]
    AcceptRa,

    #[nla_type(i32, accept_redirects)]
    AcceptRedirects,

    #[nla_type(i32, autoconf)]
    Autoconf,

    #[nla_type(i32, dad_transmits)]
    DadTransmits,

    #[nla_type(i32, rtr_solicits)]
    RtrSolicits,

    #[nla_type(i32, rtr_solicit_interval)]
    RtrSolicitInterval,

    #[nla_type(i32, rtr_solicit_delay)]
    RtrSolicitDelay,

    #[nla_type(i32, use_tempaddr)]
    UseTempaddr,

    #[nla_type(i32, temp_valid_lft)]
    TempValidLft,

    #[nla_type(i32, temp_prefered_lft)]
    TempPreferedLft,

    #[nla_type(i32, regen_max_retry)]
    RegenMaxRetry,

    #[nla_type(i32, max_desync_factor)]
    MaxDesyncFactor,

    #[nla_type(i32, max_addresses)]
    MaxAddresses,

    #[nla_type(i32, force_mld_version)]
    ForceMldVersion,

    #[nla_type(i32, accept_ra_defrtr)]
    AcceptRaDefrtr,

    #[nla_type(i32, accept_ra_pinfo)]
    AcceptRaPinfo,

    #[nla_type(i32, accept_ra_rtr_pref)]
    AcceptRaRtrPref,

    #[nla_type(i32, rtr_probe_interval)]
    RtrProbeInterval,

    #[nla_type(i32, accept_ra_rt_info_max_plen)]
    AcceptRaRtInfoMaxPlen,

    #[nla_type(i32, proxy_ndp)]
    ProxyNdp,

    #[nla_type(i32, optimistic_dad)]
    OptimisticDad,

    #[nla_type(i32, accept_source_route)]
    AcceptSourceRoute,

    #[nla_type(i32, mc_forwarding)]
    McForwarding,

    #[nla_type(i32, disable_ipv6)]
    DisableIpv6,

    #[nla_type(i32, accept_dad)]
    AcceptDad,

    #[nla_type(i32, force_tllao)]
    ForceTllao,

    #[nla_type(i32, ndisc_notify)]
    NdiscNotify,

    #[nla_type(i32, mldv1_unsolicited_report_interval)]
    Mldv1UnsolicitedReportInterval,

    #[nla_type(i32, mldv2_unsolicited_report_interval)]
    Mldv2UnsolicitedReportInterval,

    #[nla_type(i32, suppress_frag_ndisc)]
    SupressFragNdisc,

    #[nla_type(i32, accept_ra_from_local)]
    AcceptRaFromLocal,

    #[nla_type(i32, use_optimistic)]
    UseOptimistic,

    #[nla_type(i32, accept_ra_mtu)]
    AcceptRaMtu,

    // we omit DEVCONF_STABLE_SECRET for now - net/ipv6/addrconf.c
    StableSecret,

    #[nla_type(i32, use_oif_addrs_only)]
    UseOifAddrsOnly,

    #[nla_type(i32, accept_ra_min_hop_limit)]
    AcceptRaMinHopLimit,

    #[nla_type(i32, ignore_routes_with_linkdown)]
    IgnoreRoutesWithLinkdown,

    #[nla_type(i32, drop_unicast_in_l2_multicast)]
    DropUnicastInL2Multicast,

    #[nla_type(i32, drop_unsolicited_na)]
    DropUnsolicitedNa,

    #[nla_type(i32, keep_addr_on_down)]
    KeepAddrOnDown,

    #[nla_type(i32, rtr_solicit_max_interval)]
    RtrSolicitMaxInterval,

    #[nla_type(i32, seg6_enabled)]
    Seg6Enabled,

    #[nla_type(i32, seg6_require_hmac)]
    Seg6RequireHmac,

    #[nla_type(i32, enhanced_dad)]
    EnhancedDad,

    #[nla_type(i32, addr_gen_mode)]
    AddrGenMode,

    #[nla_type(i32, disable_policy)]
    DisablePolicy,

    #[nla_type(i32, accept_ra_rt_info_min_plen)]
    AcceptRaRtInfoMinPlen,

    #[nla_type(i32, ndisc_tclass)]
    NdiscTclass,

    #[nla_type(i32, rpl_seg_enabled)]
    RplSegEnabled,

    _MAX,
}
