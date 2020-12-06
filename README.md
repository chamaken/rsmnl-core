rslmnl
=======

A pure Rust lib for netlink, imitating libmnl.
Tends to be a successor of crsmnl, and (I think) more rusty.

sample
------

see examples


links
-----

* libmnl: http://netfilter.org/projects/libmnl/


differences
-----------

* (by using rsmnl-derive macro)
  validation is not done in parse, but getting value.


libmnl
------
NL_ATTR_TYPE_FLAG: NLA_FLAG
NL_ATTR_TYPE_NESTED_ARRAY: NLA_NESTED_ARRAY
  nla_nest_start_noflag(skb, i + 1)
+static int nla_validate_array(const struct nlattr *head, int len, int maxtype,
+			      const struct nla_policy *policy,
+			      struct netlink_ext_ack *extack)
+{

NL_ATTR_TYPE_NESTED: attr.nla_type & NLA_F_NESTED?
  nla_nest_start