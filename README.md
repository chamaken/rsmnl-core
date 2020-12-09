rslmnl
=======

A pure Rust lib for netlink, imitating libmnl.
Tends to be a successor of crslmnl, and (I think) more rusty.

sample
------

see examples


links
-----

* libmnl: http://netfilter.org/projects/libmnl/


differences
-----------

* nlmsghdr is represented in two ways, by its role
  - msgvec::Header for write (put attr). you can set nlmsg_ member but can not nlmsg_len,
    which is handled by push (original put) functions.
  - nlmsg::Msghdr for read (get attr). you can not handle mutable one, only getting values
    via callback.

* Use MesVec.push() to put attr, not Nlmsg.put()

* (by using rsmnl-derive macro)
  validation is done on getting value, not in parsing.

* No batch specific struct.
  Rather than use msgvec::MsgVec, similar to original batch struct,
  to construct nlmsg.


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