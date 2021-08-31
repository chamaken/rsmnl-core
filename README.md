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
    which is handled by put functions.

  - nlmsg::Msghdr for read (get attr). you can not handle mutable one, only getting it
    from callback.

  You may not specify msgvec::Header type directly, I think.


* attr validation is done on getting value, not in parsing.
  Since get fn (value(), value_ref()..). is imitate original get_..._safe().


* No batch specific struct.
  use msgvec::MsgVec, similar to original batch struct,
  to construct nlmsg.


* To put attr, use MesVec.put(), not Nlmsg.put()
