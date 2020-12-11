what is, by example
-------------------

define:

use { Msghdr, Attr, AttrTbl, Result };

#[repr(u16)]
#[derive(..., NlaType)
pub enum Parent {
    None = 0,
    One,
    Two,
    Three,
    _MAX
}

will implements std::convert::TryFrom<u16> for Parent.
Then define nla_type by macro attribute:

    [#nla_type(u32, p_one)]
    One,

putting value to nlh: Msghdr (e.g. Nlmsghdr) can be done by:

    use mnl:: { AttrTbl, Msghdr };
    Parent::push_p_one(&mut nlv, 1234u32)

create tb data from read Msghdr, specify its name:

    #[tbname="ParentTbl"]
    pub enum Parent {

Then, value can be accessed via:

    let tb = Parent::from_nlmsg(header_offset, nlh)?;
    let one: Option<u32> = tb.p_one()?;
    let attr: Option<&Attr> = tb[Parent::One]?;


str and strz (nulstr)
---------------------

static inline int nla_put_string(struct sk_buff *skb, int attrtype,
				 const char *str)
{
	return nla_put(skb, attrtype, strlen(str) + 1, str);
}
