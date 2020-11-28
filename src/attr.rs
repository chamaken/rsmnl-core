use std::{mem::size_of, str, slice};

extern crate libc;
extern crate errno;

use std::marker::PhantomData;
use errno::Errno;
use crate::netlink as netlink;
use netlink::Nlattr;
use crate::{CbStatus, AttrDataType, Result, Msghdr};

/// Netlink Type-Length-Value (TLV) attribute:
/// ```text
/// |<-- 2 bytes -->|<-- 2 bytes -->|<-- variable -->|
/// -------------------------------------------------
/// |     length    |      type     |      value     |
/// -------------------------------------------------
/// |<--------- header ------------>|<-- payload --->|
/// ```
/// The payload of the Netlink message contains sequences of attributes that are
/// expressed in TLV format.
///
/// @imitates: [netlink::struct nlattr]
#[repr(C)]
pub struct Attr<'a> {
    pub nla_len: u16,
    pub nla_type: u16,
    _nlh: PhantomData<Msghdr<'a>>,
}

/// `not implements [libmnl::mnl_attr_get_len]`
impl <'a> Attr<'a> {
    pub const HDRLEN: usize
        = ((size_of::<Nlattr>() + crate::ALIGNTO - 1)
           & !(crate::ALIGNTO - 1));

    /// get type of netlink attribute
    ///
    /// This function returns the attribute type.
    ///
    /// @imitates: [libmnl::mnl_attr_get_type]
    pub fn atype(&self) -> u16 {
        self.nla_type & netlink::NLA_TYPE_MASK
    }

    /// get the attribute payload-value length
    ///
    /// This function returns the attribute payload-value length.
    ///
    /// @imitates: [libmnl::mnl_attr_get_payload_len]
    pub fn payload_len(&self) -> u16 {
        self.nla_len - Self::HDRLEN as u16
    }

    /// get pointer to the attribute payload
    ///
    /// This function return a immutable reference to the attribute payload.
    ///
    /// @imitates: [libmnl::mnl_attr_get_payload]
    unsafe fn payload_raw<T>(&self) -> &T {
        &(*((self as *const _ as *const u8).offset(Self::HDRLEN as isize) as *const T))
    }

    /// get pointer to the attribute payload
    ///
    /// This function return a mutable reference to the attribute payload.
    ///
    /// @imitates: [libmnl::mnl_attr_get_payload]
    pub unsafe fn payload_raw_mut<T>(&mut self) -> &mut T {
        &mut (*((self as *mut _ as *mut u8).offset(Self::HDRLEN as isize) as *mut T))
    }

    /// check if there is room for an attribute in a buffer
    ///
    /// This function is used to check that a buffer, which is supposed to
    /// contain an attribute, has enough room for the attribute that it stores,
    /// i.e. this function can be used to verify that an attribute is neither
    /// malformed nor truncated.
    ///
    /// This function does not return `Err` in case of error since it is
    /// intended for iterations. Thus, it returns true on success and false on
    /// error.
    ///
    /// The len parameter may be negative in the case of malformed messages
    /// during attribute iteration, that is why we use a signed integer.
    ///
    /// @imitates: [libmnl::mnl_attr_ok]
    pub fn ok(&self, len: isize) -> bool {
        len > Self::HDRLEN as isize &&
            self.nla_len as usize >= Self::HDRLEN &&
            self.nla_len as isize <= len
    }

    /// get the next attribute in the payload of a netlink message
    ///
    /// This function returns a pointer to the next attribute after the one
    /// passed as parameter.
    ///
    /// @imitates: [libmnl::mnl_attr_next]
    pub unsafe fn next(&self) -> &Self {
        & *((self as *const _ as *const u8).offset(crate::align(self.nla_len as usize) as isize) as *const Self)
    }

    /// check if the attribute type is valid.
    ///
    /// This function allows to check if the attribute type is higher than the
    /// maximum supported type. On success, this function returns `Ok`.
    ///
    /// Strict attribute checking in user-space is not a good idea since you may
    /// run an old application with a newer kernel that supports new
    /// attributes. This leads to backward compatibility breakages in
    /// user-space. Better check if you support an attribute, if not, skip it.
    ///
    /// @imitates: [libmnl::mnl_attr_type_valid]
    pub fn type_valid(&self, max: u16) -> Result<()> {
        if self.atype() > max {
            return Err(Errno(libc::EOPNOTSUPP));
        }
        Ok(())
    }

    pub fn type_valid2(&self, max: impl Into::<u16>) -> Result<()> {
        if self.atype() > max.into() {
            return Err(Errno(libc::EOPNOTSUPP));
        }
        Ok(())
    }
}

/// @imitates: [mnl_attr_data_type_len]
fn data_type_len(atype: AttrDataType) -> u16 {
    match atype {
        AttrDataType::U8 =>    size_of::<u8>() as u16,
        AttrDataType::U16 =>   size_of::<u16>() as u16,
        AttrDataType::U32 =>   size_of::<u32>() as u16,
        AttrDataType::U64 =>   size_of::<u64>() as u16,
        AttrDataType::MSecs => size_of::<u64>() as u16,
        _ => 0,
    }
}

impl <'a> Attr<'a> {
    /// @imitates: [__mnl_attr_data_type_len]
    fn _validate(&self, atype: AttrDataType, exp_len: u16) -> Result<()> {
        let attr_len = self.payload_len();

        if attr_len < exp_len {
            return Err(Errno(libc::ERANGE));
        }
        match atype {
            AttrDataType::Flag =>  if attr_len > 0 {
                return Err(Errno(libc::ERANGE));
            },
            AttrDataType::NulString => {
                if attr_len == 0 {
                    return Err(Errno(libc::ERANGE));
                }
                if unsafe { *(self as *const _ as *const u8).offset((attr_len - 1) as isize) != 0 } {
                    return Err(Errno(libc::EINVAL));
                }
            },
            AttrDataType::String => if attr_len == 0 {
                return Err(Errno(libc::ERANGE));
            },
            AttrDataType::Nested => if attr_len != 0 && attr_len < Self::HDRLEN as u16 {
                return Err(Errno(libc::ERANGE));
            },
            _ => {},
        }
        if exp_len != 0 && attr_len > exp_len {
                return Err(Errno(libc::ERANGE));
        }

        Ok(())
    }

    /// validate netlink attribute (simplified version)
    ///
    /// The validation is based on the data type. Specifically, it checks that
    /// integers (u8, u16, u32 and u64) have enough room for them.
    ///
    /// @imitates: [libmnl::mnl_attr_validate]
    pub fn validate(&self, atype: AttrDataType) -> Result<()> {
        self._validate(atype, data_type_len(atype))
    }

    /// validate netlink attribute (extended version)
    ///
    /// This function allows to perform a more accurate validation for
    /// attributes whose size is variable.
    ///
    /// @imitates: [libmnl::mnl_attr_validate2]
    pub fn validate2<T: Sized>(&self, atype: AttrDataType) -> Result<()> {
        self._validate(atype, size_of::<T>() as u16)
    }
}

/// A struct for nesteds `Attr` stream iterator.
///
/// @imitates: [libmnl::mnl_attr_for_each_nested]
pub struct NestAttr<'a> {
    head: &'a Attr<'a>,
    cur: &'a Attr<'a>,
}

impl <'a> NestAttr<'a> {
    pub fn next(&mut self) -> Option<&'a Attr<'a>> {
        if self.cur.ok(unsafe { self.head.payload_raw::<u8>() } as *const _ as isize
                       + self.head.payload_len() as isize
                       - self.cur as *const _ as isize) {
            let next = unsafe { self.cur.next() };
            let ret = Some(self.cur);
            self.cur = next;
            ret
        } else {
            None
        }
    }
}

impl <'a> Attr<'a> {
    /// parse attributes inside a nest
    ///
    /// This function allows to iterate over the sequence of attributes that
    /// compose the Netlink message. You can then put the attribute in an array
    /// as it usually happens at this stage or you can use any other data
    /// structure (such as lists or trees).
    ///
    /// @imitates: [mnl_attr_parse_nested]
    pub fn parse_nested<T: FnMut(&'a Self) -> crate::CbResult>
        (&'a self, mut cb: T) -> crate::CbResult
    {
        let mut ret: crate::CbResult = crate::gen_errno!(libc::ENOENT);
        let mut nested = NestAttr {
            head: self,
            cur:  unsafe { self.payload_raw::<crate::Attr>() },
        };
        while let Some(attr) = nested.next() {
            ret = cb(attr);
            match ret {
                Ok(CbStatus::Ok) => {},
                _ => return ret,
            }
        }
        ret
    }
}

impl <'a> Attr<'a> {
    /// returns `Copy` able attribute payload.
    ///
    /// @imitates: [libmnl::mnl_attr_get_u8,
    ///             libmnl::mnl_attr_get_u16,
    ///             libmnl::mnl_attr_get_u32,
    ///             libmnl::mnl_attr_get_u64]
    pub fn value<T: Copy>(&self) -> Result<T> {
        Ok(*(self.ref_value::<T>()?))
    }

    /// returns attribute payload as a reference.
    pub fn ref_value<T>(&self) -> Result<&T> {
        if size_of::<T>() > self.payload_len() as usize {
            return Err(Errno(libc::EINVAL));
        }
        unsafe { Ok(self.payload_raw::<T>()) }
    }

    /// returns `&str` string attribute.
    ///
    /// This function returns the payload of string attribute value.
    ///
    /// @imitates: [libmnl::mnl_attr_get_str]
    pub fn str_value(&self) -> Result<&str> {
        let s = unsafe {
            slice::from_raw_parts(
                (self as *const _ as *const u8).offset(Self::HDRLEN as isize),
                self.payload_len() as usize)
        };
        str::from_utf8(s)
            .map_err(|_| Errno(libc::EILSEQ))
    }

    pub fn bytes_value(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.ref_value::<u8>().unwrap(),
                self.payload_len() as usize)
        }
    }
}

pub trait AttrSet<'a>: std::marker::Sized {
    type AttrType: std::convert::TryFrom<u16>;

    fn new() -> Self;
    fn len() -> usize;
    fn atype(&Attr) -> std::result::Result<Self::AttrType, errno::Errno>;

    fn get(&self, Self::AttrType) -> Option<&Attr>;
    fn set(&mut self, Self::AttrType, a: &'a Attr);

    fn from_nlmsg(offset: usize, nlh: &'a Msghdr) -> std::result::Result<Self, crate::GenError> {
        let mut tb = Self::new();
        nlh.parse(offset, |attr: &Attr| {
            tb.set(Self::atype(attr)?, attr);
            Ok(crate::CbStatus::Ok)
        })?;
        Ok(tb)
    }

    fn from_nest(nest: &'a Attr) -> std::result::Result<Self, crate::GenError> {
        nest.validate(crate::AttrDataType::Nested)?;
        let mut tb = Self::new();
        nest.parse_nested(|attr: &Attr| {
            tb.set(Self::atype(attr)?, attr);
            Ok(crate::CbStatus::Ok)
        })?;
        Ok(tb)
    }
}
