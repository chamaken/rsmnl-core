use std::{
    mem,
    fmt,
    str,
    slice,
    marker::PhantomData,
    convert::TryFrom,
};

use libc;
use errno::Errno;
use { CbStatus, CbResult, AttrDataType, Result, Msghdr };

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
/// MUST sync to linux/netlink.h::struct nlattr
/// ```
/// extern crate libc;
/// use std::mem::size_of;
/// assert!(size_of::<libc::nlattr>() == size_of::<rsmnl::Attr>());
/// let b: Vec<u8> = (0..size_of::<libc::nlattr>()).map(|x| x as u8).collect();
/// let nla = unsafe { &*(b.as_ptr() as *const _ as *const libc::nlattr) };
/// let a =  unsafe { &*(b.as_ptr() as *const _ as *const rsmnl::Attr) };
/// assert!(nla.nla_len == a.nla_len);
/// assert!(nla.nla_type == a.nla_type);
/// ```
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
        = ((mem::size_of::<Self>() + crate::ALIGNTO - 1)
           & !(crate::ALIGNTO - 1));

    /// get type of netlink attribute
    ///
    /// This function returns the attribute type.
    ///
    /// @imitates: [libmnl::mnl_attr_get_type]
    pub fn atype(&self) -> u16 {
        self.nla_type & libc::NLA_TYPE_MASK as u16
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
    unsafe fn payload_ptr(&self) -> *const u8 {
        (self as *const _ as *const u8).offset(Self::HDRLEN as isize)
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

    pub fn as_intptr(&self) -> libc::intptr_t {
        self as *const _ as libc::intptr_t
    }
}

/// @imitates: [mnl_attr_data_type_len]
fn data_type_len(atype: AttrDataType) -> u16 {
    match atype {
        AttrDataType::U8 =>    mem::size_of::<u8>() as u16,
        AttrDataType::U16 =>   mem::size_of::<u16>() as u16,
        AttrDataType::U32 =>   mem::size_of::<u32>() as u16,
        AttrDataType::U64 =>   mem::size_of::<u64>() as u16,
        AttrDataType::MSecs => mem::size_of::<u64>() as u16,
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
                if unsafe { *(self.payload_raw() as *const _ as *const u8).offset((attr_len - 1) as isize) != 0 } {
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
        self._validate(atype, mem::size_of::<T>() as u16)
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
    pub fn new(attr: &'a Attr<'a>) -> Self {
        Self {
            head: attr,
            cur: unsafe { attr.payload_raw::<Attr>() },
        }
    }

    pub fn next(&mut self) -> Option<&'a Attr<'a>> {
        if self.cur.ok(unsafe { self.head.payload_raw::<u8>() } as *const _ as isize
                       + self.head.payload_len() as isize
                       - self.cur as *const _ as isize) {
            let ret = Some(self.cur);
            self.cur = unsafe { self.cur.next() };
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
    pub fn parse_nested<T: FnMut(&'a Self) -> CbResult>
        (&'a self, mut cb: T) -> CbResult
    {
        // validate AttrDataType::Nested
        let attr_len = self.payload_len();
        if attr_len != 0 && attr_len < Self::HDRLEN as u16 {
            return crate::gen_errno!(libc::ERANGE);
        }
        // XXX: need check? - attr.nla_type & NLA_F_NESTED?

        let mut ret: CbResult = crate::gen_errno!(libc::ENOENT);
        let mut nested = NestAttr::new(self);
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
        Ok(*(self.value_ref::<T>()?))
    }

    /// returns attribute payload as a reference.
    pub fn value_ref<T>(&self) -> Result<&T> {
        if mem::size_of::<T>() > self.payload_len() as usize {
            return Err(Errno(libc::ERANGE));
        }
        unsafe { Ok(self.payload_raw::<T>()) }
    }

    /// returns `&str` string attribute.
    ///
    /// This function returns the payload of string attribute value.
    ///
    /// @imitates: [libmnl::mnl_attr_get_str]
    pub fn str_ref(&self) -> Result<&str> {
        // _validate AttrDataType::String
        let attr_len = self.payload_len() as usize;
        if attr_len == 0 {
            return Err(Errno(libc::ERANGE));
        }

        let s = unsafe {
            slice::from_raw_parts(self.payload_ptr(), attr_len)
        };
        str::from_utf8(s)
            .map_err(|_| Errno(libc::EILSEQ))
    }

    pub fn strz_ref(&self) -> Result<&str> {
        // _validate AttrDataType::NulString
        let pptr = unsafe { self.payload_ptr() };
        let attr_len = self.payload_len() as usize;
        if attr_len == 0 {
            return Err(Errno(libc::ERANGE));
        }
        if unsafe { *pptr.offset((attr_len - 1) as isize) } != 0 {
            return Err(Errno(libc::EINVAL));
        }

        let s = unsafe {
            slice::from_raw_parts(pptr, attr_len - 1)
        };
        // println!("strz bytes: {:?}", s);
        str::from_utf8(s)
            .map_err(|_| Errno(libc::EILSEQ))
    }

    pub fn bytes_ref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.value_ref::<u8>().unwrap(),
                self.payload_len() as usize)
        }
    }
}

pub trait AttrTbl<'a>: std::marker::Sized
{
    type Index: std::convert::TryFrom<u16, Error=Errno>;

    fn new() -> Self;
    fn _set(&mut self, index: Self::Index, attr: &'a Attr);

    fn try_from_nlmsg(offset: usize, nlh: &'a Msghdr) -> Result<Self> {
        let mut tb = Self::new();
        nlh.parse(offset, |attr: &Attr| {
            tb._set(Self::Index::try_from(attr.atype())?, attr);
            // tb[T::try_from(attr.atype())?] = Some(attr);
            Ok(CbStatus::Ok)
        }).map_err(|err| {
            // Msghdr::parse() itself returns ENOENT only.
            if let Some(e) = err.downcast_ref::<Errno>() {
                *e
            } else {
                unreachable!()
            }
        })?;
        Ok(tb)
    }

    fn try_from_nest(nest: &'a Attr) -> Result<Self> {
        nest.validate(crate::AttrDataType::Nested)?;
        let mut tb = Self::new();
        nest.parse_nested(|attr: &Attr| {
            tb._set(Self::Index::try_from(attr.atype())?, attr);
            // tb[T::try_from(attr.atype())?] = Some(attr);
            Ok(CbStatus::Ok)
        }).map_err(|err| {
            if let Some(e) = err.downcast_ref::<Errno>() {
                *e
            } else {
                unreachable!()
            }
        })?;
        Ok(tb)
    }

    fn add(&mut self, attr: &'a Attr<'a>, count: &mut usize) -> CbResult {
        // skip unsupported attribute in user-space
        let _ = Self::Index::try_from(attr.atype()).map(|atype| {
            self._set(atype, attr);
            *count += 1;
        });
        Ok(CbStatus::Ok)
    }

    fn from_nlmsg(offset: usize, nlh: &'a Msghdr) -> Result<Self> {
        let mut tb = Self::new();
        let mut count = 0;
        nlh.parse(offset, |attr: &Attr| tb.add(attr, &mut count))
            .map_err(|err| {
                if let Some(e) = err.downcast_ref::<Errno>() {
                    *e
                } else {
                    unreachable!()
                }
            })?;
        if count == 0 {
            Err(Errno(libc::ENOENT))
        } else {
            Ok(tb)
        }
    }

    fn from_nest(nest: &'a Attr) -> Result<Self> {
        nest.validate(crate::AttrDataType::Nested)?;
        let mut tb = Self::new();
        let mut count = 0;
        nest.parse_nested(|attr: &Attr| tb.add(attr, &mut count))
            .map_err(|err| {
                if let Some(e) = err.downcast_ref::<Errno>() {
                    *e
                } else {
                    unreachable!()
                }
            })?;
        if count == 0 {
            Err(Errno(libc::ENOENT))
        } else {
            Ok(tb)
        }
    }
}

impl <'a> Attr<'a> {
    pub fn nest_array<T: AttrTbl<'a>>(&'a self) -> Result<Vec<T>> {
        let mut v = Vec::new();
        self.parse_nested(|nest| {
            v.push(T::from_nest(nest)?);
            Ok(CbStatus::Ok)
        }).map_err(|err| {
            if let Some(e) = err.downcast_ref::<Errno>() {
                *e
            } else {
                unreachable!()
            }
        })?;
        Ok(v)
    }
}

impl <'a> fmt::Debug for Attr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "nla_len: {}, nla_type: {} ({})", self.nla_len, self.atype(), self.nla_type)?;
        if self.nla_type & libc::NLA_F_NESTED as u16 != 0 {
            write!(f, ", NESTED")?;
        }
        if self.nla_type & libc::NLA_F_NET_BYTEORDER as u16 != 0 {
            write!(f, ", NET_BYTEORDER")?;
        }
        Ok(())
    }
}
