use std:: {
    mem,
    marker::PhantomData,
    convert:: { AsRef, Into },
};

use libc;
use errno::Errno;

use linux::netlink;
use { Result, Attr };

pub struct MsgVec<'a> {
    buf: Vec<u8>,
    nlmsg_len: Option<&'a mut u32>,
}

#[repr(C)]
pub struct Header<'a> {
    _nlmsg_len: u32,		// Just a place, holder,
    				// pointed and handled ONLY from MsgVec.nlmsg_len
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    _buf: PhantomData<MsgVec<'a>>,
}

impl <'a> Header<'a> {
    /// might be for only test
    pub fn nlmsg_len(&self) -> u32 {
        self._nlmsg_len
    }
}

impl <'a> AsRef<[u8]> for MsgVec<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf.as_ref()
    }
}

impl <'a> MsgVec<'a> {
    pub fn new() -> Self {
        // Self { buf: Vec::new(), nlmsg_len: None }
        Self { buf: Vec::with_capacity(crate::socket_buffer_size()), nlmsg_len: None }
    }

    pub fn with_capacity(size: usize) -> Self {
        Self { buf: Vec::with_capacity(size), nlmsg_len: None }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    pub fn nlmsg_len(&self) -> u32 {
        self.nlmsg_len.as_ref().map_or(0, |v| **v )
    }

    pub fn reset(&mut self) {
        self.buf.iter_mut().map(|x| *x = 0).count();
        self.buf.clear();
        self.nlmsg_len = None;
    }

    /// creates, reserve and prepare room for Netlink header
    ///
    /// This function sets to zero the room that is required to put the Netlink
    /// header in the memory buffer passed as parameter. This function also
    /// initializes the nlmsg_len field to the size of the Netlink header. This
    /// function creates Netlink header structure, Msghdr.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_put_header]
    ///
    /// ```
    /// let mut nlb = rsmnl::MsgVec::new();
    /// nlb.push_header();
    /// assert!(nlb.len() == 16);
    /// assert!(nlb.nlmsg_len() == 16);
    /// nlb.push_header();
    /// assert!(nlb.len() == 32);
    /// assert!(nlb.nlmsg_len() == 16);
    /// let mut nlb = rsmnl::MsgVec::with_capacity(0);
    /// nlb.push_header();
    /// assert!(nlb.len() == 16);
    /// assert!(nlb.nlmsg_len() == 16);
    /// ```
    pub fn push_header(&mut self) -> &'a mut Header<'a> {
        let old_len = self.buf.len();
        let new_len = old_len + netlink::NLMSG_HDRLEN as usize;
        self.buf.reserve(new_len);
        let ret = unsafe {
            self.buf.set_len(new_len);
            let ptr = self.buf.as_mut_ptr().offset(old_len as isize) as *mut _ as *mut Header;
            (*ptr)._nlmsg_len = netlink::NLMSG_HDRLEN;
            self.nlmsg_len = Some(&mut (*ptr)._nlmsg_len);
            &mut *ptr
        };
        ret
    }

    fn extends<T>(&mut self, size: usize) -> Result<&mut T> {
        if self.nlmsg_len.is_none() {
            return Err(Errno(libc::EBADMSG));
        }

        let old_len = self.buf.len();
        let nlmsg_len = self.nlmsg_len.as_mut().unwrap();

        let new_len = old_len + size;
        **nlmsg_len += size as u32;

        self.buf.reserve(new_len);
        unsafe {
            self.buf.set_len(new_len);
            // required on a test
            self.buf[old_len..new_len].iter_mut().map(|x| *x = 0).count();
            Ok(&mut *(self.buf.as_mut_ptr().offset(old_len as isize) as *mut _ as *mut T))
        }
    }

    /// reserve and prepare room for an extra data
    ///
    /// This function sets to zero the room that is required to put the extra
    /// data after the initial Netlink header. This function also increases
    /// the nlmsg_len field. This function returns a pointer to the mutable
    /// extra data reference.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_put_extra_header]
    ///
    /// ```
    /// #[repr(C)]
    /// struct Foo(u16,u32);
    /// let mut nlb = rsmnl::MsgVec::new();
    /// nlb.push_header();
    /// nlb.push_extra_header::<Foo>();
    /// assert!(nlb.len() == 24);
    /// assert!(nlb.nlmsg_len() == 24);
    /// ```
    pub fn push_extra_header<T>(&mut self) -> Result<&'a mut T> {
        let ptr = self.extends::<T>(mem::size_of::<T>())?;
        Ok(unsafe { &mut *(ptr as *mut T) })
    }

    /// add an attribute to netlink message
    ///
    /// This function updates the length field of the Netlink message
    /// (nlmsg_len) by adding the size (header + payload) of the new attribute.
    ///
    /// @imitates: [libmnl::mnl_attr_put,
    ///             libmnl::mnl_attr_put_u8,
    ///             libmnl::mnl_attr_put_u8_check,
    ///             libmnl::mnl_attr_put_u16,
    ///             libmnl::mnl_attr_put_u16_check,
    ///             libmnl::mnl_attr_put_u32,
    ///             libmnl::mnl_attr_put_u32_check,
    ///             libmnl::mnl_attr_put_u64,
    ///             libmnl::mnl_attr_put_u64_check]
    ///
    /// To accept nlh.put<Ipv[4|6]Addr>(... both IpAddr has no tag:
    /// ```
    /// assert_eq!(std::mem::size_of::<std::net::Ipv4Addr>(), 4);
    /// assert_eq!(std::mem::size_of::<std::net::Ipv6Addr>(), 16);
    /// ```
    ///
    /// ```
    /// let mut nlb = rsmnl::MsgVec::new();
    /// nlb.push_header();
    /// assert!(nlb.push(1u16, &32u32).is_ok());
    /// assert!(nlb.len() == 24);
    /// assert!(nlb.nlmsg_len() == 24);
    /// ```
    pub fn push<T: Sized + Into<u16>, U: Copy>
        (&mut self, atype: T, data: &U) -> Result<&mut Self>
    {
        let attr_len = netlink::NLA_HDRLEN + crate::align(mem::size_of::<U>()) as u16;
        let attr = self.extends::<Attr>(attr_len as usize)?;
        attr.nla_type = atype.into();
        attr.nla_len = attr_len;

        let dst = unsafe { attr.payload_raw_mut::<U>() };
        *dst = *data;
        Ok(self)
    }

    fn _push_bytes<T: Sized + Into<u16>>
        (&mut self, atype: T, data: &[u8], len: usize) -> Result<&mut Self>
    {
        let attr_len = netlink::NLA_HDRLEN + crate::align(len) as u16;
        let attr = self.extends::<Attr>(attr_len as usize)?;
        attr.nla_type = atype.into();
        attr.nla_len = attr_len;

        let src = data as *const _ as *const u8;
        let dst = unsafe { attr.payload_raw_mut::<u8>() };
        for i in 0..data.len() { // memcpy
            unsafe {
                *(dst as *mut u8).offset(i as isize) = *src.offset(i as isize);
            }
        }
        Ok(self)
    }

    pub fn push_bytes<T: Sized + Into<u16>>
        (&mut self, atype: T, data: &[u8]) -> Result<&mut Self>
    {
        self._push_bytes(atype, data, data.len())
    }

    /// add string attribute to netlink message
    ///
    /// This function updates the length field of the Netlink message
    /// (nlmsg_len) by adding the size (header + payload) of the new attribute.
    ///
    /// @imitates: [libmnl::mnl_attr_put_str, libmnl::mnl_attr_put_str_check]
    pub fn push_str<T: Sized + Into<u16>>
        (&mut self, atype: T, data: &str) -> Result<&mut Self>
    {
        let b = data.as_bytes();
        self._push_bytes(atype, b, b.len())
    }

    /// add string attribute to netlink message
    ///
    /// This function is similar to mnl_attr_put_str, but it includes the
    /// NUL/zero ('\0') terminator at the end of the string.
    ///
    /// @imitates: [libmnl::mnl_attr_put_strz,
    ///             libmnl::mnl_attr_put_strz_check]
    pub fn push_strz<T: Sized + Into<u16>>
        (&mut self, atype: T, data: &str) -> Result<&mut Self>
    {
        let b = data.as_bytes();
        self._push_bytes(atype, b, b.len() + 1)
    }

    /// add flag attribute to netlink message
    ///
    /// This function is for NL_ATTR_TYPE_FLAG, only put attribute type.
    pub fn push_flag<T: Sized + Into<u16>>
        (&mut self, atype: T) -> Result<&mut Self>
    {
        let attr = self.extends::<Attr>(netlink::NLA_HDRLEN as usize)?;
        attr.nla_type = atype.into();
        attr.nla_len = netlink::NLA_HDRLEN;
        Ok(self)
    }

    /// start an attribute nest
    ///
    /// This function adds the attribute header that identifies the beginning of
    /// an attribute nest. If the nested attribute cannot be added then `Err`,
    /// otherwise valid pointer to the beginning of the nest is returned.
    ///
    /// @imitates: [libmnl::mnl_attr_nest_start,
    ///             libmnl::mnl_attr_nest_start_check]
    pub fn nest_start<T: Sized + Into<u16>>
        (&mut self, atype: T) -> Result<&mut Attr>
    {
        let start = self.extends::<Attr>(netlink::NLA_HDRLEN as usize)?;
	// set start->nla_len in mnl_attr_nest_end()
        start.nla_type = netlink::NLA_F_NESTED | atype.into();
        Ok(start)
    }

    /// end an attribute nest
    ///
    /// This function updates the attribute header that identifies the nest.
    /// `start` pointer to the attribute nest returned by nest_start()
    ///
    /// @imitates: [libmnl::mnl_attr_nest_end]
    pub fn nest_end(&self, start: &mut Attr) -> Result<()> {
        let tail = unsafe {
            self.buf.as_ptr().offset(crate::align(self.buf.len()) as isize) as libc::intptr_t
        };
        let head = start as *const _ as libc::intptr_t;
        if head > tail {
            return Err(Errno(libc::EINVAL));
        }
        start.nla_len = (tail - head) as u16;
        Ok(())
    }

    /// cancel an attribute nest
    ///
    /// This function updates the attribute header that identifies the nest.
    /// `start` pointer to the attribute nest returned by nest_start()
    ///
    /// @imitates: [libmnl::mnl_attr_nest_cancel]
    pub fn nest_cancel(&mut self, start: &Attr) -> Result<()> {
        if self.nlmsg_len.is_none() {
            return Err(Errno(libc::EBADMSG));
        }
        let nlmsg_len = self.nlmsg_len.as_mut().unwrap();

        let tail = unsafe {
            self.buf.as_ptr().offset(crate::align(self.buf.len()) as isize) as usize
        };
        let head = start as *const _ as usize; // libc::intptr_t;
        if head > tail {
            return Err(Errno(libc::EINVAL));
        }

        self.buf[head..tail].iter_mut().map(|x| *x = 0).count();
        **nlmsg_len -= (tail - head) as u32;
        unsafe {
            self.buf.set_len(self.buf.len() - (tail - head));
        }
        Ok(())
    }
}
