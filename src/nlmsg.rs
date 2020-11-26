use std::{mem::size_of, fmt, ptr, convert::Into };
use std::convert::AsRef;

extern crate libc;
extern crate errno;

use errno::Errno;
use linux::netlink as netlink;
use crate::{CbStatus, Attr, Result, CbResult, gen_errno};
// use crate::linux::netlink::Nlattr;

/// Netlink message:
/// ```text
/// |<----------------- 4 bytes ------------------->|
/// |<----- 2 bytes ------>|<------- 2 bytes ------>|
/// |-----------------------------------------------|
/// |      Message length (including header)        |
/// |-----------------------------------------------|
/// |     Message type     |     Message flags      |
/// |-----------------------------------------------|
/// |           Message sequence number             |
/// |-----------------------------------------------|
/// |                 Netlink PortID                |
/// |-----------------------------------------------|
/// |                                               |
/// .                   Payload                     .
/// |_______________________________________________|
/// ```
/// There is usually an extra header after the the Netlink header (at the
/// beginning of the payload). This extra header is specific of the Netlink
/// subsystem. After this extra header, it comes the sequence of attributes that
/// are expressed in Type-Length-Value (TLV) format.
///
/// `implements: [netlink::struct nlmsghdr]`
pub struct Nlmsg<'a> {
    buf: &'a mut [u8],
    pub nlmsg_len: &'a mut u32,
    pub nlmsg_type: &'a mut u16,
    pub nlmsg_flags: &'a mut u16,
    pub nlmsg_seq: &'a mut u32,
    pub nlmsg_pid: &'a mut u32,
}

impl <'a> AsRef<[u8]> for Nlmsg<'a> {
    fn as_ref(&self) -> &[u8] {
        // self.buf.as_ref()
        &self.buf[..*self.nlmsg_len as usize]
    }
}

impl <'a> Nlmsg<'a> {
    pub const HDRLEN: usize
        = (size_of::<netlink::Nlmsghdr>() + super::ALIGNTO - 1)
        & !(super::ALIGNTO - 1);


    /// creates Nlmsg
    ///
    /// use [put_header](#method.put_header) instead for construct
    ///
    /// # Safety
    /// `buf` length must be greater than 16
    pub unsafe fn from_bytes(buf: &'a mut [u8]) -> Nlmsg<'a> {
        let p = buf.as_mut_ptr();
        Nlmsg {
            buf:	 buf,
            nlmsg_len:   (p as *mut u32).offset(0).as_mut().unwrap(),
            nlmsg_type:  (p as *mut u16).offset(2).as_mut().unwrap(),
            nlmsg_flags: (p as *mut u16).offset(3).as_mut().unwrap(),
            nlmsg_seq:   (p as *mut u32).offset(2).as_mut().unwrap(),
            nlmsg_pid:   (p as *mut u32).offset(3).as_mut().unwrap(),
        }
    }

    /// calculate the size of Netlink message (without alignment)
    ///
    /// This function returns the size of a netlink message (header plus
    /// payload) without alignment.
    ///
    /// `implements: [libmnl::mnl_nlmsg_size,]`
    pub fn size(len: usize) -> usize {
        len + Self::HDRLEN
    }

    /// get the length of the Netlink payload
    ///
    /// This function returns the Length of the netlink payload, ie. the length
    /// of the full message minus the size of the Netlink header.
    ///
    /// `implements: [libmnl::mnl_nlmsg_get_payload_len,]`
    pub fn payload_len(&self) -> u32 {
        *self.nlmsg_len - Self::HDRLEN as u32
    }

    /// creates, reserve and prepare room for Netlink header
    ///
    /// This function sets to zero the room that is required to put the Netlink
    /// header in the memory buffer passed as parameter. This function also
    /// initializes the nlmsg_len field to the size of the Netlink header. This
    /// function creates Netlink header structure, Nlmsg.
    ///
    /// # Failures
    /// This function returns error if `buf` length less than 16 or greater than
    /// u32 MAX.
    ///
    /// `implements: [libmnl::mnl_nlmsg_put_header,]`
    pub fn put_header(buf: &'a mut [u8]) -> Result<Self> {
        if buf.len() < Self::HDRLEN
            || buf.len() > ::std::u32::MAX as usize {
                return Err(Errno(libc::EINVAL));
        }
        unsafe { ptr::write_bytes(buf.as_mut_ptr(), 0, Self::HDRLEN) };
        let nlh = unsafe { Self::from_bytes(buf) };
        *nlh.nlmsg_len = Self::HDRLEN as u32;
        return Ok(nlh)
    }

    unsafe fn calloc_raw<T>(&mut self, size: usize) -> Result<&'a mut T> {
        let len = *self.nlmsg_len as usize + super::align(size);
        if len > ::std::u32::MAX as usize {
            return Err(Errno(libc::EINVAL));
        }
        if self.buf.len() < len {
            return Err(Errno(libc::ENOSPC));
        }
        let p = self.buf.as_mut_ptr().offset(*self.nlmsg_len as isize);
        ptr::write_bytes(p, 0, super::align(size));
        *self.nlmsg_len = len as u32;
        Ok(&mut (*(p as *mut T)))
    }

    /// reserve and prepare room for an extra data
    ///
    /// This function sets to zero the room that is required to put the extra
    /// data after the initial Netlink header. This function also increases
    /// the nlmsg_len field. This function returns a pointer to the mutable
    /// extra data reference.
    ///
    /// # Failures
    /// This function returns error if it can not prepare a required room.
    ///
    /// `implements: [libmnl::mnl_nlmsg_put_extra_header,]`
    pub fn put_extra_header<T>(&mut self) -> Result<&'a mut T> {
        unsafe { self.calloc_raw::<T>(size_of::<T>()) }
    }

    unsafe fn payload_raw<T>(&self) -> &'a T {
        &(*(self.buf.as_ptr().offset(Self::HDRLEN as isize) as *const T))
    }

    /// get a pointer to the payload of the netlink message
    ///
    /// This function returns a pointer to the payload of the netlink message.
    ///
    /// # Failures
    /// This function returns error if it's length is less than required.
    ///
    /// `implements: [libmnl::mnl_nlmsg_get_payload,]`
    pub fn payload<T>(&self) -> Result<&'a T> {
        if super::align(size_of::<T>()) + Self::HDRLEN > *self.nlmsg_len as usize {
            Err(Errno(libc::ENODATA))
        } else {
            Ok(unsafe { self.payload_raw::<T>() })
        }
    }

    /// `implements: [libmnl::mnl_nlmsg_get_payload,]`
    // unsafe fn payload_mut<T>(&mut self) -> &'a mut T {
    //     &mut (*(self.buf.as_mut_ptr().offset(Self::HDRLEN as isize) as *mut T))
    // }

    /// get a pointer to the payload of the message
    ///
    /// This function returns a pointer to the payload of the netlink message
    /// plus a given offset.
    ///
    /// # Safety
    /// `offset` must not exceed `self.buf` length.
    ///
    /// `implements: [libmnl::mnl_nlmsg_get_payload_offset,]`
    pub unsafe fn payload_offset<T>(&self, offset: usize) -> &'a T {
        &*(self.buf.as_ptr().offset(
            Self::HDRLEN as isize + super::align(offset) as isize
        ) as *const _ as *const T)
    }

    /// `implements: [libmnl::mnl_nlmsg_get_payload_offset,]`
    unsafe fn payload_offset_mut<T>(&mut self, offset: usize) -> &'a mut T {
        &mut *(self.buf.as_mut_ptr().offset(
            Self::HDRLEN as isize + super::align(offset) as isize
        ) as *mut _ as *mut T)
    }

    /// check a there is room for netlink message
    ///
    /// This function is used to check that a buffer that contains a netlink
    /// message has enough room for the netlink message that it stores, ie. this
    /// function can be used to verify that a netlink message is not malformed
    /// nor truncated.
    ///
    /// `implements: [libmnl::mnl_nlmsg_ok,]`
    pub fn ok(&'a self) -> bool {
        self.buf.len() >= Self::HDRLEN &&
            *self.nlmsg_len as usize >= Self::HDRLEN &&
            *self.nlmsg_len as usize <= self.buf.len()
    }

    /// get the next netlink message in a multipart message
    /// This function returns a pointer to the next netlink message that is part
    /// of a multi-part netlink message. Netlink can batch several messages into
    /// one buffer so that the receiver has to iterate over the whole set of
    /// Netlink messages.
    ///
    /// `implements: [libmnl::mnl_nlmsg_next,]`
    pub fn next(self) -> Option<Nlmsg<'a>> {
        let nlh = unsafe {
            Self::from_bytes(&mut self.buf[super::align(*self.nlmsg_len as usize)..])
        };
        if nlh.ok() {
            Some(nlh)
        } else {
            None
        }
    }

    /// get the ending of the netlink message
    ///
    /// This function returns a pointer to the netlink message tail. This is
    /// useful to build a message since we continue adding attributes at the end
    /// of the message.
    ///
    /// # Safety
    /// `*self.nlmsg_len` must not exceed `self.buf` length.
    ///
    /// `implements: [libmnl::mnl_nlmsg_get_payload_tail,]`
    pub unsafe fn payload_tail<T>(&self) -> &'a T {
        &*(self.buf.as_ptr().offset(super::align(*self.nlmsg_len as usize) as isize) as *const T)
    }

    /// `implements: [libmnl::mnl_nlmsg_get_payload_tail,]`
    pub unsafe fn payload_tail_mut<T>(&mut self) -> &'a mut T {
        &mut (*(self.buf.as_mut_ptr().offset(super::align(*self.nlmsg_len as usize) as isize) as *mut T))
    }

    /// perform sequence tracking
    ///
    /// This functions returns `Ok` if the sequence tracking is fulfilled,
    /// otherwise `Err` is returned. We skip the tracking for netlink messages
    /// whose sequence number is zero since it is usually reserved for
    /// event-based kernel notifications. On the other hand, if seq is set but
    /// the message sequence number is not set (i.e. this is an event message
    /// coming from kernel-space), then we also skip the tracking. This approach
    /// is good if we use the same socket to send commands to kernel-space (that
    /// we want to track) and to listen to events (that we do not track).
    ///
    /// # Failures
    /// both `self` and argument `seq` is not zero and differ.
    ///
    /// `implements: [libmnl::mnl_nlmsg_seq_ok,]`
    pub fn seq_ok(&self, seq: u32) -> Result<()> {
        if *self.nlmsg_seq != 0 && seq != 0 && *self.nlmsg_seq != seq {
            return Err(Errno(libc::EPROTO));
        }
        Ok(())
    }

    /// perform portID origin check
    ///
    /// This functions returns `Ok` if the origin is fulfilled, otherwise `Err`
    /// is returned. We skip the tracking for netlink message whose portID is
    /// zero since it is reserved for event-based kernel notifications. On the
    /// other hand, if portid is set but the message PortID is not (i.e. this is
    /// an event message coming from kernel-space), then we also skip the
    /// tracking. This approach is good if we use the same socket to send
    /// commands to kernel-space (that we want to track) and to listen to events
    /// (that we do not track).
    ///
    /// # Failures
    /// both `self` and argument `pid` is not zero and differ.
    ///
    /// `implements: [libmnl::mnl_nlmsg_portid_ok,]`
    pub fn portid_ok(&self, portid: u32) -> Result<()> {
        if *self.nlmsg_pid != 0 && portid != 0 && *self.nlmsg_pid != portid {
            return Err(Errno(libc::ESRCH));
        }
        Ok(())
    }

    /// parse attributes
    ///
    /// This function allows to iterate over the sequence of attributes that
    /// compose the Netlink message. You can then put the attribute in an array
    /// as it usually happens at this stage or you can use any other data
    /// structure (such as lists or trees).
    ///
    /// This function propagates the return value of the callback, which can be
    /// `Error`, `Ok` or `Stop`.
    ///
    /// `implements: [libmnl::mnl_attr_parse,]`

    pub fn parse<T: FnMut(&'a Attr<'a>) -> CbResult>
        (&'a self, offset: usize, mut cb: T) -> CbResult
    {
        let mut ret: CbResult = gen_errno!(libc::ENOENT);
        let mut it = self.attrs(offset)?;
        while let Some(attr) = it.next() {
            ret = cb(attr);
            match ret {
                Ok(CbStatus::Ok) => {},
                _ => return ret,
            }
        }
        ret
    }

    unsafe fn alloc_attr(&mut self, atype: u16, size: usize) -> Result<&'a mut Attr<'a>> {
        let len = Attr::HDRLEN as usize + size;
        if len > ::std::u16::MAX as usize {
            return Err(Errno(libc::EINVAL));
        }
        let attr: &mut Attr = self.calloc_raw(len)?;
        attr.nla_type = atype;
        attr.nla_len = len as u16;
        Ok(attr)
    }

    /// add an attribute to netlink message
    ///
    /// This function updates the length field of the Netlink message
    /// (nlmsg_len) by adding the size (header + payload) of the new attribute.
    ///
    /// # Failures
    /// if there is no enough space to put a specified type.
    ///
    /// `implements: [libmnl::mnl_attr_put,
    ///               libmnl::mnl_attr_put_u8,
    ///               libmnl::mnl_attr_put_u8_check,
    ///               libmnl::mnl_attr_put_u16,
    ///               libmnl::mnl_attr_put_u16_check,
    ///               libmnl::mnl_attr_put_u32,
    ///               libmnl::mnl_attr_put_u32_check,
    ///               libmnl::mnl_attr_put_u64,
    ///               libmnl::mnl_attr_put_u64_check]
    pub fn put<T: Copy>(&mut self, atype: u16, data: &T) -> Result<&mut Self> {
        let attr = unsafe { self.alloc_attr(atype, size_of::<T>())? };
        let dst = unsafe { attr.payload_mut::<T>() };
        *dst = *data;
        Ok(self)
    }

    fn put_bytes(&mut self, atype: u16, data: &[u8], len: usize) -> Result<&mut Self> {
        let attr = unsafe { self.alloc_attr(atype, len)? };
        let dst = unsafe { attr.payload_mut::<u8>() };
        let src = data as *const _ as *const u8;
        for i in 0..data.len() { // memcpy
            unsafe {
                *(dst as *mut u8).offset(i as isize) = *src.offset(i as isize);
            }
        }
        Ok(self)
    }

    /// add string attribute to netlink message
    ///
    /// This function updates the length field of the Netlink message
    /// (nlmsg_len) by adding the size (header + payload) of the new attribute.
    ///
    /// # Failures
    /// if there is no enough space to put a specified str length.
    ///
    /// `implements: [libmnl::mnl_attr_put_str, libmnl::mnl_attr_put_str_check]`
    pub fn put_str(&mut self, atype: u16, data: &str) -> Result<&mut Self> {
        let b = data.as_bytes();
        self.put_bytes(atype, b, b.len())
    }

    /// add string attribute to netlink message
    ///
    /// This function is similar to mnl_attr_put_str, but it includes the
    /// NUL/zero ('\0') terminator at the end of the string.
    ///
    /// # Failures
    /// if there is no enough space to put a specified str length plus one.
    ///
    /// `implements: [libmnl::mnl_attr_put_strz,
    ///               libmnl::mnl_attr_put_strz_check]`
    pub fn put_strz(&mut self, atype: u16, data: &str) -> Result<&mut Self> {
        let b = data.as_bytes();
        self.put_bytes(atype, b, b.len() + 1)
    }

    /// start an attribute nest
    ///
    /// This function adds the attribute header that identifies the beginning of
    /// an attribute nest. If the nested attribute cannot be added then `Err`,
    /// otherwise valid pointer to the beginning of the nest is returned.
    ///
    /// # Failures
    /// if there is no enough space to put a nest `Attr`.
    ///
    /// `implements: [libmnl::mnl_attr_nest_start,
    ///               libmnl::mnl_attr_nest_start_check]`
    pub fn nest_start(&mut self, atype: u16) -> Result<&'a mut Attr> {
        let len = *self.nlmsg_len as usize + Attr::HDRLEN;
        if len > self.buf.len() {
            return Err(Errno(libc::EINVAL));
        }

        let start = unsafe { self.payload_tail_mut::<Attr>() };
	// set start->nla_len in mnl_attr_nest_end()
        start.nla_type = netlink::NLA_F_NESTED | atype;
        *self.nlmsg_len = len as u32;
        Ok(start)
    }

    /// end an attribute nest
    ///
    /// This function updates the attribute header that identifies the nest.
    /// `start` pointer to the attribute nest returned by nest_start()
    ///
    /// # Failures
    /// if `start` pointer is invalid, e.g. `start` position is before the
    /// current one. (RFC: needs to check?
    /// `start.nla_type & netlink::NLA_F_NESTED != 0`)
    ///
    /// `implements: [libmnl::mnl_attr_nest_end]`
    pub fn nest_end(&mut self, start: &mut Attr) -> Result<()> {
        let tail = unsafe { self.payload_tail::<u8>() as *const _ as libc::uintptr_t };
        let head = start as *const _ as libc::uintptr_t;
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
    /// # Failures
    /// if `start` pointer is invalid, e.g. `start` position is before the
    /// current one.
    ///
    /// `implements: [libmnl::mnl_attr_nest_cancel]`
    pub fn nest_cancel(&mut self, start: &Attr) -> Result<()> {
        let tail = unsafe { self.payload_tail::<u8>() as *const _ as libc::uintptr_t };
        let head = start as *const _ as libc::uintptr_t;
        if head > tail {
            return Err(Errno(libc::EINVAL));
        }

        let len = *self.nlmsg_len - ((tail - head) as u32);
        *self.nlmsg_len = len;
        Ok(())
    }

    /// creates stream iterator for `Attr`
    ///
    /// # Failures
    /// returns `Err` in case of there is no following `Attr`s.
    ///
    /// `implements: [libmnl:: mnl_attr_for_each]`
    // pub fn attrs(&'a mut self, offset: usize) -> Result<Attrs> {
    pub fn attrs<'b>(&'b self, offset: usize) -> Result<Attrs<'a, 'b>> {
        if Self::HDRLEN + offset + Attr::HDRLEN > self.buf.len() {
            return Err(Errno(libc::ENOSPC));
        }
        Ok(Attrs { nlh: self, offset: offset })
    }
}

/// stream iterarot for `Attr`
pub struct Attrs<'a: 'b, 'b> {
    nlh: &'b Nlmsg<'a>,
    offset: usize,
}

impl <'a, 'b> Attrs<'a, 'b> {
    pub fn next(&mut self) -> Option<&'a Attr<'a>> {
        let attr = unsafe { self.nlh.payload_offset::<Attr>(self.offset) };
        if attr.ok(*self.nlh.nlmsg_len as isize - self.offset as isize) {
            self.offset += super::align(attr.nla_len as usize);
            Some(attr)
        } else {
            None
        }
    }
}

struct RoNlmsg<'a> {
    buf: &'a [u8],
    nlmsg_len: &'a u32,
    nlmsg_type: &'a u16,
    nlmsg_flags: &'a u16,
    nlmsg_seq: &'a u32,
    nlmsg_pid: &'a u32,
}

impl <'a> RoNlmsg<'a> {
    fn from_nlmsg(nlh: &'a Nlmsg<'a>) -> Self {
        RoNlmsg {
            buf: nlh.buf,
            nlmsg_len: nlh.nlmsg_len,
            nlmsg_type: nlh.nlmsg_type,
            nlmsg_flags: nlh.nlmsg_flags,
            nlmsg_seq: nlh.nlmsg_seq,
            nlmsg_pid: nlh.nlmsg_pid,
        }
    }

    pub unsafe fn from_bytes(buf: &'a [u8]) -> Self {
        let p = buf.as_ptr();
        RoNlmsg {
            buf:	 buf,
            nlmsg_len:   (p as *const u32).offset(0).as_ref().unwrap(),
            nlmsg_type:  (p as *const u16).offset(2).as_ref().unwrap(),
            nlmsg_flags: (p as *const u16).offset(3).as_ref().unwrap(),
            nlmsg_seq:   (p as *const u32).offset(2).as_ref().unwrap(),
            nlmsg_pid:   (p as *const u32).offset(3).as_ref().unwrap(),
        }
    }

    pub fn ok(&'a self) -> bool {
        self.buf.len() >= Nlmsg::HDRLEN &&
            *self.nlmsg_len as usize >= Nlmsg::HDRLEN &&
            *self.nlmsg_len as usize <= self.buf.len()
    }

    pub fn next(self) -> Option<Self> {
        let nlh = unsafe {
            Self::from_bytes(&self.buf[super::align(*self.nlmsg_len as usize)..])
        };
        if nlh.ok() {
            Some(nlh)
        } else {
            None
        }
    }

    /// `implements: [libmnl::mnl_nlmsg_fprintf_header,]`
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "----------------\t------------------\n")?;
	write!(f, "|  {:^010}  |\t| message length |\n", *self.nlmsg_len)?;
	write!(f, "| {:^05} | {}{}{}{} |\t|  type | flags  |\n",
	       *self.nlmsg_type,
	       if *self.nlmsg_flags & netlink::NLM_F_REQUEST != 0 { 'R' } else { '-' },
	       if *self.nlmsg_flags & netlink::NLM_F_MULTI   != 0 { 'M' } else { '-' },
	       if *self.nlmsg_flags & netlink::NLM_F_ACK     != 0 { 'A' } else { '-' },
	       if *self.nlmsg_flags & netlink::NLM_F_ECHO    != 0 { 'E' } else { '-' })?;
	write!(f, "|  {:^010}  |\t| sequence number|\n", *self.nlmsg_seq)?;
	write!(f, "|  {:^010}  |\t|     port ID    |\n", *self.nlmsg_pid)?;
	write!(f, "----------------\t------------------\n")
    }

    /// `implements: [libmnl::mnl_nlmsg_fprintf_payload,]`
    unsafe fn fmt_payload(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // XXX
        let mut extra_header_size = f.precision().unwrap_or(0);

        let mut rem = 0isize;
        let b = self.buf.as_ptr() as *const u8;

        for ii in size_of::<netlink::Nlmsghdr>() / 4..(*self.nlmsg_len / 4) as usize {
            let i = ii * 4;
            let attr = &*(b.offset(i as isize) as *const _ as *const Attr);

            if *self.nlmsg_type < netlink::NLMSG_MIN_TYPE {
	        // netlink control message. */
                write!(f, "| {:2x} {:2x} {:2x} {:2x}  |\t",
                       0xff & self.buf[i],	0xff & self.buf[i + 1],
                       0xff & self.buf[i + 2],	0xff & self.buf[i + 4])?;
                write!(f,  "|                |\n")?;
            } else if extra_header_size > 0 {
                // special handling for the extra header.
                extra_header_size -= 4;
                write!(f, "| {:2x} {:2x} {:2x} {:2x}  |\t",
        	       0xff & self.buf[i],	0xff & self.buf[i + 1],
        	       0xff & self.buf[i + 2],	0xff & self.buf[i + 3])?;
        	write!(f, "|  extra header  |\n")?;
            } else if rem == 0 && (attr.nla_type & netlink::NLA_TYPE_MASK != 0) {
        	write!(f, "|{}[{};{}m\
        	           {:5}\
        	           {}[{}m\
        	           |\
        	           {}[{};{}m\
        	           {}{}\
        	           {}[{}m\
        	           |\
        	           {}[{};{}m\
        	           {:5}\
        	           {}[{}m|\t",
        	       '\x1b', 1, 31,
        	       attr.nla_len,
        	       '\x1b', 0,
        	       '\x1b', 1, 32,
        	       if attr.nla_type & netlink::NLA_F_NESTED != 0 { 'N' } else {'-'},
        	       if attr.nla_type & netlink::NLA_F_NET_BYTEORDER != 0 { 'B' } else { '-' },
        	       '\x1b', 0,
        	       '\x1b', 1, 34,
        	       attr.nla_type & netlink::NLA_TYPE_MASK,
        	       '\x1b', 0)?;
                write!(f, "|len |flags| type|\n")?;

                if attr.nla_type & netlink::NLA_F_NESTED == 0 {
                    rem = super::align(attr.nla_len as usize) as isize
                        - Attr::HDRLEN as isize;
                }
            } else if rem > 0 {
		// this is the attribute payload.
                rem -= 4;
                write!(f, "| {:2x} {:2x} {:2x} {:2x}  |\t",
		       0xff & self.buf[i],	0xff & self.buf[i+1],
		       0xff & self.buf[i+2],	0xff & self.buf[i+3])?;
                write!(f, "|      data      |")?;
                let mut c: char;
                write!(f, "\t {} {} {} {}\n",
                       { c = self.buf[i  ].into(); if c.is_ascii_graphic() { c } else { ' ' } },
                       { c = self.buf[i+1].into(); if c.is_ascii_graphic() { c } else { ' ' } },
                       { c = self.buf[i+2].into(); if c.is_ascii_graphic() { c } else { ' ' } },
                       { c = self.buf[i+3].into(); if c.is_ascii_graphic() { c } else { ' ' } })?;
		}
	}
	write!(f, "----------------\t------------------\n")
    }
}

impl <'a> fmt::Debug for Nlmsg<'a> {
    /// format netlink message
    ///
    /// This function prints the netlink header to a file handle. It may be
    /// useful for debugging purposes. One example of the output is the
    /// following:
    ///
    /// ```text
    /// ----------------        ------------------
    /// |  0000000040  |        | message length |
    /// | 00016 | R-A- |        |  type | flags  |
    /// |  1289148991  |        | sequence number|
    /// |  0000000000  |        |     port ID    |
    /// ----------------        ------------------
    /// | 00 00 00 00  |        |  extra header  |
    /// | 00 00 00 00  |        |  extra header  |
    /// | 01 00 00 00  |        |  extra header  |
    /// | 01 00 00 00  |        |  extra header  |
    /// |00008|--|00003|        |len |flags| type|
    /// | 65 74 68 30  |        |      data      |       e t h 0
    /// ----------------        ------------------
    /// ```
    /// This example above shows the netlink message that is send to
    /// kernel-space to set up the link interface eth0. The netlink and
    /// attribute header data are displayed in base 10 whereas the extra header
    /// and the attribute payload are expressed in base 16. The possible flags
    /// in the netlink header are:
    ///
    /// - `R`, that indicates that NLM_F_REQUEST is set.
    /// - `M`, that indicates that NLM_F_MULTI is set.
    /// - `A`, that indicates that NLM_F_ACK is set.
    /// - `E`, that indicates that NLM_F_ECHO is set.
    ///
    /// The lack of one flag is displayed with '-'. On the other hand, the
    /// possible attribute flags available are:
    ///
    /// - `N`, that indicates that NLA_F_NESTED is set.
    /// - `B`, that indicates that NLA_F_NET_BYTEORDER is set.
    ///
    /// `implements: libmnl::mnl_nlmsg_fprintf`
    /// TODO: how to handle `extra_header_size`? original signature:
    /// ```c
    /// void mnl_nlmsg_fprintf(
    ///     FILE *fd,
    ///     const void *data,
    ///     size_t datalen,
    ///     size_t extra_header_size)
    /// ```

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // if self.buf.len() < Self::HDRLEN {

        // let mut buf = vec![0u8; self.buf.len()];
        // buf.clone_from_slice(self.buf);

        unsafe {
            let mut nlh = RoNlmsg::from_nlmsg(&self);
            loop {
                nlh.fmt_header(f)?;
                nlh.fmt_payload(f)?;
                match nlh.next() {
                    Some(v) => nlh = v,
                    _ => break,
                }
            }
        }
        Ok(())
    }
}
