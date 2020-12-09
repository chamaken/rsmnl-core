use std::{
    mem,
    fmt,
    slice,
    convert:: { Into }, //  AsRef },
    marker::PhantomData,
};

extern crate libc;
extern crate errno;

use errno::Errno;
use linux::netlink;
use linux::netlink::Nlmsghdr;
use { CbStatus, Attr, Result, CbResult };

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
/// @imitates: [netlink::struct nlmsghdr]
#[repr(C)]
pub struct Msghdr<'a> {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    _buf: PhantomData<&'a [u8]>,
}

impl <'a> Msghdr<'a> {
    pub const HDRLEN: usize
        = (mem::size_of::<Nlmsghdr>() + crate::ALIGNTO - 1)
        & !(crate::ALIGNTO - 1);

    /// calculate the size of Netlink message (without alignment)
    ///
    /// This function returns the size of a netlink message (header plus
    /// payload) without alignment.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_size]
    pub fn size<T>() -> usize {
        mem::size_of::<T>() + Self::HDRLEN
    }

    /// get the length of the Netlink payload
    ///
    /// This function returns the Length of the netlink payload, ie. the length
    /// of the full message minus the size of the Netlink header.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_get_payload_len]
    pub fn payload_len(&self) -> u32 {
        self.nlmsg_len - Self::HDRLEN as u32
    }

    /// @imitates: [libmnl::mnl_nlmsg_get_payload]
    unsafe fn payload_raw<T>(&self) -> &'a T {
        &*((self as *const _ as *const u8).offset(Self::HDRLEN as isize) as *const T)
    }

    /// get a pointer to the payload of the netlink message
    ///
    /// This function returns a pointer to the payload of the netlink message.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_get_payload]
    pub fn payload<T>(&self) -> Result<&'a T> {
        if crate::align(Self::size::<T>()) > self.nlmsg_len as usize {
            Err(Errno(libc::ENODATA))
        } else {
            Ok(unsafe { self.payload_raw::<T>() })
        }
    }

    /// get a pointer to the payload of the message
    ///
    /// This function returns a pointer to the payload of the netlink message
    /// plus a given offset.
    ///
    /// # Safety
    /// `offset` must not exceed `self.buf` length.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_get_payload_offset]
    pub unsafe fn payload_offset<T>(&self, offset: usize) -> &'a T {
        &*((self as *const _ as *const u8).offset(
            Self::HDRLEN as isize + crate::align(offset) as isize
        ) as *const _ as *const T)
    }

    /// check a there is room for netlink message
    ///
    /// This function is used to check that a buffer that contains a netlink
    /// message has enough room for the netlink message that it stores, ie. this
    /// function can be used to verify that a netlink message is not malformed
    /// nor truncated.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_ok]
    pub fn ok(&self, len: usize) -> bool {
        len >= Self::HDRLEN &&
            self.nlmsg_len as usize >= Self::HDRLEN &&
            self.nlmsg_len as usize <= len
    }

    /// get the next netlink message in a multipart message
    /// This function returns a pointer to the next netlink message that is part
    /// of a multi-part netlink message. Netlink can batch several messages into
    /// one buffer so that the receiver has to iterate over the whole set of
    /// Netlink messages.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_next]
    pub unsafe fn next(&self, len: &mut usize) -> &Self {
        *len -= crate::align(self.nlmsg_len as usize);
        &*((self as *const _ as *const u8)
           .offset(self.nlmsg_len as isize)
           as *const _ as *const Self)
    }

    /// get the ending of the netlink message
    ///
    /// This function returns a pointer to the netlink message tail. This is
    /// useful to build a message since we continue adding attributes at the end
    /// of the message.
    ///
    /// @imitates: [libmnl::mnl_nlmsg_get_payload_tail]
    pub unsafe fn payload_tail<T>(&self) -> *const T {
        (self as *const _ as *const u8)
            .offset(crate::align(self.nlmsg_len as usize) as isize)
            as *const T
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
    /// @imitates: [libmnl::mnl_nlmsg_seq_ok]
    pub fn seq_ok(&self, seq: u32) -> Result<()> {
        if self.nlmsg_seq != 0 && seq != 0 && self.nlmsg_seq != seq {
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
    /// @imitates: [libmnl::mnl_nlmsg_portid_ok]
    pub fn portid_ok(&self, portid: u32) -> Result<()> {
        if self.nlmsg_pid != 0 && portid != 0 && self.nlmsg_pid != portid {
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
    /// @imitates: [libmnl::mnl_attr_parse]
    pub fn parse<T: FnMut(&'a Attr<'a>) -> CbResult>
        (&self, offset: usize, mut cb: T) -> CbResult
    {
        let mut ret: CbResult = crate::gen_errno!(libc::ENOENT);
        let mut attr = unsafe { self.payload_offset::<Attr>(offset) };
        loop {
            if !attr.ok(unsafe {
                self.payload_tail::<u8>() as libc::intptr_t
                    - attr as *const _ as *const u8 as libc::intptr_t
            }) {
                return ret;
            }
            ret = cb(attr);
            match ret {
                Ok(CbStatus::Ok) => {},
                _ => return ret,
            }
            attr = unsafe { attr.next() };
        }
    }
}

impl <'a> Msghdr<'a> {
    /// @imitates: [libmnl::mnl_nlmsg_fprintf_header]
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "----------------\t------------------\n")?;
	write!(f, "|  {:^010}  |\t| message length |\n", self.nlmsg_len)?;
	write!(f, "| {:^05} | {}{}{}{} |\t|  type | flags  |\n",
	       self.nlmsg_type,
	       if self.nlmsg_flags & netlink::NLM_F_REQUEST != 0 { 'R' } else { '-' },
	       if self.nlmsg_flags & netlink::NLM_F_MULTI   != 0 { 'M' } else { '-' },
	       if self.nlmsg_flags & netlink::NLM_F_ACK     != 0 { 'A' } else { '-' },
	       if self.nlmsg_flags & netlink::NLM_F_ECHO    != 0 { 'E' } else { '-' })?;
	write!(f, "|  {:^010}  |\t| sequence number|\n", self.nlmsg_seq)?;
	write!(f, "|  {:^010}  |\t|     port ID    |\n", self.nlmsg_pid)?;
	write!(f, "----------------\t------------------\n")
    }

    /// @imitates: [libmnl::mnl_nlmsg_fprintf_payload]
    unsafe fn fmt_payload(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // XXX: check length?
        let mut extra_header_size = f.precision().unwrap_or(0);

        let mut rem = 0isize;
        let b = self as *const _ as *const u8;

        for ii in mem::size_of::<Nlmsghdr>() / 4..(self.nlmsg_len / 4) as usize {
            let buf = slice::from_raw_parts(self as *const _ as *const u8, self.nlmsg_len as usize);
            let i = ii * 4;
            let attr = &*(b.offset(i as isize) as *const _ as *const Attr);

            if self.nlmsg_type < netlink::NLMSG_MIN_TYPE {
	        // netlink control message. */
                write!(f, "| {:2x} {:2x} {:2x} {:2x}  |\t",
                       0xff & buf[i],		0xff & buf[i + 1],
                       0xff & buf[i + 2],	0xff & buf[i + 4])?;
                write!(f,  "|                |\n")?;
            } else if extra_header_size > 0 {
                // special handling for the extra header.
                extra_header_size -= 4;
                write!(f, "| {:2x} {:2x} {:2x} {:2x}  |\t",
        	       0xff & buf[i],		0xff & buf[i + 1],
        	       0xff & buf[i + 2],	0xff & buf[i + 3])?;
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
                    rem = crate::align(attr.nla_len as usize) as isize
                        - Attr::HDRLEN as isize;
                }
            } else if rem > 0 {
		// this is the attribute payload.
                rem -= 4;
                write!(f, "| {:2x} {:2x} {:2x} {:2x}  |\t",
		       0xff & buf[i],	0xff & buf[i+1],
		       0xff & buf[i+2],	0xff & buf[i+3])?;
                write!(f, "|      data      |")?;
                let mut c: char;
                write!(f, "\t {} {} {} {}\n",
                       { c = buf[i  ].into(); if c.is_ascii_graphic() { c } else { ' ' } },
                       { c = buf[i+1].into(); if c.is_ascii_graphic() { c } else { ' ' } },
                       { c = buf[i+2].into(); if c.is_ascii_graphic() { c } else { ' ' } },
                       { c = buf[i+3].into(); if c.is_ascii_graphic() { c } else { ' ' } })?;
		}
	}
	write!(f, "----------------\t------------------\n")
    }
}

impl <'a> fmt::Debug for Msghdr<'a> {
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
    /// @imitates: [libmnl::mnl_nlmsg_fprintf]
    /// extra_header_size 'n' can be specified by {n:?}
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // original libmnl debug() iterates over whole nlmsg
        // but this one formats only one, self.
        // if we need to show all in this single call, we need to:
        //    let mut buf = vec![0u8; self.buf.len()];
        //    buf.clone_from_slice(self.buf);
        // and something.

        unsafe {
            self.fmt_header(f)?;
            self.fmt_payload(f)?;
        }
        Ok(())
    }
}
