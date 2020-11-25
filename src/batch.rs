use std::{io, convert::AsRef};

extern crate libc;

use linux::netlink as netlink;
use super::Nlmsg;


/// This struct provides helpers to batch several messages into one single
/// datagram. The following figure represents a Netlink message batch:
/// ```text
/// |<-------------------- batch ------------------>|
/// |-----------|-----------|-----------|-----------|
/// |<- nlmsg ->|<- nlmsg ->|<- nlmsg ->|<- nlmsg ->|
/// |-----------|-----------|-----------|-----------|
///                                           ^      
///                                           |      
///                                      message N   
/// ```
/// You have to invoke `next()` to get room for a new message in the batch. If
/// this function returns `None`, it means that the last message that was not
/// added. Thus, you have to send the batch and, then, you have to call
/// `reset()` to re-initialize the batch. Or you need to call `laden_cap()`
/// before it did not return `None` to send buffer.
///
/// `implements: [libmnl::struct nlmsg_batch]`
pub struct NlmsgBatch {
    buf: Vec<u8>,
    size: usize,
}

impl AsRef<[u8]> for NlmsgBatch {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.size]
    }
}

impl AsMut<[u8]> for NlmsgBatch {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.size]
    }
}

/// `not implements [libmnl::mnl_nlmsg_batch_head,
///                  libmnl::mnl_nlmsg_batch_current]
impl NlmsgBatch {
    /// initialize a batch by specified `size`.
    ///
    /// allocate the buffer that you use to store the batch in the heap.
    ///
    /// # Failures
    /// returns `Err` if the `size` is less than `Nlmsg::HDRLEN`
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_start]
    pub fn with_capacity(size: usize) -> io::Result<Self> {
        if size < Nlmsg::HDRLEN {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self{ buf: vec![0u8; size],  size: 0, })
    }

    /// initialize a batch by default `size`.
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_start]
    pub fn new() -> Self {
        Self::with_capacity(super::default_bufsize()).unwrap()
    }

    /// reset the batch
    ///
    /// This function allows to reset a batch, so you can reuse it to create a
    /// new one.
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_reset]`
    pub fn reset(&mut self) {
        self.size = 0;
        self.buf.iter_mut().map(|x| *x = 0).count();
    }

    /// get current size of the batch
    ///
    /// This function returns the current size of the batch.
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_size]`
    pub fn size(&self) -> usize {
        self.size
    }

    /// check if there is any message in the batch
    ///
    /// This function returns true if the batch is empty.
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_is_empty]`
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// cap the batch if any message in it.
    ///
    /// You must call this if the last `next()` call returns `Ok` before sending
    /// the batch, to add the last message length. This function is equal to if
    /// not `is_empty()` then `let _ = self.next()`
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_is_empty]`
    pub fn laden_cap(&mut self) -> bool {
	if self.size == 0 || self.size + Nlmsg::HDRLEN > self.buf.len() {
            return false
        }
        let nlh = unsafe { self.nlmsghdr() };
        self.size += nlh.nlmsg_len as usize;
        true
    }

    unsafe fn nlmsghdr<'a>(&self) -> &'a netlink::Nlmsghdr {
        &*(self.buf.as_ptr().offset(self.size as isize) as *const _ as *const netlink::Nlmsghdr)
    }


    /// get the next netlink message in a multipart message
    ///
    /// This function a next netlink message that is part of a multi-part
    /// netlink message. Netlink can batch several messages into one buffer so
    /// that the receiver has to iterate over the whole set of Netlink messages.
    ///
    /// `implements: [libmnl::mnl_nlmsg_batch_next]`
    //
    // impl <'a> Iterator for NlmsgBatch<'a> {
    //     type Item = Nlmsg<'a>;
    pub fn next(&mut self) -> Option<Nlmsg> {
        if self.size + Nlmsg::HDRLEN > self.buf.len() {
            return None;
        }

        let raw = unsafe { self.nlmsghdr() };
        if self.size + raw.nlmsg_len as usize > self.buf.len() {
            panic!("buffer overflow");
        }

        self.size += raw.nlmsg_len as usize;
        if let Ok(nlh) = Nlmsg::put_header(&mut self.buf[self.size..]) {
            Some(nlh)
        } else {
            None
        }
    }
}
