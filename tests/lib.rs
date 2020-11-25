use std::io::{Error, ErrorKind};
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use std::mem::size_of;
// use std::iter::Iterator;
use std::collections::HashMap;

extern crate rsmnl as mnl;
use mnl::linux as linux;
extern crate libc;


fn buf_offset_as<T>(buf: &[u8], offset: isize) -> &T {
    assert!(buf.len() >= offset as usize + size_of::<T>());
    unsafe {
        (buf.as_ptr().offset(offset) as *const T).as_ref().unwrap()
    }
}

fn set_buf<T>(buf: &mut [u8], offset: isize, v: T) {
    assert!(buf.len() >= offset as usize + size_of::<T>());
    unsafe {
        *(buf.as_mut_ptr().offset(offset) as *mut T) = v;
    }
}

#[allow(dead_code)]
fn set_nlmsg_len(buf: &mut[u8], len: u32) {
    set_buf(buf, 0, len);
}

#[allow(dead_code)]
fn set_nlmsg_type(buf: &mut[u8], mtype: u16) {
    set_buf(buf, 4, mtype);
}

#[allow(dead_code)]
fn set_nlmsg_flags(buf: &mut[u8], flags: u16) {
    set_buf(buf, 6, flags);
}

#[allow(dead_code)]
fn set_nlmsg_seq(buf: &mut[u8], seq: u32) {
    set_buf(buf, 8, seq);
}

#[allow(dead_code)]
fn set_nlmsg_pid(buf: &mut[u8], pid: u32) {
    set_buf(buf, 12, pid);
}

#[test]
fn netlink_netfilter() {
    assert!(linux::netlink::Family::NETFILTER as libc::c_int == 12);
}

#[test]
fn socket_open() {
    assert!(mnl::Socket::open(linux::netlink::Family::NETFILTER, 0).is_ok());
}

#[test]
fn socket_fdopen() {
    let sock = unsafe { libc::socket(16, 3, 12) } as RawFd;
    unsafe { mnl::Socket::from_raw_fd(sock) }; // will not panic
}

macro_rules! default_socket {
    () => {
        mnl::Socket::open(linux::netlink::Family::NETFILTER, 0).unwrap()
    }
}

#[test]
fn socket_bind() {
    let mut nls = default_socket!();
    assert!(nls.bind(0, mnl::SOCKET_AUTOPID).is_ok());
}

#[test]
fn socket_get_fd() {
    let nls = default_socket!();
    assert!(nls.as_raw_fd() >= 0);
}

#[test]
fn socket_get_portid() {
    let mut nls = default_socket!();
    nls.bind(0, mnl::SOCKET_AUTOPID).unwrap();
    assert!(nls.portid() > 0);
}

// TODO: no...
//   sendto, recvfrom
//   setsockopt, getsockopt
// those may require root privilege

#[test]
fn nlmsg_size() {
    assert!(mnl::Nlmsg::size(123) == mnl::Nlmsg::HDRLEN + 123);
}

#[test]
fn nlmsg_with_capacity() {
    let mut buf = mnl::default_buf();
    let nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(*nlh.nlmsg_len as usize == mnl::Nlmsg::HDRLEN);
    let mut buf = [0u8; 32];
    let rc = mnl::Nlmsg::put_header(&mut buf[1..]);
    let nlh = rc.unwrap();
    assert!(*nlh.nlmsg_len as usize == mnl::Nlmsg::HDRLEN);
}

#[test]
fn nlmsg_put_extra_header() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    let exthdr: &mut linux::netfilter::nfnetlink::Nfgenmsg = nlh.put_extra_header().unwrap();
    assert!(exthdr.nfgen_family == 0);
    assert!(exthdr.version == 0);
    assert!(exthdr.res_id == 0);
    assert!(*nlh.nlmsg_len as usize
            == mnl::Nlmsg::HDRLEN
               + size_of::<linux::netfilter::nfnetlink::Nfgenmsg>());
}

#[test]
fn nlmsg_ok() {
    let mut buf = [0u8; mnl::Nlmsg::HDRLEN];
    set_nlmsg_len(&mut buf, 16);
    let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
    assert!(nlh.ok());

    let mut buf = [0u8; mnl::Nlmsg::HDRLEN];
    set_nlmsg_len(&mut buf, 17);
    let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
    assert!(!nlh.ok());
}

#[test]
fn nlmsg_next_header() {
    let mut buf = [0u8; 256];
    let hdrlen = mnl::Nlmsg::HDRLEN;
    set_nlmsg_len(&mut buf, hdrlen as u32);
    set_nlmsg_len(&mut buf[hdrlen..], hdrlen as u32);
    let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
    let mut nnlh = nlh.next().unwrap();
    assert!(*nnlh.nlmsg_len == hdrlen as u32);
    // illegal usage?
    assert!(nnlh.put_extra_header::<[u8; 224]>().is_ok());
}

#[test]
fn nlmsg_seq_ok() {
    let mut buf = [0u8; 512];
    set_nlmsg_len(&mut buf, 16);
    {
        let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
        assert!(nlh.seq_ok(0).is_ok());
    }
    set_nlmsg_seq(&mut buf, 1234567890);
    {
        let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
        assert!(nlh.seq_ok(1234567890).is_ok());
    }
}

#[test]
fn nlmsg_porid_ok() {
    let mut buf = [0u8; 512];
    set_nlmsg_len(&mut buf, 16);
    {
        let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
        assert!(nlh.portid_ok(0).is_ok());
    }
    set_nlmsg_seq(&mut buf, 1234567890);
    {
        let nlh = unsafe { mnl::Nlmsg::from_bytes(&mut buf) };
        assert!(nlh.portid_ok(1234567890).is_ok());
    }
}

#[test]
fn nlmsg_payload() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    *nlh.put_extra_header().unwrap() = std::u64::MAX;
    assert!(*nlh.payload::<u64>().unwrap() == std::u64::MAX);

    assert!(*buf_offset_as::<u64>(nlh.as_ref(), 16) == std::u64::MAX);
}

#[test]
fn nlmsg_payload_offset() {
    let mut buf = mnl::default_buf();
    set_buf(&mut buf, 16 + 128, std::u64::MAX);
    let nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    *nlh.nlmsg_len = 16 + 128;
    assert!(unsafe { *nlh.payload_offset::<u64>(128) == std::u64::MAX });
}

#[test]
fn nlmsg_payload_tail() {
    let mut buf = mnl::default_buf();
    set_buf(&mut buf, 128, std::u64::MAX);
    let nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    *nlh.nlmsg_len = 128;
    assert!(unsafe { *nlh.payload_tail::<u64>() == std::u64::MAX });
}

#[test]
fn nlmsg_put_attr_slice() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    let mut a = [0u8; 16];
    for (i, v) in a.iter_mut().enumerate() {
        *v = i as u8;
    }
    assert!(nlh.put(123, &a).is_ok());
    assert_eq!(&nlh.as_ref()[20..36].to_vec(), &a);
}

#[test]
fn nlmsg_put_attr() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(123, &std::u64::MAX).is_ok());
    assert!(*nlh.nlmsg_len == mnl::Nlmsg::HDRLEN as u32 + mnl::Attr::HDRLEN as u32 + mnl::align(size_of::<u64>()) as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len as usize == mnl::Attr::HDRLEN + size_of::<u64>());
    assert!(attr.nla_type == 123);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == mnl::Attr::HDRLEN + size_of::<u64>());
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 123);
    assert!(*buf_offset_as::<u64>(nlh.as_ref(), 20) == std::u64::MAX);

    let mut buf = [0u8; 39];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(123, &std::u64::MAX).is_ok());
    assert!(nlh.put(234, &std::u64::MAX).is_err());

    let mut buf = [0u8; 40];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(123, &std::u64::MAX).is_ok());
    assert!(nlh.put(234, &std::u64::MAX).is_ok());
}

#[test]
fn nlmsg_put_u8_check() {
    let attr_len = mnl::Attr::HDRLEN + size_of::<u8>();

    let mut buf = [0u8; 512];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(12, &34u8).is_ok());
    assert!(*nlh.nlmsg_len == (mnl::Nlmsg::HDRLEN + mnl::align(attr_len)) as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len);
    assert!(attr.nla_type == 12);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 12);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 20) == 34);

    let mut buf = [0u8; 31];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(12, &34u8).is_ok());
    assert!(nlh.put(56, &78u8).is_err());

    let mut buf = [0u8; 32];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(12, &34u8).is_ok());
    assert!(nlh.put(56, &78u8).is_ok());

    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 24) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 26) == 56);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 28) == 78);
}

#[test]
fn nlmsg_put_u16_check() {
    let attr_len = mnl::Attr::HDRLEN + size_of::<u16>();

    let mut buf = [0u8; 512];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &5678u16).is_ok());
    assert!(*nlh.nlmsg_len == (mnl::Nlmsg::HDRLEN + mnl::align(attr_len)) as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len  as usize == attr_len);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 20) == 5678);

    let mut buf = [0u8; 31];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &5678u16).is_ok());
    assert!(nlh.put(9012, &3456u16).is_err());

    let mut buf = [0u8; 32];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &5678u16).is_ok());
    assert!(nlh.put(9012, &3456u16).is_ok());
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 24) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 26) == 9012);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 28) == 3456);
}

#[test]
fn nlmsg_put_u32_check() {
    let attr_len = mnl::Attr::HDRLEN + size_of::<u32>();

    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &56789012u32).is_ok());
    assert!(*nlh.nlmsg_len == (mnl::Nlmsg::HDRLEN + mnl::align(attr_len)) as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
    assert!(*buf_offset_as::<u32>(nlh.as_ref(), 20) == 56789012);

    let mut buf = [0u8; 31];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &56789012u32).is_ok());
    assert!(nlh.put(3456, &78901234u32).is_err());

    let mut buf = [0u8; 32];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &56789012u32).is_ok());
    assert!(nlh.put(3456, &78901234u32).is_ok());
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 24) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 26) == 3456);
    assert!(*buf_offset_as::<u32>(nlh.as_ref(), 28) == 78901234);
}

#[test]
fn nlmsg_put_u64_check() {
    let attr_len = mnl::Attr::HDRLEN + size_of::<u64>();

    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &0x567890abcdef0123u64).is_ok());
    assert!(*nlh.nlmsg_len == (mnl::Nlmsg::HDRLEN + mnl::align(attr_len)) as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
    assert!(*buf_offset_as::<u64>(nlh.as_ref(), 20) == 0x567890abcdef0123);

    let mut buf = [0u8; 39];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &0x567890abcdef0123u64).is_ok());
    assert!(nlh.put(4567, &0x890abcdef0123456u64).is_err());

    let mut buf = [0u8; 40];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put(1234, &0x567890abcdef0123u64).is_ok());
    assert!(nlh.put(4567, &0x890abcdef0123456u64).is_ok());
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 28) as usize == attr_len);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 30) == 4567);
    assert!(*buf_offset_as::<u64>(nlh.as_ref(), 32) == 0x890abcdef0123456);
}

#[test]
fn nlmsg_put_str_check() {
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = mnl::Attr::HDRLEN + b1.len();
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_str(1234, s1).is_ok());
    assert!(*nlh.nlmsg_len == (mnl::Nlmsg::HDRLEN + mnl::align(attr_len1)) as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len1);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len1);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(nlh.as_ref(), 20)).unwrap() == s1);

    let s2 = "My name is";
    let b2 = s2.as_bytes(); // .len() == 10
    let mut buf = [0u8; 51];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_str(1234, s1).is_ok());
    assert!(nlh.put_str(5678, s2).is_err());

    let attr_len2 = mnl::Attr::HDRLEN + b2.len();
    let mut buf = [0u8; 52];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_str(1234, s1).is_ok());
    let attr = unsafe { nlh.payload_tail::<mnl::Attr>() };
    let bi = *nlh.nlmsg_len as isize;
    assert!(nlh.put_str(5678, s2).is_ok());
    assert!(attr.nla_len as usize == attr_len2);
    assert!(attr.nla_type == 5678);

    assert!(*buf_offset_as::<u16>(nlh.as_ref(), bi) as usize == attr_len2);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(nlh.as_ref(), bi + 4)).unwrap() == s2);
}

#[test]
fn nlmsg_put_strz_check() {
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() +1 == 14
    let attr_len1 = mnl::Attr::HDRLEN + b1.len() + 1;
    let nlmsg_len = mnl::Nlmsg::HDRLEN + mnl::align(attr_len1);
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_strz(1234, s1).is_ok());
    assert!(*nlh.nlmsg_len == nlmsg_len as u32);
    let attr = nlh.payload::<mnl::Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len1);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len1);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(nlh.as_ref(), 20)).unwrap() == s1);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), (mnl::Nlmsg::HDRLEN + attr_len1) as isize) == 0);

    let s2 = "My name is N";
    let b2 = s2.as_bytes(); // .len() + 1 == 13
    let mut buf = [0u8; 52];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_strz(1234, s1).is_ok());
    assert!(nlh.put_strz(5678, s2).is_err());

    let attr_len2 = mnl::Attr::HDRLEN + b2.len() + 1;
    let mut buf = [0u8; 56];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_strz(1234, s1).is_ok());
    let attr = unsafe { nlh.payload_tail::<mnl::Attr>() };
    let bi = *nlh.nlmsg_len as isize;
    assert!(nlh.put_strz(5678, s2).is_ok());
    assert!(attr.nla_len as usize == attr_len2);
    assert!(attr.nla_type == 5678);

    assert!(*buf_offset_as::<u16>(nlh.as_ref(), bi) as usize == attr_len2);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 12]>(&nlh.as_ref(), bi + 4)).unwrap() == s2);
}

#[test]
fn nlmsg_nest_start() {
    let mut buf = [0u8; 19];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.nest_start(0x123).is_err());

    let mut buf = [0u8; 20];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    let attr = nlh.nest_start(0x123).unwrap();
    assert!(*nlh.nlmsg_len as usize == mnl::Nlmsg::HDRLEN + mnl::Attr::HDRLEN);
    assert!(attr.nla_len == 0); // will update after _end
    assert!(attr.nla_type & linux::netlink::NLA_F_NESTED != 0);
    assert!(attr.nla_type & linux::netlink::NLA_TYPE_MASK == 0x123);
}

#[test]
fn nlmsg_nest_end() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    let attr = nlh.nest_start(0x123).unwrap();
    nlh.put(0x4567, &0x89u8).unwrap();
    nlh.put(0xabcd, &0xef01234567890abcu64).unwrap();
    nlh.nest_end(attr).unwrap();
    assert!(*nlh.nlmsg_len == 16 + 4 + 8 + 12);
    assert!(attr.nla_len == 4 + 8 + 12);

    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) == 4 + 8 + 12);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == linux::netlink::NLA_F_NESTED | 0x123);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 20) == 5);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 22) == 0x4567);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 24) == 0x89);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 28) == 12);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 30) == 0xabcd);
    assert!(*buf_offset_as::<u64>(nlh.as_ref(), 32) == 0xef01234567890abc);
}

#[test]
fn nlmsg_nest_cancel() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    let mut attr = nlh.nest_start(0x123).unwrap();
    nlh.nest_cancel(attr).unwrap();
    assert!(*nlh.nlmsg_len == 16);

    nlh.put(0x2345, &0x67u8).unwrap();
    attr = nlh.nest_start(0x234).unwrap();
    nlh.nest_cancel(attr).unwrap();
    assert!(*nlh.nlmsg_len == 24);

    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) == 5);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 0x2345);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 20) == 0x67);
}

// fn parse_cb(n: u16) -> dyn FnMut(&mnl::Attr) -> io::Result<mnl::CbStatus> {
// fn parse_cb(n: u16) -> Box::<dyn FnMut(&mnl::Attr) -> mnl::CbResult> {
fn parse_cb(n: u16) -> Box<dyn FnMut(&mnl::Attr) -> mnl::CbResult> {
    let mut data = n;
    Box::new(move |attr: &mnl::Attr| {
        if attr.nla_type != data {
            return Err(mnl::GenError::from(Error::new(ErrorKind::Other, "type is differ")));
        }
        if attr.value::<u8>().unwrap() as u16 != 0x10 + data {
            return Err(mnl::GenError::from(Error::new(ErrorKind::Other, "value is differ")));
        }
        data += 1;
        Ok(mnl::CbStatus::Ok)
    })
}

#[test]
fn nlmsg_parse() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    nlh.put(1, &0x11u8).unwrap();
    nlh.put(2, &0x12u8).unwrap();
    nlh.put(3, &0x13u8).unwrap();
    nlh.put(4, &0x14u8).unwrap();
    assert!(nlh.parse(0, parse_cb(1)).is_ok());

    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    nlh.put(0, &0x0u8).unwrap();
    assert!(nlh.parse(0, parse_cb(1)).is_err());
}

#[test]
fn nlmsg_attrs() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    nlh.put(0, &0x10u8).unwrap();
    nlh.put(1, &0x11u8).unwrap();
    nlh.put(2, &0x12u8).unwrap();
    nlh.put(3, &0x13u8).unwrap();

    let mut i = 0u8;
    let mut attrs = nlh.attrs(0).unwrap();
    while let Some(attr) = attrs.next() {
        assert!(attr.nla_type == i as u16);
        assert!(attr.value::<u8>().unwrap() == (0x10 + i));
        i += 1;
    }
}

#[test]
fn nlmsg_batch_construct() {
    let _ = mnl::NlmsgBatch::new();
    assert!(mnl::NlmsgBatch::with_capacity(2).is_err());
    assert!(mnl::NlmsgBatch::with_capacity(512).is_ok());
}

#[test]
fn nlmsg_batch_next() {
    let mut b = mnl::NlmsgBatch::with_capacity(256).unwrap();
    {
        let next = b.next();
        assert!(next.is_some());
        let mut nlh = next.unwrap();
        assert!(nlh.put(123, &[0u8; 256 - 16 - 4]).is_ok());
    }
    assert!(b.next().is_none());
    assert!(b.next().is_none());
}

#[test]
fn nlmsg_batch_size() {
    let mut b = mnl::NlmsgBatch::with_capacity(256).unwrap();
    {
        let next = b.next();
        assert!(next.is_some());
        assert!(next.unwrap()
                .put(123, &[0u8; 128 - 16 - 4])
                .is_ok());
    }
    assert!(b.size() == 0);

    {
        let next = b.next();
        assert!(next.is_some());
        assert!(next.unwrap()
                .put(456, &[0u8; 128 - 16 - 4])
                .is_ok());
    }
    assert!(b.size() == 128);

    { assert!(b.next().is_none()); }
    assert!(b.size() == 256);
}

#[test]
fn nlmsg_batch_reset() {
    let mut b = mnl::NlmsgBatch::with_capacity(256).unwrap();
    {
        let mut nlh = b.next().unwrap();
        assert!(nlh.put(123, &[0u8; 256 - 16 - 4]).is_ok());
    }
    assert!(b.next().is_none());
    assert!(b.size() == 256);
    b.reset();
    assert!(b.size() == 0);

    {
        let mut nlh = b.next().unwrap();
        assert!(nlh.put(123, &[0u8; 240 - 16 - 4]).is_ok());
    }
    assert!(b.next().is_some());
    b.reset();
    assert!(b.size() == 0);
}

#[test]
fn nlmsg_batch_is_empty() {
    let mut b = mnl::NlmsgBatch::with_capacity(512).unwrap();
    assert!(b.is_empty() == true);
    let _ = b.next().unwrap().put(123, &[0u8; 256]);
    assert!(b.next().is_some());
    assert!(!b.is_empty());
    b.reset();
    assert!(b.is_empty());
}

fn nlmsg_cb_ok(_: &mnl::Nlmsg) -> mnl::CbResult {
    Ok(mnl::CbStatus::Ok)
}

fn nlmsg_cb_stop(_: &mnl::Nlmsg) -> mnl::CbResult {
    Ok(mnl::CbStatus::Stop)
}

fn nlmsg_cb_error(_: &mnl::Nlmsg) -> mnl::CbResult {
    Err(mnl::GenError::from(Error::new(ErrorKind::Other, "error")))
}

#[test]
fn nlmsg_cb_run() {
    let mut b = mnl::NlmsgBatch::with_capacity(512).unwrap();
    {
        *(b.next().unwrap()).nlmsg_type
            = linux::netlink::NLMSG_NOOP;	// 0x1
    }
    {
        *(b.next().unwrap()).nlmsg_type
            = linux::netlink::NLMSG_ERROR;	// 0x2
    }
    {
        *(b.next().unwrap()).nlmsg_type
            = linux::netlink::NLMSG_DONE;	// 0x3
    }
    {
        *(b.next().unwrap()).nlmsg_type
            = linux::netlink::NLMSG_OVERRUN;	// 0x4
    }

    let mut ctlcbs: HashMap<linux::netlink::ControlType, fn(&mnl::Nlmsg) -> mnl::CbResult> = HashMap::new();
    ctlcbs.insert(linux::netlink::ControlType::Noop,    nlmsg_cb_ok);
    ctlcbs.insert(linux::netlink::ControlType::Error,   nlmsg_cb_ok);
    ctlcbs.insert(linux::netlink::ControlType::Done,    nlmsg_cb_ok);
    ctlcbs.insert(linux::netlink::ControlType::Overrun, nlmsg_cb_ok);

    // bufsize = 16 * 4
    assert!(mnl::cb_run2(b.as_mut(), 0, 0, None, &mut ctlcbs).is_ok());

    ctlcbs.insert(linux::netlink::ControlType::Error,   nlmsg_cb_error);
    assert!(mnl::cb_run2(b.as_mut(), 0, 0, None, &mut ctlcbs).is_err());

    ctlcbs.insert(linux::netlink::ControlType::Error,   nlmsg_cb_ok);
    ctlcbs.insert(linux::netlink::ControlType::Done,    nlmsg_cb_stop);
    assert!(mnl::cb_run2(b.as_mut(), 0, 0, None, &mut ctlcbs).unwrap() == mnl::CbStatus::Stop);
}

#[test]
fn nlmsg_batch_iterator() {
    let mut b = mnl::NlmsgBatch::with_capacity(64).unwrap();
    let mut i = 0u16;
    while let Some(nlh) = b.next() {
        *nlh.nlmsg_type = i;
        i += 1;
    }
    println!("i: {}", i);
    assert!(i == 4);
    println!("b.size(): {}", b.size());
    assert!(b.size() == 64);
    assert!(!b.laden_cap());
}

#[test]
fn nlmsg_put_extra_header_check() {
    let mut buf = [0u8; 32];
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    assert!(nlh.put_extra_header::<linux::netlink::Nlmsghdr>().is_ok());
    assert!(nlh.put_extra_header::<linux::netlink::Nlmsghdr>().is_err());
}

#[test]
fn attr_cl_parse_payload() {
    let mut buf = mnl::default_buf();
    let mut nlh = mnl::Nlmsg::put_header(&mut buf).unwrap();
    for i in 0..4u8 {
        nlh.put(i as u16, &i).unwrap();
    }
    // payload_len() == 8 * 4
    let mut data = 4;
    assert!(mnl::parse_payload(nlh.payload::<[u8; 32]>().unwrap(),
                               move |attr: &mnl::Attr| {
                                   if attr.nla_type < data {
                                       return Ok(mnl::CbStatus::Ok);
                                   }
                                   Err(mnl::GenError::from(Error::new(ErrorKind::Other, "error")))
                               }).is_ok());

    data = 3;
    assert!(mnl::parse_payload(nlh.payload::<[u8; 32]>().unwrap(),
                               move |attr: &mnl::Attr| {
                                   if attr.nla_type < data {
                                       return Ok(mnl::CbStatus::Ok);
                                   }
                                   Err(mnl::GenError::from(Error::new(ErrorKind::Other, "error")))
                               }).is_err());
}
