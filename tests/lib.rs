#![allow(dead_code)]

use std:: {
    io:: {
        Error, ErrorKind
    },
    os::unix::io:: {
        AsRawFd, RawFd, FromRawFd
    },
    mem,
};
extern crate libc;
use libc::genlmsghdr;

extern crate rsmnl as mnl;
use mnl:: {
    Socket, Msghdr, MsgVec, Attr,
};

fn buf_offset_as<T>(buf: &[u8], offset: isize) -> &T {
    assert!(buf.len() >= offset as usize + mem::size_of::<T>());
    unsafe {
        (buf.as_ptr().offset(offset) as *const T).as_ref().unwrap()
    }
}

fn set_buf<T>(buf: &mut [u8], offset: isize, v: T) {
    assert!(buf.len() >= offset as usize + mem::size_of::<T>());
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

fn bytes2nlmsg(bytes: &[u8]) -> &Msghdr {
    unsafe {
        &*(bytes as *const _ as *const Msghdr)
    }
}

#[test]
fn socket_open() {
    assert!(Socket::open(libc::NETLINK_NETFILTER, 0).is_ok());
}

#[test]
fn socket_fdopen() {
    let sock = unsafe { libc::socket(16, 3, 12) } as RawFd;
    unsafe { Socket::from_raw_fd(sock) }; // will not panic
}

macro_rules! default_socket {
    () => {
        Socket::open(libc::NETLINK_NETFILTER, 0).unwrap()
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
    assert!(Msghdr::size::<u32>() == Msghdr::HDRLEN + 4);
}

#[test]
fn nlmsg_with_capacity() {
    let mut nlv = MsgVec::new();
    nlv.push_header();
    assert!(nlv.nlmsg_len() == 16); // libc::NLMSG_HDRLEN
    nlv.push_header();
    assert!(nlv.len() as u32 == 16 * 2);
    assert!(nlv.nlmsg_len() == 16);

    nlv = MsgVec::with_capacity(0);
    assert!(nlv.len() == 0);
    assert!(nlv.capacity() == 0);
    nlv.push_header();
    assert!(nlv.len() == 16); // libc::NLMSG_HDRLEN
    assert!(nlv.capacity() >= 16);
}

#[test]
fn nlmsg_push_extra_header() {
    let mut nlv = MsgVec::new();
    assert!(nlv.push_extra_header::<genlmsghdr>().is_err());
    nlv.push_header();
    let exthdr = nlv.push_extra_header::<genlmsghdr>().unwrap();
    assert!(exthdr.cmd == 0);
    assert!(exthdr.version == 0);
    assert!(exthdr.reserved == 0);
    assert!(nlv.nlmsg_len() as usize
            == Msghdr::HDRLEN
               + mem::size_of::<genlmsghdr>());
}

#[test]
fn nlmsg_ok() {
    let mut buf = [0u8; Msghdr::HDRLEN];
    let mut len = buf.len() as isize;

    set_nlmsg_len(&mut buf, 16);
    let nlh = bytes2nlmsg(&buf);
    assert!(nlh.ok(len));

    len = buf.len() as isize;
    set_nlmsg_len(&mut buf, 17);
    let nlh = bytes2nlmsg(&buf);
    assert!(!nlh.ok(len));
}

#[test]
fn nlmsg_next_header() {
    // Msghdr::HDRLEN = 16;
    let mut buf = [0u8; 256];
    let mut len = buf.len() as isize;

    set_nlmsg_len(&mut buf, 16);
    set_nlmsg_len(&mut buf[16..], 16);
    set_nlmsg_len(&mut buf[32..], 256 - 16 - 16 + 1);

    let nlh0 = bytes2nlmsg(&buf);
    assert!(nlh0.nlmsg_len == 16);
    assert!(nlh0.ok(len));

    let nlh1 = unsafe { nlh0.next(&mut len) };
    assert!(len == 256 - 16);
    assert!(nlh1.nlmsg_len == 16);
    assert!(nlh1.ok(len));

    let nlh2 = unsafe { nlh1.next(&mut len) };
    assert!(len == 256 - 32);
    assert!(nlh2.nlmsg_len == (256 - 16 - 16 + 1) as u32);
    assert!(!nlh2.ok(len));
}

#[test]
fn nlmsg_seq_ok() {
    // ignores 0
    let mut buf = [0u8; 512];
    set_nlmsg_len(&mut buf, 16);
    {
        let nlh = bytes2nlmsg(&mut buf);
        assert!(nlh.seq_ok(0).is_ok());
        assert!(nlh.seq_ok(1234567890).is_ok());
    }
    set_nlmsg_seq(&mut buf, 1234567890);
    {
        let nlh = bytes2nlmsg(&mut buf);
        assert!(nlh.seq_ok(0).is_ok());
        assert!(nlh.seq_ok(1234567890).is_ok());
        assert!(nlh.seq_ok(123456789).is_err());
    }
}

#[test]
fn nlmsg_porid_ok() {
    // ignores 0
    let mut buf = [0u8; 512];
    set_nlmsg_len(&mut buf, 16);
    {
        let nlh = bytes2nlmsg(&mut buf);
        assert!(nlh.portid_ok(0).is_ok());
        assert!(nlh.portid_ok(1234567890).is_ok());
    }
    set_nlmsg_pid(&mut buf, 1234567890);
    {
        let nlh = bytes2nlmsg(&mut buf);
        assert!(nlh.portid_ok(0).is_ok());
        assert!(nlh.portid_ok(1234567890).is_ok());
        assert!(nlh.portid_ok(123456789).is_err());
    }
}

#[test]
fn nlmsg_payload() {
    let mut nlv = MsgVec::new();
    nlv.push_header();
    *nlv.push_extra_header::<u64>().unwrap() = std::u64::MAX;

    let nlh = bytes2nlmsg(nlv.as_ref());
    assert!(*nlh.payload::<u64>().unwrap() == std::u64::MAX);
}

#[test]
fn nlmsg_payload_offset() {
    let mut buf = mnl::default_buffer();
    set_nlmsg_len(&mut buf, mem::size_of::<u64>() as u32 + 16 + 128);
    set_buf(&mut buf, 16 + 128, std::u64::MAX);
    let nlh = bytes2nlmsg(&buf);
    assert!(unsafe { *nlh.payload_offset::<u64>(128) == std::u64::MAX });
}

#[test]
fn nlmsg_payload_tail() {
    let mut buf = mnl::default_buffer();
    set_nlmsg_len(&mut buf, 128);
    set_buf(&mut buf, 128, std::u64::MAX);
    let nlh = bytes2nlmsg(&buf);
    assert!(unsafe { *nlh.payload_tail::<u64>() == std::u64::MAX });
}

#[test]
fn nlmsg_put_bytes() {
    let mut a = [0u8; 16];
    for (i, v) in a.iter_mut().enumerate() {
        *v = i as u8;
    }

    let mut nlv = MsgVec::new();
    assert!(nlv.push(123u16, &a).is_err());
    nlv.push_header();
    assert!(nlv.push(123u16, &a).is_ok());
    assert_eq!(&nlv.as_ref()[20..36].to_vec(), &a);
}

#[test]
fn nlmsg_put_attr() {
    let mut nlv = MsgVec::new();
    assert!(nlv.push(123u16, &std::u64::MAX).is_err());
    nlv.push_header();
    assert!(nlv.push(123u16, &std::u64::MAX).is_ok());
    assert!(nlv.len() == Msghdr::HDRLEN + Attr::HDRLEN + mnl::align(mem::size_of::<u64>()));
    assert!(nlv.nlmsg_len() == Msghdr::HDRLEN as u32 + Attr::HDRLEN as u32 + mnl::align(mem::size_of::<u64>()) as u32);

    let nlh = bytes2nlmsg(nlv.as_ref());
    let attr = nlh.payload::<Attr>().unwrap();
    assert!(attr.nla_len as usize == Attr::HDRLEN + mem::size_of::<u64>());
    assert!(attr.nla_type == 123);
    assert!(*buf_offset_as::<u16>(nlv.as_ref(), 16) as usize == Attr::HDRLEN + mem::size_of::<u64>());
    assert!(*buf_offset_as::<u16>(nlv.as_ref(), 18) == 123);
    assert!(*buf_offset_as::<u64>(nlv.as_ref(), 20) == std::u64::MAX);
}

// #[test]
// fn nlmsg_put_u8_check() {
//     let attr_len = Attr::HDRLEN + mem::size_of::<u8>();

//     let mut buf = [0u8; 512];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(12u16, &34u8).is_ok());
//     assert!(*nlh.nlmsg_len == (Msghdr::HDRLEN + mnl::align(attr_len)) as u32);
//     let attr = nlh.payload::<Attr>().unwrap();
//     assert!(attr.nla_len as usize == attr_len);
//     assert!(attr.nla_type == 12);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 12);
//     assert!(*buf_offset_as::<u8>(nlh.as_ref(), 20) == 34);

//     let mut buf = [0u8; 31];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(12u16, &34u8).is_ok());
//     assert!(nlh.put(56u16, &78u8).is_err());

//     let mut buf = [0u8; 32];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(12u16, &34u8).is_ok());
//     assert!(nlh.put(56u16, &78u8).is_ok());

//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 24) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 26) == 56);
//     assert!(*buf_offset_as::<u8>(nlh.as_ref(), 28) == 78);
// }

// #[test]
// fn nlmsg_put_u16_check() {
//     let attr_len = Attr::HDRLEN + mem::size_of::<u16>();

//     let mut buf = [0u8; 512];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &5678u16).is_ok());
//     assert!(*nlh.nlmsg_len == (Msghdr::HDRLEN + mnl::align(attr_len)) as u32);
//     let attr = nlh.payload::<Attr>().unwrap();
//     assert!(attr.nla_len  as usize == attr_len);
//     assert!(attr.nla_type == 1234);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 20) == 5678);

//     let mut buf = [0u8; 31];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &5678u16).is_ok());
//     assert!(nlh.put(9012u16, &3456u16).is_err());

//     let mut buf = [0u8; 32];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &5678u16).is_ok());
//     assert!(nlh.put(9012u16, &3456u16).is_ok());
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 24) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 26) == 9012);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 28) == 3456);
// }

// #[test]
// fn nlmsg_put_u32_check() {
//     let attr_len = Attr::HDRLEN + mem::size_of::<u32>();

//     let mut buf = mnl::default_buffer();
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &56789012u32).is_ok());
//     assert!(*nlh.nlmsg_len == (Msghdr::HDRLEN + mnl::align(attr_len)) as u32);
//     let attr = nlh.payload::<Attr>().unwrap();
//     assert!(attr.nla_len as usize == attr_len);
//     assert!(attr.nla_type == 1234);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
//     assert!(*buf_offset_as::<u32>(nlh.as_ref(), 20) == 56789012);

//     let mut buf = [0u8; 31];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &56789012u32).is_ok());
//     assert!(nlh.put(3456u16, &78901234u32).is_err());

//     let mut buf = [0u8; 32];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &56789012u32).is_ok());
//     assert!(nlh.put(3456u16, &78901234u32).is_ok());
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 24) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 26) == 3456);
//     assert!(*buf_offset_as::<u32>(nlh.as_ref(), 28) == 78901234);
// }

// #[test]
// fn nlmsg_put_u64_check() {
//     let attr_len = Attr::HDRLEN + mem::size_of::<u64>();

//     let mut buf = mnl::default_buffer();
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &0x567890abcdef0123u64).is_ok());
//     assert!(*nlh.nlmsg_len == (Msghdr::HDRLEN + mnl::align(attr_len)) as u32);
//     let attr = nlh.payload::<Attr>().unwrap();
//     assert!(attr.nla_len as usize == attr_len);
//     assert!(attr.nla_type == 1234);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 1234);
//     assert!(*buf_offset_as::<u64>(nlh.as_ref(), 20) == 0x567890abcdef0123);

//     let mut buf = [0u8; 39];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &0x567890abcdef0123u64).is_ok());
//     assert!(nlh.put(4567u16, &0x890abcdef0123456u64).is_err());

//     let mut buf = [0u8; 40];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put(1234u16, &0x567890abcdef0123u64).is_ok());
//     assert!(nlh.put(4567u16, &0x890abcdef0123456u64).is_ok());
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 28) as usize == attr_len);
//     assert!(*buf_offset_as::<u16>(nlh.as_ref(), 30) == 4567);
//     assert!(*buf_offset_as::<u64>(nlh.as_ref(), 32) == 0x890abcdef0123456);
// }

#[test]
fn nlmsg_put_str_check() {
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = Attr::HDRLEN + b1.len();
    let mut nlv = MsgVec::new();
    assert!(nlv.push_str(1234u16, s1).is_err());
    nlv.push_header();
    assert!(nlv.push_str(1234u16, s1).is_ok());
    assert!(nlv.nlmsg_len() == (Msghdr::HDRLEN + mnl::align(attr_len1)) as u32);

    let nlh = bytes2nlmsg(nlv.as_ref());
    let attr = nlh.payload::<Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len1);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlv.as_ref(), 16) as usize == attr_len1);
    assert!(*buf_offset_as::<u16>(nlv.as_ref(), 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(nlv.as_ref(), 20)).unwrap() == s1);

    let old_len = nlv.len();
    nlv.push_header();
    assert!(nlv.push_str(1234u16, s1).is_ok());

    let s2 = "My name is";
    let b2 = s2.as_bytes(); // .len() == 10
    let attr_len2 = Attr::HDRLEN + b2.len();
    let bi = nlv.nlmsg_len() as isize;
    assert!(nlv.push_str(5678u16, s2).is_ok());
    let nlh = bytes2nlmsg(&nlv.as_ref()[old_len..]);
    let attr2 = unsafe { nlh.payload_offset::<Attr>(mnl::align(attr_len1)) };
    assert!(attr2.nla_len as usize == attr_len2);
    assert!(attr2.nla_type == 5678);
    assert!(nlh.nlmsg_len as usize == Msghdr::HDRLEN + mnl::align(attr_len1) + mnl::align(attr_len2));
    assert!(nlv.nlmsg_len() as usize == Msghdr::HDRLEN + mnl::align(attr_len1) + mnl::align(attr_len2));

    assert!(*buf_offset_as::<u16>(&nlv.as_ref()[old_len..], bi) as usize == attr_len2);
    assert!(*buf_offset_as::<u16>(&nlv.as_ref()[old_len..], bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(&nlv.as_ref()[old_len..], bi + 4)).unwrap() == s2);
}

#[test]
fn nlmsg_put_strz_check() {
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = Attr::HDRLEN + b1.len();
    let mut nlv = MsgVec::new();
    assert!(nlv.push_strz(1234u16, s1).is_err());
    nlv.push_header();
    assert!(nlv.push_strz(1234u16, s1).is_ok());
    assert!(nlv.nlmsg_len() == (Msghdr::HDRLEN + mnl::align(attr_len1 + 1)) as u32);

    let nlh = bytes2nlmsg(nlv.as_ref());
    let attr = nlh.payload::<Attr>().unwrap();
    assert!(attr.nla_len as usize == attr_len1 + 1);
    assert!(attr.nla_type == 1234);
    assert!(*buf_offset_as::<u16>(nlv.as_ref(), 16) as usize == attr_len1 + 1);
    assert!(*buf_offset_as::<u16>(nlv.as_ref(), 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(nlv.as_ref(), 20)).unwrap() == s1);

    let old_len = nlv.len();
    nlv.push_header();
    assert!(nlv.push_strz(1234u16, s1).is_ok());

    let s2 = "My name is";
    let b2 = s2.as_bytes(); // .len() == 10
    let attr_len2 = Attr::HDRLEN + b2.len();
    let bi = nlv.nlmsg_len() as isize;
    assert!(nlv.push_strz(5678u16, s2).is_ok());
    let nlh = bytes2nlmsg(&nlv.as_ref()[old_len..]);
    let attr2 = unsafe { nlh.payload_offset::<Attr>(mnl::align(attr_len1)) };
    assert!(attr2.nla_len as usize == attr_len2 + 1);
    assert!(attr2.nla_type == 5678);
    assert!(nlh.nlmsg_len as usize == Msghdr::HDRLEN + mnl::align(attr_len1) + mnl::align(attr_len2 + 1));
    assert!(nlv.nlmsg_len() as usize == Msghdr::HDRLEN + mnl::align(attr_len1) + mnl::align(attr_len2 + 1));

    assert!(*buf_offset_as::<u16>(&nlv.as_ref()[old_len..], bi) as usize == attr_len2 + 1);
    assert!(*buf_offset_as::<u16>(&nlv.as_ref()[old_len..], bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(&nlv.as_ref()[old_len..], bi + 4)).unwrap() == s2);
}

#[test]
fn nlmsg_nest_start() {
    let mut nlv = MsgVec::new();
    assert!(nlv.nest_start(0x123u16).is_err());

    nlv.push_header();
    assert!(nlv.nest_start(0x123u16).is_ok());
    assert!(nlv.nlmsg_len() as usize == Msghdr::HDRLEN + Attr::HDRLEN);
    let attr = nlv.msghdr().unwrap().payload::<Attr>().unwrap();
    assert!(attr.nla_len == 0); // will update after _end
    assert!(attr.nla_type & libc::NLA_F_NESTED as u16 != 0);
    assert!(attr.nla_type & libc::NLA_TYPE_MASK as u16 == 0x123);
}

#[test]
fn nlmsg_nest_end() {
    let mut nlv = MsgVec::new();
    nlv.push_header();
    assert!(nlv.nest_end().is_err());

    assert!(nlv.nest_start(0x123u16).is_ok());
    assert!(nlv.push(0x4567u16, &0x89u8).is_ok());
    assert!(nlv.push(0xabcdu16, &0xef01234567890abcu64).is_ok());
    assert!(nlv.nest_end().is_ok());
    let nlh = nlv.header().unwrap();
    assert!(nlh.nlmsg_len() == 16 + 4 + 8 + 12);
    let attr = nlv.msghdr().unwrap().payload::<Attr>().unwrap();
    assert!(attr.nla_len == 4 + 8 + 12);

    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) == 4 + 8 + 12);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == libc::NLA_F_NESTED as u16 | 0x123);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 20) == 5);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 22) == 0x4567);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 24) == 0x89);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 28) == 12);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 30) == 0xabcd);
    assert!(*buf_offset_as::<u64>(nlh.as_ref(), 32) == 0xef01234567890abc);
}

#[test]
fn nlmsg_nest_cancel() {
    let mut nlv = MsgVec::new();
    assert!(nlv.nest_cancel().is_err());

    nlv.push_header();
    assert!(nlv.nest_start(0x123u16).is_ok());
    assert!(nlv.nest_cancel().is_ok());
    assert!(nlv.nlmsg_len() == 16);

    assert!(nlv.push(0x2345u16, &0x67u8).is_ok());
    assert!(nlv.nest_start(0x234u16).is_ok());
    assert!(nlv.nest_cancel().is_ok());

    let nlh = nlv.header().unwrap();
    assert!(nlv.nlmsg_len() == 24);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) == 5);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 0x2345);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 20) == 0x67);

    assert!(nlv.nest_start(0x234u16).is_ok());
    assert!(nlv.push(0x2345u16, &0x67u8).is_ok());
    assert!(nlv.push(0x2345u16, &0x67u8).is_ok());
    assert!(nlv.nest_cancel().is_ok());
    assert!(nlv.nlmsg_len() == 24);

    let nlh = nlv.header().unwrap();
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 16) == 5);
    assert!(*buf_offset_as::<u16>(nlh.as_ref(), 18) == 0x2345);
    assert!(*buf_offset_as::<u8>(nlh.as_ref(), 20) == 0x67);
}

fn parse_cb(mut n: u16) -> Box<dyn FnMut(&Attr) -> mnl::CbResult> {
    Box::new(move |attr: &Attr| {
        if attr.nla_type != n {
            return Err(mnl::GenError::from(Error::new(ErrorKind::Other, "type is differ")));
        }
        if attr.value::<u8>().unwrap() as u16 != 0x10 + n {
            return Err(mnl::GenError::from(Error::new(ErrorKind::Other, "value is differ")));
        }
        n += 1;
        Ok(mnl::CbStatus::Ok)
    })
}

#[test]
fn nlmsg_parse() {
    let mut nlv = MsgVec::new();
    nlv.push_header();
    nlv.push(1u16, &0x11u8).unwrap();
    nlv.push(2u16, &0x12u8).unwrap();
    nlv.push(3u16, &0x13u8).unwrap();
    nlv.push(4u16, &0x14u8).unwrap();
    assert!(nlv.msghdr().unwrap().parse(0, parse_cb(1)).is_ok());
    nlv.reset();

    nlv.push_header();
    nlv.push(0u16, &0x0u8).unwrap();
    assert!(nlv.msghdr().unwrap().parse(0, parse_cb(1)).is_err());
}

// #[test]
// fn nlmsg_attrs() {
//     let mut buf = mnl::default_buffer();
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     nlh.put(0u16, &0x10u8).unwrap();
//     nlh.put(1u16, &0x11u8).unwrap();
//     nlh.put(2u16, &0x12u8).unwrap();
//     nlh.put(3u16, &0x13u8).unwrap();

//     let mut i = 0u8;
//     let mut attrs = nlh.attrs(0).unwrap();
//     while let Some(attr) = attrs.next() {
//         assert!(attr.nla_type == i as u16);
//         assert!(attr.value::<u8>().unwrap() == (0x10 + i));
//         i += 1;
//     }
// }

// #[test]
// fn nlmsg_batch_construct() {
//     let _ = mnl::MsgBatch::new();
//     assert!(mnl::MsgBatch::with_capacity(2).is_err());
//     assert!(mnl::MsgBatch::with_capacity(512).is_ok());
// }

// #[test]
// fn nlmsg_batch_next() {
//     let mut b = mnl::MsgBatch::with_capacity(256).unwrap();
//     {
//         let next = b.next();
//         assert!(next.is_some());
//         let mut nlh = next.unwrap();
//         assert!(nlh.put(123u16, &[0u8; 256 - 16 - 4]).is_ok());
//     }
//     assert!(b.next().is_none());
//     assert!(b.next().is_none());
// }

// #[test]
// fn nlmsg_batch_size() {
//     let mut b = mnl::MsgBatch::with_capacity(256).unwrap();
//     {
//         let next = b.next();
//         assert!(next.is_some());
//         assert!(next.unwrap()
//                 .put(123u16, &[0u8; 128 - 16 - 4])
//                 .is_ok());
//     }
//     assert!(b.size() == 0);

//     {
//         let next = b.next();
//         assert!(next.is_some());
//         assert!(next.unwrap()
//                 .put(456u16, &[0u8; 128 - 16 - 4])
//                 .is_ok());
//     }
//     assert!(b.size() == 128);

//     { assert!(b.next().is_none()); }
//     assert!(b.size() == 256);
// }

// #[test]
// fn nlmsg_batch_reset() {
//     let mut b = mnl::MsgBatch::with_capacity(256).unwrap();
//     {
//         let mut nlh = b.next().unwrap();
//         assert!(nlh.put(123u16, &[0u8; 256 - 16 - 4]).is_ok());
//     }
//     assert!(b.next().is_none());
//     assert!(b.size() == 256);
//     b.reset();
//     assert!(b.size() == 0);

//     {
//         let mut nlh = b.next().unwrap();
//         assert!(nlh.put(123u16, &[0u8; 240 - 16 - 4]).is_ok());
//     }
//     assert!(b.next().is_some());
//     b.reset();
//     assert!(b.size() == 0);
// }

// #[test]
// fn nlmsg_batch_is_empty() {
//     let mut b = mnl::MsgBatch::with_capacity(512).unwrap();
//     assert!(b.is_empty() == true);
//     let _ = b.next().unwrap().put(123u16, &[0u8; 256]);
//     assert!(b.next().is_some());
//     assert!(!b.is_empty());
//     b.reset();
//     assert!(b.is_empty());
// }

fn nlmsg_cb_ok(_: &Msghdr) -> mnl::CbResult {
    Ok(mnl::CbStatus::Ok)
}

fn nlmsg_cb_stop(_: &Msghdr) -> mnl::CbResult {
    Ok(mnl::CbStatus::Stop)
}

fn nlmsg_cb_error(_: &Msghdr) -> mnl::CbResult {
    Err(mnl::GenError::from(Error::new(ErrorKind::Other, "error")))
}

#[test]
fn nlmsg_cb_run() {
    let mut nlv = MsgVec::new();
    nlv.push_header().nlmsg_type = libc::NLMSG_NOOP as u16;
    nlv.push_header().nlmsg_type = libc::NLMSG_ERROR as u16;
    nlv.push_header().nlmsg_type = libc::NLMSG_DONE as u16;
    nlv.push_header().nlmsg_type = libc::NLMSG_OVERRUN as u16;

    let mut ctlcbs: [Option<fn(&Msghdr) -> mnl::CbResult>; 5] = [
        None,
        Some(nlmsg_cb_ok),
        Some(nlmsg_cb_ok),
        Some(nlmsg_cb_ok),
        Some(nlmsg_cb_ok),
    ];

    assert!(mnl::cb_run2(nlv.as_ref(), 0, 0, mnl::NOCB, &mut ctlcbs).is_ok());

    ctlcbs[libc::NLMSG_ERROR as usize] = Some(nlmsg_cb_error);
    assert!(mnl::cb_run2(nlv.as_ref(), 0, 0, mnl::NOCB, &mut ctlcbs).is_err());

    ctlcbs[libc::NLMSG_ERROR as usize] = Some(nlmsg_cb_ok);
    ctlcbs[libc::NLMSG_DONE as usize] = Some(nlmsg_cb_stop);
    assert!(mnl::cb_run2(nlv.as_ref(), 0, 0, mnl::NOCB, &mut ctlcbs).unwrap() == mnl::CbStatus::Stop);
}

// #[test]
// fn nlmsg_batch_iterator() {
//     let mut b = mnl::MsgBatch::with_capacity(64).unwrap();
//     let mut i = 0u16;
//     while let Some(nlh) = b.next() {
//         *nlh.nlmsg_type = i;
//         i += 1;
//     }
//     println!("i: {}", i);
//     assert!(i == 4);
//     println!("b.size(): {}", b.size());
//     assert!(b.size() == 64);
//     assert!(!b.laden_cap());
// }

// #[test]
// fn nlmsg_put_extra_header_check() {
//     let mut buf = [0u8; 32];
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     assert!(nlh.put_extra_header::<libc::Nlmsghdr>().is_ok());
//     assert!(nlh.put_extra_header::<libc::Nlmsghdr>().is_err());
// }

// #[test]
// fn attr_cl_parse_payload() {
//     let mut buf = mnl::default_buffer();
//     let mut nlh = Msghdr::put_header(&mut buf).unwrap();
//     for i in 0..4u8 {
//         nlh.put(i as u16, &i).unwrap();
//     }
//     // payload_len() == 8 * 4
//     let mut data = 4;
//     assert!(mnl::parse_payload(nlh.payload::<[u8; 32]>().unwrap(),
//                                move |attr: &Attr| {
//                                    if attr.nla_type < data {
//                                        return Ok(mnl::CbStatus::Ok);
//                                    }
//                                    Err(mnl::GenError::from(Error::new(ErrorKind::Other, "error")))
//                                }).is_ok());

//     data = 3;
//     assert!(mnl::parse_payload(nlh.payload::<[u8; 32]>().unwrap(),
//                                move |attr: &Attr| {
//                                    if attr.nla_type < data {
//                                        return Ok(mnl::CbStatus::Ok);
//                                    }
//                                    Err(mnl::GenError::from(Error::new(ErrorKind::Other, "error")))
//                                }).is_err());
// }
