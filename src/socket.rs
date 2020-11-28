use std::ptr;
use std::mem::{size_of, zeroed};
use std::os::unix::io::{ RawFd, AsRawFd, FromRawFd };

extern crate libc;
use libc::{ c_int, c_uint, c_void, sockaddr, sockaddr_nl };

extern crate errno;
use errno::{errno, Errno};

use linux::netlink as netlink;
use crate::Result;

pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

pub fn cvt<T: IsMinusOne>(t: T) -> Result<T> {
    if t.is_minus_one() {
        // Err(io::Error::last_os_error())
        Err(errno())
    } else {
        Ok(t)
    }
}

/// A Netlink socket helpers.
/// @imitates [libmnl::struct mnl_socket]
pub struct Socket {
    fd: c_int,
    addr: sockaddr_nl,
}

impl Socket {
    /// open a netlink socket with appropriate flags
    ///
    /// creates `Socket` structure, allows to set flags like SOCK_CLOEXEC at
    /// socket creation time (useful for multi-threaded programs performing exec
    /// calls).
    ///
    /// @imitates: [libmnl::mnl_socket_open2, mnl_socket_open]
    pub fn open(bus: netlink::Family, flags: u32) -> Result<Self> {
        let fd = cvt(unsafe { libc::socket(
            libc::AF_NETLINK, libc::SOCK_RAW | flags as c_int, bus as c_int) })?;
        Ok(Self {
            fd: fd,
            addr: unsafe { zeroed() },
        })
    }

    /// obtain Netlink PortID from netlink socket
    ///
    /// This function returns the Netlink PortID of a given netlink socket. It's
    /// a common mistake to assume that this PortID equals the process ID which
    /// is not always true. This is the case if you open more than one socket
    /// that is binded to the same Netlink subsystem from the same process.
    ///
    /// @imitates: [libmnl::mnl_socket_get_portid]
    pub fn portid(&self) -> u32 {
        self.addr.nl_pid
    }

    /// bind netlink socket
    ///
    /// You can use MNL_SOCKET_AUTOPID which is 0 for automatic port ID
    /// selection.
    ///
    /// @imitates: [libmnl::mnl_socket_bind]
    pub fn bind(&mut self, groups: u32, pid: u32) -> Result<()> {
        self.addr.nl_family = libc::AF_NETLINK as u16;
        self.addr.nl_groups = groups as c_uint;
        self.addr.nl_pid = pid;
        cvt(unsafe { libc::bind(
            self.fd,
            &self.addr as *const _ as *const sockaddr,
            size_of::<sockaddr_nl>() as u32)
        })?;
        let mut addr_len = size_of::<sockaddr_nl>() as u32;
        cvt(unsafe { libc::getsockname(
            self.fd,
            &mut self.addr as *mut _ as *mut sockaddr,
            &mut addr_len)
        })?;
        if addr_len as usize != size_of::<sockaddr_nl>() {
            return Err(Errno(libc::EINVAL));
        }
        if self.addr.nl_family as i32 != libc::AF_NETLINK {
            return Err(Errno(libc::EINVAL));
        }
        Ok(())
    }

    /// send a netlink message of a certain size
    ///
    /// @imitates: [libmnl::mnl_socket_sendto]
    pub fn sendto(&self, data: &dyn AsRef<[u8]>) -> Result<usize> {
        let mut snl: sockaddr_nl = unsafe { zeroed() };
        snl.nl_family = libc::AF_NETLINK as u16;
        let buf = data.as_ref();
        let ret = cvt(unsafe { libc::sendto(
            self.fd,
            buf.as_ptr() as *const _ as *const c_void,
            buf.len(), 0,
            &snl as *const _ as *const sockaddr,
            size_of::<sockaddr_nl>() as u32)
        })?;
        Ok(ret as usize)
    }

    /// receive a netlink message
    ///
    /// If errno is set to ENOSPC, it means that the buffer that you have passed
    /// to store the netlink message is too small, so you have received a
    /// truncated message. To avoid this, you have to allocate a buffer of
    /// `default_bufsize` (which is 8KB, see linux/netlink.h for more
    /// information). Using this buffer size ensures that your buffer is big
    /// enough to store the netlink message without truncating it.
    ///
    /// @imitates: [libmnl::mnl_socket_recvfrom]
    pub fn recvfrom(&self, buf: &mut[u8]) -> Result<usize> {
        let mut addr = unsafe { zeroed::<sockaddr_nl>() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _ as *mut c_void,
            iov_len: buf.len(),
        };
        let mut msg = libc::msghdr {
            msg_name:       &mut addr as *mut _ as *mut c_void,
            msg_namelen:    size_of::<sockaddr_nl>() as u32,
            msg_iov:        &mut iov,
            msg_iovlen:     1,
            msg_control:    ptr::null_mut(),
            msg_controllen: 0,
            msg_flags:      0,
        };
        let ret = cvt(unsafe { libc::recvmsg(self.fd, &mut msg, 0) })?;
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(Errno(libc::ENOSPC));
        }
        if msg.msg_namelen as usize != size_of::<sockaddr_nl>() {
            return Err(Errno(libc::EINVAL));
        }
        Ok(ret as usize)
    }
}

impl Drop for Socket {
    /// @imitates: [libmnl::mnl_socket_close]
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

impl AsRawFd for Socket {
    /// @imitates: [libmnl::mnl_socket_get_fd]
    fn as_raw_fd(&self) -> RawFd {
        self.fd as RawFd
    }
}

impl FromRawFd for Socket {
    /// @imitates: [libmnl::mnl_socket_fdopen]
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        let mut addr: sockaddr_nl = zeroed();
        let mut addr_len = size_of::<sockaddr_nl>() as u32;
        cvt(libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr , &mut addr_len)).unwrap();
        let mut nl = Self {
            fd: fd,
            addr: zeroed(),
        };
        if addr.nl_family as i32 == libc::AF_NETLINK {
            nl.addr = addr;
        }
        nl
    }
}

macro_rules! get_bool_opt {
    ($self:expr, $f:expr) => ( {
        let ret = unsafe { $self.getsockopt::<c_int>($f)? };
        if ret == 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    } )
}

macro_rules! set_bool_opt {
    ($self:expr, $o:expr, $v:expr) => ( unsafe {
        $self.setsockopt::<c_int>($o, if $v { &1 } else { &0 })
    } )
}

impl Socket {
    /// set Netlink socket option
    ///
    /// This function allows you to set some Netlink socket option. As of
    /// writing this (see linux/netlink.h), the existing options are:
    /// <ul>
    /// <li>`#define NETLINK_ADD_MEMBERSHIP  1`</li>
    /// <li>`#define NETLINK_DROP_MEMBERSHIP 2`</li>
    /// <li>`#define NETLINK_PKTINFO         3`</li>
    /// <li>`#define NETLINK_BROADCAST_ERROR 4`</li>
    /// <li>`#define NETLINK_NO_ENOBUFS      5`</li>
    /// </ul>
    /// In the early days, Netlink only supported 32 groups expressed in a
    /// 32-bits mask. However, since 2.6.14, Netlink may have up to 2^32
    /// multicast groups but you have to use setsockopt() with
    /// NETLINK_ADD_MEMBERSHIP to join a given multicast group. This function
    /// internally calls setsockopt() to join a given netlink multicast
    /// group. You can still use mnl_bind() and the 32-bit mask to join a set of
    /// Netlink multicast groups.
    ///
    /// @imitates: [libmnl::mnl_socket_setsockopt]
    unsafe fn setsockopt<T>(&self, otype: i32, opt: &T) -> Result<()> {
        cvt(libc::setsockopt(
            self.fd,
            libc::SOL_NETLINK,
            otype,
            opt as *const _ as *const c_void,
            size_of::<T>() as u32))?;
        Ok(())
    }

    /// get a Netlink socket option
    ///
    /// @imitates: [libmnl::mnl_socket_getsockopt]
    unsafe fn getsockopt<T>(&self, otype: i32) -> Result<T> {
        let mut opt = zeroed::<T>();
        let mut optlen = size_of::<T>() as u32;
        cvt(libc::getsockopt(
            self.fd,
            libc::SOL_NETLINK,
            otype,
            &mut opt as *mut _ as *mut c_void,
            &mut optlen as *mut u32))?;
        Ok(opt)
    }

    // NETLINK_ADD_MEMBERSHIP		1
    // NETLINK_DROP_MEMBERSHIP		2
    // NETLINK_PKTINFO			3
    // NETLINK_BROADCAST_ERROR		4
    // NETLINK_NO_ENOBUFS		5
    // NETLINK_LISTEN_ALL_NSID		8
    // NETLINK_LIST_MEMBERSHIPS		9
    // NETLINK_CAP_ACK			10
    // NETLINK_EXT_ACK			11

    //getsockopt
	// case NETLINK_PKTINFO:
	// 	if (len < sizeof(int))
	// 		return -EINVAL;
	// 	len = sizeof(int);
	// 	val = nlk->flags & NETLINK_F_RECV_PKTINFO ? 1 : 0;
	// 	if (put_user(len, optlen) ||
	// 	    put_user(val, optval))
	// 		return -EFAULT;
	// 	err = 0;
	// 	break;
	// case NETLINK_BROADCAST_ERROR:
	// 	if (len < sizeof(int))
	// 		return -EINVAL;
	// 	len = sizeof(int);
	// 	val = nlk->flags & NETLINK_F_BROADCAST_SEND_ERROR ? 1 : 0;
	// 	if (put_user(len, optlen) ||
	// 	    put_user(val, optval))
	// 		return -EFAULT;
	// 	err = 0;
	// 	break;
	// case NETLINK_NO_ENOBUFS:
	// 	if (len < sizeof(int))
	// 		return -EINVAL;
	// 	len = sizeof(int);
	// 	val = nlk->flags & NETLINK_F_RECV_NO_ENOBUFS ? 1 : 0;
	// 	if (put_user(len, optlen) ||
	// 	    put_user(val, optval))
	// 		return -EFAULT;
	// 	err = 0;
	// 	break;
	// case NETLINK_LIST_MEMBERSHIPS: {
	// 	int pos, idx, shift;
        //
	// 	err = 0;
	// 	netlink_lock_table();
	// 	for (pos = 0; pos * 8 < nlk->ngroups; pos += sizeof(u32)) {
	// 		if (len - pos < sizeof(u32))
	// 			break;
        //
	// 		idx = pos / sizeof(unsigned long);
	// 		shift = (pos % sizeof(unsigned long)) * 8;
	// 		if (put_user((u32)(nlk->groups[idx] >> shift),
	// 			     (u32 __user *)(optval + pos))) {
	// 			err = -EFAULT;
	// 			break;
	// 		}
	// 	}
	// 	if (put_user(ALIGN(nlk->ngroups / 8, sizeof(u32)), optlen))
	// 		err = -EFAULT;
	// 	netlink_unlock_table();
	// 	break;
	// }
	// case NETLINK_CAP_ACK:
	// 	if (len < sizeof(int))
	// 		return -EINVAL;
	// 	len = sizeof(int);
	// 	val = nlk->flags & NETLINK_F_CAP_ACK ? 1 : 0;
	// 	if (put_user(len, optlen) ||
	// 	    put_user(val, optval))
	// 		return -EFAULT;
	// 	err = 0;
	// 	break;
	// case NETLINK_EXT_ACK:
	// 	if (len < sizeof(int))
	// 		return -EINVAL;
	// 	len = sizeof(int);
	// 	val = nlk->flags & NETLINK_F_EXT_ACK ? 1 : 0;
	// 	if (put_user(len, optlen) || put_user(val, optval))
	// 		return -EFAULT;
	// 	err = 0;
	// 	break;

    pub fn pktinfo(&self) -> Result<bool> {
        get_bool_opt!(self, libc::NETLINK_PKTINFO)
    }

    pub fn broadcast_error(&self) -> Result<bool> {
        get_bool_opt!(self, libc::NETLINK_BROADCAST_ERROR)
    }

    pub fn no_enobufs(&self) -> Result<bool> {
        get_bool_opt!(self, libc::NETLINK_NO_ENOBUFS)
    }

    pub fn list_membership(&self) -> Result<Vec<u32>> {
        let mut size = 0u32;
        cvt(unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                ptr::null_mut::<c_void>(),
                &mut size)})?;
        let mut v = vec![0u32; size as usize];
        cvt(unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                v.as_mut_ptr() as *mut _ as *mut c_void,
                &mut size)})?;
        Ok(v)
    }

    pub fn cap_ack(&self) -> Result<bool> {
        get_bool_opt!(self, libc::NETLINK_CAP_ACK)
    }

    pub fn ext_ack(&self) -> Result<bool> {
        get_bool_opt!(self, netlink::NETLINK_EXT_ACK)
    }

//setsockopt
	// if (optlen >= sizeof(int) &&
	//     get_user(val, (unsigned int __user *)optval))
	// 	return -EFAULT;

	// switch (optname) {
	// case NETLINK_PKTINFO:
	// 	if (val)
	// 		nlk->flags |= NETLINK_F_RECV_PKTINFO;
	// 	else
	// 		nlk->flags &= ~NETLINK_F_RECV_PKTINFO;
	// 	err = 0;
	// 	break;
	// case NETLINK_ADD_MEMBERSHIP:
	// case NETLINK_DROP_MEMBERSHIP: {
	// 	if (!netlink_allowed(sock, NL_CFG_F_NONROOT_RECV))
	// 		return -EPERM;
	// 	err = netlink_realloc_groups(sk);
	// 	if (err)
	// 		return err;
	// 	if (!val || val - 1 >= nlk->ngroups)
	// 		return -EINVAL;
	// 	if (optname == NETLINK_ADD_MEMBERSHIP && nlk->netlink_bind) {
	// 		err = nlk->netlink_bind(sock_net(sk), val);
	// 		if (err)
	// 			return err;
	// 	}
	// 	netlink_table_grab();
	// 	netlink_update_socket_mc(nlk, val,
	// 				 optname == NETLINK_ADD_MEMBERSHIP);
	// 	netlink_table_ungrab();
	// 	if (optname == NETLINK_DROP_MEMBERSHIP && nlk->netlink_unbind)
	// 		nlk->netlink_unbind(sock_net(sk), val);

	// 	err = 0;
	// 	break;
	// }
	// case NETLINK_BROADCAST_ERROR:
	// 	if (val)
	// 		nlk->flags |= NETLINK_F_BROADCAST_SEND_ERROR;
	// 	else
	// 		nlk->flags &= ~NETLINK_F_BROADCAST_SEND_ERROR;
	// 	err = 0;
	// 	break;
	// case NETLINK_NO_ENOBUFS:
	// 	if (val) {
	// 		nlk->flags |= NETLINK_F_RECV_NO_ENOBUFS;
	// 		clear_bit(NETLINK_S_CONGESTED, &nlk->state);
	// 		wake_up_interruptible(&nlk->wait);
	// 	} else {
	// 		nlk->flags &= ~NETLINK_F_RECV_NO_ENOBUFS;
	// 	}
	// 	err = 0;
	// 	break;
	// case NETLINK_LISTEN_ALL_NSID:
	// 	if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_BROADCAST))
	// 		return -EPERM;

	// 	if (val)
	// 		nlk->flags |= NETLINK_F_LISTEN_ALL_NSID;
	// 	else
	// 		nlk->flags &= ~NETLINK_F_LISTEN_ALL_NSID;
	// 	err = 0;
	// 	break;
	// case NETLINK_CAP_ACK:
	// 	if (val)
	// 		nlk->flags |= NETLINK_F_CAP_ACK;
	// 	else
	// 		nlk->flags &= ~NETLINK_F_CAP_ACK;
	// 	err = 0;
	// 	break;
	// case NETLINK_EXT_ACK:
	// 	if (val)
	// 		nlk->flags |= NETLINK_F_EXT_ACK;
	// 	else
	// 		nlk->flags &= ~NETLINK_F_EXT_ACK;
	// 	err = 0;
	// 	break;
	// default:
	// 	err = -ENOPROTOOPT;
	// }
	// return err;
    pub fn set_pktinfo(&self, v: bool) -> Result<()> {
        set_bool_opt!(&self, libc::NETLINK_PKTINFO, v)
    }

    pub fn add_membership(&self, v: u32) -> Result<()> {
        unsafe {
            self.setsockopt(libc::NETLINK_ADD_MEMBERSHIP, &v)
        }
    }

    pub fn drop_membership(&self, v: u32) -> Result<()> {
        unsafe {
            self.setsockopt(libc::NETLINK_DROP_MEMBERSHIP, &v)
        }
    }

    pub fn set_broadcast_error(&self, v: bool) -> Result<()> {
        set_bool_opt!(&self, libc::NETLINK_BROADCAST_ERROR, v)
    }

    pub fn set_no_enobufs(&self, v: bool) -> Result<()> {
        set_bool_opt!(&self, libc::NETLINK_NO_ENOBUFS, v)
    }

    pub fn set_listen_all_nsid(&self, v: bool) -> Result<()> {
        set_bool_opt!(&self, libc::NETLINK_LISTEN_ALL_NSID, v)
    }

    pub fn set_cap_ack(&self, v: bool) -> Result<()> {
        set_bool_opt!(&self, libc::NETLINK_CAP_ACK, v)
    }

    pub fn set_ext_ack(&self, v: bool) -> Result<()> {
        // set_bool_opt!(&self, libc::NETLINK_EXT_ACK, v)
        set_bool_opt!(&self, netlink::NETLINK_EXT_ACK, v)
    }
}
