use std::{
    env,
    time::Duration,
    os::unix::io::{ AsRawFd, FromRawFd },
    mem,
    net::{ IpAddr, Ipv4Addr, Ipv6Addr },
    collections::HashMap,
};

extern crate libc;
extern crate mio;
extern crate errno;
extern crate rsmnl as mnl;

use errno::Errno;
use libc::{ c_int, c_void, socklen_t };
use mnl::{
    Attr, Msghdr, CbStatus, CbResult, AttrTbl, Socket, GenError, Result,
    linux::netlink,
    linux::netlink::Family,
    linux::netfilter::nfnetlink as nfnl,
    linux::netfilter::nfnetlink::Nfgenmsg,
    linux::netfilter::nfnetlink_conntrack as nfct,
    linux::netfilter::nfnetlink_conntrack::{
        CtattrTypeTbl, CtattrType,
        CtattrCountersTbl, CtattrCounters,
        CtattrIpTbl,
        CtattrTupleTbl, CtattrTuple,
    }
};

mod timerfd;

#[derive(Debug)]
struct Nstats {
    pkts: u64,
    bytes: u64,
}

#[allow(dead_code)]
fn parse_counters<'a>(nest: &'a Attr, ns: &'a mut Nstats) -> Result<()> {
    let tb = CtattrCountersTbl::from_nest(nest)?;
    tb[CtattrCounters::Packets]
        .map(|attr| {
            match attr.value() {
                Ok(n) => { ns.pkts += u64::from_be(n); Ok(n) },
                ret @ Err(_) => return ret
            }
        });
    tb[CtattrCounters::Bytes]
        .map(|attr| {
            match attr.value() {
                Ok(n) => { ns.bytes += u64::from_be(n); Ok(n) },
                ret @ Err(_) => return ret
            }
        });
    Ok(())
}

#[allow(dead_code)]
fn parse_ip(nest: &Attr, addr: &mut IpAddr) -> Result<()> {
    let tb = CtattrIpTbl::from_nest(nest)?;
    tb.v4src_array()?.map(|r| {
        *addr = IpAddr::V4(Ipv4Addr::new(r[0], r[1], r[2], r[3]));
    });
    tb.v6src_array()?.map(|r| {
        *addr = IpAddr::V6(Ipv6Addr::new(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]));
    });
    Ok(())
}

#[allow(dead_code)]
fn parse_tuple(nest: &Attr, addr: &mut IpAddr) -> Result<()> {
    let tb = CtattrTupleTbl::from_nest(nest)?;
    tb[CtattrTuple::Ip].map(|attr| parse_ip(attr, addr));
    Ok(())
}

fn data_cb(hmap: &mut HashMap<IpAddr, Box<Nstats>>)
           -> impl FnMut(&Msghdr) -> CbResult + '_
{
    move |nlh: &Msghdr| {
        let mut addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)); // XXX: no default?
        let mut ns = Box::new(Nstats { pkts: 0, bytes: 0 });
        let tb = CtattrTypeTbl::from_nlmsg(mem::size_of::<nfnl::Nfgenmsg>(), nlh)?;

        // tb[CtattrType::TupleOrig]
        //     .map(|attr| parse_tuple(attr, &mut addr));
        // tb[CtattrType::CountersOrig]
        //     .map(|attr| parse_counters(attr, &mut *ns));

        if let Some(tuple_tb) = tb.tuple_orig()? {
            if let Some(ip_tb) = tuple_tb.ip()? {
                ip_tb.v4src()?.map(|r| {
                    addr = IpAddr::V4(*r);
                });
                ip_tb.v6src()?.map(|r| {
                    addr = IpAddr::V6(*r);
                });
            }
        }

        if let Some(counters_tb) = tb.counters_orig()? {
            counters_tb.packets()?.map(|c| {
                ns.pkts += u64::from_be(*c);
            });
            counters_tb.bytes()?.map(|c| {
                ns.bytes += u64::from_be(*c);
            });
        }

        if let Some(cur) = hmap.get_mut(&addr) {
            cur.pkts += ns.pkts;
            cur.bytes += ns.pkts;
            return Ok(CbStatus::Ok);
        }

        hmap.insert(addr, ns);
        Ok(CbStatus::Ok)
    }
}

fn handle(nl: &mut Socket, hmap: &mut HashMap<IpAddr, Box<Nstats>>) -> CbResult {
    let mut buf = mnl::default_buf();
    match nl.recvfrom(&mut buf) {
        Ok(nrecv) =>
            return mnl::cb_run(&mut buf[0..nrecv], 0, 0, Some(data_cb(hmap))),

        Err(errno) => {
            if errno.0 == libc::ENOBUFS {
                println!("The daemon has hit ENOBUFS, you can \
			  increase the size of your receiver \
			  buffer to mitigate this or enable \
			  reliable delivery.");
            } else {
                println!("mnl_socket_recvfrom: {}", errno);
            }
            return mnl::gen_errno!(errno.0);
        },
    }
}

////////

pub const SO_RECVBUFFORCE: c_int = 33;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("\nUsage: {} <poll-secs>", args[0]);
    }
    let secs = args[1].parse::<u32>().unwrap();
    println!("Polling every {} seconds from kernel...", secs);

    // Tbl high priority for this process, less chances to overrun
    // the netlink receiver buffer since the scheduler gives this process
    // more chances to run.
    unsafe { libc::nice(-20); };

    let mut nl = Socket::open(Family::Netfilter, 0)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(nfct::NF_NETLINK_CONNTRACK_DESTROY, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    unsafe {
	// Set netlink receiver buffer to 16 MBytes, to avoid packet drops
        let buffersize: c_int = 1 << 22;
        libc::setsockopt(nl.as_raw_fd(), libc::SOL_SOCKET, SO_RECVBUFFORCE,
                         &buffersize as *const _ as *const c_void, mem::size_of::<socklen_t>() as u32);
    }
    // The two tweaks below enable reliable event delivery, packets may
    // be dropped if the netlink receiver buffer overruns. This happens ...
    //
    // a) if the kernel spams this user-space process until the receiver
    //    is filled.
    //
    // or:
    //
    // b) if the user-space process does not pull messages from the
    //    receiver buffer so often.
    let _ = nl.set_broadcast_error(true);
    let _ = nl.set_no_enobufs(true);

    let mut buf = mnl::default_buf();
    let mut nlh = Msghdr::put_header(&mut buf).unwrap();
    // Counters are atomically zeroed in each dump
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | nfct::IPCTNL_MSG_CT_GET_CTRZERO;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;

    let nfh = nlh.put_extra_header::<Nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = nfnl::NFNETLINK_V0;
    nfh.res_id = 0;

    // Filter by mark: We only want to dump entries whose mark is zero
    // nlh.put(CtattrType::Mark, &0u32.to_be()).unwrap();
    CtattrType::put_mark(&mut nlh, &0u32.to_be()).unwrap();
    // nlh.put(CtattrType::MarkMask, &0xffffffffu32.to_be()).unwrap();
    CtattrType::put_mark_mask(&mut nlh, &0xffffffffu32.to_be()).unwrap();

    let mut hmap = HashMap::<IpAddr, Box<Nstats>>::new();

    // mio initializations
    let token = mio::Token(nl.as_raw_fd() as usize);
    let mut listener = unsafe { mio::net::UdpSocket::from_raw_fd(nl.as_raw_fd()) };
    let mut timer = timerfd::Timerfd::create(libc::CLOCK_MONOTONIC, 0).unwrap();
    timer.settime(
        0,
        &timerfd::Itimerspec {
            it_interval: Duration::new(secs as u64, 0),
            it_value: Duration::new(0, 1),
        }).unwrap();

    // Create an poll instance
    let mut poll = mio::Poll::new().unwrap();
    // Start listening for incoming connections
    poll.registry().register(&mut listener, token, mio::Interest::READABLE).unwrap();
    poll.registry().register(&mut timer, mio::Token(0), mio::Interest::READABLE).unwrap();
    // Create storage for events
    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match usize::from(event.token()) {
                0 => { // timer
                    timer.read().unwrap(); // just consume
                    nl.sendto(&nlh)
                        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
                    for (addr, nstats) in hmap.iter() {
                        print!("src={:?} ", addr);
                        println!("counters {} {}", nstats.pkts, nstats.bytes);
                    }
                },
                _ => {
                    let _ = handle(&mut nl, &mut hmap).unwrap();
                },
            }
        }
    }
}
