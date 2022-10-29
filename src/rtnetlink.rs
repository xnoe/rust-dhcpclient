#[repr(C)]
pub struct ifinfomsg {
    pub ifi_family: libc::__u8,
    pub ifi_pad: libc::__u8,
    pub ifi_type: libc::__u16,
    pub ifi_index: libc::c_int,
    pub ifi_flags: libc::__u32,
    pub ifi_change: libc::__u32,
}

#[repr(C)]
pub struct ifaddrmsg {
    pub ifa_family: libc::c_uchar,
    pub ifa_prefixlen: libc::c_uchar,
    pub ifa_flags: libc::c_uchar,
    pub ifa_scope: libc::c_uchar,
    pub ifa_index: libc::c_int,
}

#[repr(C)]
pub struct rtmsg {
    pub rtm_family: libc::c_uchar,
    pub rtm_dst_len: libc::c_uchar,
    pub rtm_src_len: libc::c_uchar,
    pub rtm_tos: libc::c_uchar,
    pub rtm_table: libc::c_uchar,

    pub rtm_protocol: libc::c_uchar,
    pub rtm_scope: libc::c_uchar,
    pub rtm_type: libc::c_uchar,

    pub rtm_flags: libc::c_uint,
}

#[repr(C)]
pub struct ifa_cacheinfo {
    pub ifa_preferred: libc::__u32,
    pub ifa_valid: libc::__u32,
    pub cstamp: libc::__u32,
    pub tstamp: libc::__u32,
}

#[repr(C)]
pub struct rta_cacheinfo {
    pub rta_clntref: libc::__u32,
    pub rta_lastuse: libc::__u32,
    pub rta_expires: libc::__u32,
    pub rta_error: libc::__u32,
    pub rta_used: libc::__u32,
    pub rta_id: libc::__u32,
    pub rta_ts: libc::__u32,
    pub rta_tsage: libc::__u32,
}

#[allow(non_upper_case_globals)]
const nlmsg_alignto: u32 = 4;

macro_rules! nlmsg_align {
    ($len:expr) => {
        ($len as u32 + (nlmsg_alignto - 1)) & !(nlmsg_alignto - 1)
    };
}

#[allow(non_upper_case_globals)]
const nlmsg_hdrlen: usize = nlmsg_align!(std::mem::size_of::<libc::nlmsghdr>()) as usize;

pub fn nlmsg_length(len: u32) -> u32 {
    len as u32 + nlmsg_hdrlen as u32
}

#[inline]
pub unsafe fn nlmsg_data(nlh: *const libc::nlmsghdr) -> *const u8 {
    return (nlh as *const u8).offset(nlmsg_hdrlen as isize);
}

#[inline]
unsafe fn nlmsg_next(nlh: *const libc::nlmsghdr, len: &mut u32) -> *const libc::nlmsghdr {
    *len -= nlmsg_align!((*nlh).nlmsg_len);
    return (nlh as *const u8).offset(nlmsg_align!((*nlh).nlmsg_len) as isize)
        as *const libc::nlmsghdr;
}

#[inline]
unsafe fn nlmsg_ok(nlh: *const libc::nlmsghdr, len: &mut u32) -> bool {
    return *len >= std::mem::size_of::<libc::nlmsghdr>() as u32
        && (*nlh).nlmsg_len >= std::mem::size_of::<libc::nlmsghdr>() as u32
        && (*nlh).nlmsg_len <= *len;
}

#[repr(C)]
pub struct rtattr {
    pub rta_len: libc::c_ushort,
    pub rta_type: libc::c_ushort,
}

#[allow(non_upper_case_globals)]
const rta_alignto: u32 = 4;

macro_rules! rta_align {
    ($len:expr) => {
        ($len as u32 + (rta_alignto - 1)) & !(rta_alignto - 1)
    };
}

#[inline]
pub unsafe fn rta_ok(rta: *const rtattr, len: &mut u32) -> bool {
    return *len >= std::mem::size_of::<rtattr>() as u32
        && (*rta).rta_len >= std::mem::size_of::<rtattr>() as libc::c_ushort
        && (*rta).rta_len <= *len as libc::c_ushort;
}

#[inline]
pub unsafe fn rta_next(rta: *const rtattr, len: &mut u32) -> *const rtattr {
    *len -= rta_align!((*rta).rta_len);
    return (rta as *const u8).offset(nlmsg_align!((*rta).rta_len) as isize) as *const rtattr;
}

#[inline]
fn rta_length(len: u32) -> u32 {
    return std::mem::size_of::<rtattr>() as u32 + len;
}

#[inline]
pub unsafe fn rta_data(rta: *const rtattr) -> *const u8 {
    return (rta as *const u8).offset(rta_length(0) as isize);
}

struct RtAttrs {
    current_attr: *const rtattr,
    current_size: u32,
}

impl Iterator for RtAttrs {
    type Item = *const rtattr;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if rta_ok(self.current_attr, &mut self.current_size) {
                let hdr = self.current_attr;
                self.current_attr = rta_next(self.current_attr, &mut self.current_size);
                return Some(hdr);
            } else {
                None
            }
        }
    }
}

#[inline]
unsafe fn ifla_rta(r: *const ifinfomsg) -> *const rtattr {
    return (r as *const u8).offset(nlmsg_align!(std::mem::size_of::<ifinfomsg>()) as isize)
        as *const rtattr;
}

pub struct Socket {
    socket: libc::c_int,
    src_addr: libc::sockaddr_nl,
    dest_addr: libc::sockaddr_nl
}

pub fn create_netlink_socket(subscribed: bool) -> Result<Socket, &'static str> {
    let mut src_addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    let mut dest_addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };

    src_addr.nl_family = libc::AF_NETLINK as u16;
    if subscribed {
        src_addr.nl_groups = libc::RTMGRP_LINK as u32;
    }
    src_addr.nl_pid = unsafe { libc::getpid() } as u32;

    dest_addr.nl_family = libc::AF_NETLINK as u16;

    let socket;
    unsafe {
        socket = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        if socket == -1 {
            return Err("Failed to create socket");
        }

        if libc::bind(socket, &src_addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) == -1 {
            return Err("Failed to bind to socket");
        }
    }

    Ok(Socket {
        socket: socket,
        src_addr: src_addr,
        dest_addr: dest_addr
    })
}

impl Socket {
    pub fn send(&mut self, msg: &[u8]) -> Result<(), i32> {
        let mut iov = libc::iovec {
            iov_base: msg as *const _ as *mut libc::c_void,
            iov_len: msg.len() as usize,
        };
    
        let mut msg = unsafe { std::mem::zeroed::<libc::msghdr>() };
        msg.msg_name = &mut self.dest_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        msg.msg_iov = &mut iov as *mut libc::iovec;
        msg.msg_iovlen = 1;

        if unsafe { libc::sendmsg(self.socket, &msg as *const libc::msghdr, 0) } < 0 {
            return Err(unsafe { *libc::__errno_location() });
        }

        Ok(())
    }

    pub fn recv<const N: usize>(&mut self, buffer: &mut [u8; N]) -> Result<isize, i32> {
        let mut iov = libc::iovec {
            iov_base: buffer as *mut _ as *mut libc::c_void,
            iov_len: N,
        };

        let mut msg = unsafe { std::mem::zeroed::<libc::msghdr>() };
        msg.msg_name = &mut self.src_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        msg.msg_iov = &mut iov as *mut libc::iovec;
        msg.msg_iovlen = 1;

        let n = unsafe { libc::recvmsg(self.socket, &mut msg as *mut libc::msghdr, 0) };
        if n < 0 {
            return Err(n as i32);
        } else {
            return Ok(n);
        }
    }
}

pub struct InterfaceIterator {
    socket: Socket,

    buffer: [u8; 4096],
    current_header: Option<*const libc::nlmsghdr>,
    current_len: u32,
}

pub unsafe fn to_slice<T: Sized>(p: &T) -> &[u8] {
    std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        std::mem::size_of::<T>(),
    )
}

pub fn new_interface_iterator() -> Result<InterfaceIterator, &'static str> {
    let mut socket = create_netlink_socket(true).unwrap();

    let mut request = unsafe { std::mem::zeroed::<(libc::nlmsghdr, ifinfomsg)>() };
    request.0.nlmsg_len = nlmsg_length(std::mem::size_of::<ifinfomsg>() as u32);
    request.0.nlmsg_type = libc::RTM_GETLINK;
    request.0.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    request.1.ifi_family = libc::AF_NETLINK as u8;

    socket.send(unsafe {to_slice(&request)}).expect("Failed to send interface request!");

    Ok(InterfaceIterator {
        socket: socket,

        buffer: [0; 4096],
        current_header: None,
        current_len: 0,
    })
}

pub struct InterfaceDetails {
    pub index: i32,
    pub name: [libc::c_char; libc::IFNAMSIZ],
    pub hwaddr: [u8; 6],
}

pub enum MessageType {
    NewLink(InterfaceDetails),
    DelLink(InterfaceDetails),
}

impl Iterator for InterfaceIterator {
    type Item = MessageType;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let None = self.current_header {
                let n = self.socket.recv(&mut self.buffer).unwrap();
                if n < 0 {
                    panic!("Failed to receive on AF_NETLINK socket!");
                }

                self.current_header = Some(&self.buffer as *const _ as *const libc::nlmsghdr);
                self.current_len = n as u32;
            }

            if unsafe { !nlmsg_ok(self.current_header.unwrap(), &mut self.current_len) } {
                self.current_header = None;
                continue;
            }

            if unsafe { (*self.current_header.unwrap()).nlmsg_type } == libc::NLMSG_DONE as u16 {
                self.current_header = None;
                continue;
            }

            let hdr = self.current_header.unwrap();
            self.current_header =
                Some(unsafe { nlmsg_next(self.current_header.unwrap(), &mut self.current_len) });

            let ifi = unsafe { std::ptr::read(nlmsg_data(hdr) as *const ifinfomsg) };

            if ifi.ifi_type != 1 {
                continue;
            }

            let mut addr: [u8; 6] = [0; 6];
            let mut name: [libc::c_char; libc::IFNAMSIZ] = [0; libc::IFNAMSIZ];

            for attr in (RtAttrs {
                current_attr: unsafe { ifla_rta(nlmsg_data(hdr) as *const ifinfomsg) },
                current_size: unsafe { (*hdr).nlmsg_len }
                    - std::mem::size_of::<libc::nlmsghdr>() as u32,
            }) {
                match unsafe { (*attr).rta_type } {
                    libc::IFLA_ADDRESS => {
                        addr = unsafe { std::ptr::read(rta_data(attr) as *const [u8; 6]) };
                    }

                    libc::IFLA_IFNAME => {
                        name = unsafe {
                            std::ptr::read(rta_data(attr) as *const [libc::c_char; libc::IFNAMSIZ])
                        };
                    }

                    _ => (),
                }
            }

            let interfacedetails = InterfaceDetails {
                index: ifi.ifi_index,
                name: name,
                hwaddr: addr,
            };

            match unsafe { (*hdr).nlmsg_type } {
                libc::RTM_NEWLINK => return Some(MessageType::NewLink(interfacedetails)),
                libc::RTM_DELLINK => return Some(MessageType::DelLink(interfacedetails)),
                _ => panic!("Unknown Message Received! {}", unsafe { (*hdr).nlmsg_type }),
            }
        }
    }
}
