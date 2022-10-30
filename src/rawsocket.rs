fn pad_array<const N: usize, T: Default + Copy>(src: &[T]) -> [T; N] {
    let mut arr = [Default::default(); N];
    arr[..src.len()].copy_from_slice(src);
    arr
}

pub struct RawSocket {
    socket: libc::c_int,
    src_addr: libc::sockaddr_ll,
    dest_addr: libc::sockaddr_ll,
    if_index: i32,
}

pub fn create_raw_socket(index: i32, mac: [u8; 6]) -> Result<RawSocket, &'static str> {
    let src_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_halen: 6,
        sll_hatype: 1,
        sll_ifindex: index,
        sll_addr: pad_array(&mac),
        sll_pkttype: 0,
        sll_protocol: 0x0008,
    };

    let dest_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_halen: 6,
        sll_hatype: 1,
        sll_ifindex: index,
        sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
        sll_pkttype: 0,
        sll_protocol: 0x0008,
    };

    let socket;
    unsafe {
        socket = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
        if socket == -1 {
            return Err("Failed to create socket");
        }

        let mut timeval = std::mem::zeroed::<libc::timeval>();
        timeval.tv_sec = 30;

        if libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        ) == -1
        {
            return Err("Failed to set SO_RCVTIMEO");
        }

        if libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &(1 as u32) as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as u32,
        ) == -1
        {
            return Err("Failed to set SO_BROADCAST");
        }

        if libc::bind(
            socket,
            &src_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        ) == -1
        {
            return Err("Failed to bind to socket");
        }
    }

    Ok(RawSocket {
        socket: socket,
        src_addr: src_addr,
        dest_addr: dest_addr,
        if_index: index,
    })
}

impl RawSocket {
    pub fn send(&mut self, msg: &[u8]) -> Result<isize, i32> {
        let mut iov = libc::iovec {
            iov_base: msg as *const _ as *mut libc::c_void,
            iov_len: msg.len() as usize,
        };

        let mut msg = unsafe { std::mem::zeroed::<libc::msghdr>() };
        msg.msg_name = &mut self.dest_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        msg.msg_iov = &mut iov as *mut libc::iovec;
        msg.msg_iovlen = 1;

        let count = unsafe { libc::sendmsg(self.socket, &msg as *const libc::msghdr, 0) };
        if count < 0 {
            return Err(unsafe { *libc::__errno_location() });
        }

        Ok(count)
    }

    pub fn recv<const N: usize>(&mut self, buffer: &mut [u8; N]) -> Result<(isize, [u8; 6]), i32> {
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
            match unsafe { *libc::__errno_location() } {
                libc::EAGAIN => return Ok((0, [0, 0, 0, 0, 0, 0])),
                err => return Err(err),
            }
        } else {
            return Ok((
                n,
                unsafe { std::ptr::read(msg.msg_name as *mut _ as *mut libc::sockaddr_ll) }
                    .sll_addr[..6]
                    .try_into()
                    .unwrap(),
            ));
        }
    }

    pub fn set_destination_to_broadcast(&mut self) {
        self.dest_addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_halen: 6,
            sll_hatype: 1,
            sll_ifindex: self.if_index,
            sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
            sll_pkttype: 0,
            sll_protocol: 0x0008,
        };
    }

    pub fn set_destination_to(&mut self, addr: [u8; 6]) {
        self.dest_addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_halen: 6,
            sll_hatype: 1,
            sll_ifindex: self.if_index,
            sll_addr: pad_array(&addr),
            sll_pkttype: 0,
            sll_protocol: 0x0008,
        };
    }
}
