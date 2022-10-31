pub mod rawsocket;
pub mod rtnetlink;

use eui48::MacAddress;
use rand::prelude::*;
use std::net::Ipv4Addr;

use dhcprs::dhcp::DHCPMessageType;
use dhcprs::dhcp::DHCPOption;

use std::collections::HashMap;

use std::io::Write;

fn create_dhcp_packet(
    xid: u32,
    mac: MacAddress,
    source_ip: Option<Ipv4Addr>,
    dest_ip: Option<Ipv4Addr>,
    options: Vec<dhcprs::dhcp::DHCPOption>,
) -> dhcprs::udpbuilder::RawUDPPacket {
    let options_bytes = dhcprs::dhcp::DHCPOption::to_bytes(options);
    let mut vend = [0; 312];
    vend[..options_bytes.len()].copy_from_slice(&options_bytes);

    let bootppacket = dhcprs::bootp::BOOTPPacket::new(
        dhcprs::bootp::OpCode::BOOTREQUEST, // This is a DHCP client, we'll only be dealing with bootrequests
        0,
        xid,
        0,
        0,
        source_ip,
        None,
        dest_ip,
        None,
        mac,
        [0; 64],
        [0; 128],
        vend,
    );

    let udppacket = dhcprs::udpbuilder::UDPPacket::new(
        source_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
        dest_ip.unwrap_or(Ipv4Addr::new(255, 255, 255, 255)),
        68,
        67,
        dhcprs::bootp::RawBOOTPPacket::from(bootppacket)
            .as_bytes()
            .try_into()
            .unwrap(),
    );

    return dhcprs::udpbuilder::RawUDPPacket::from(udppacket);
}

enum DHCPTransactionState {
    Discover,
    WaitingAfterDiscover,
    Request,
    WaitAfterRequest,
    Renew,
}

fn pick_weighted<T>(list: &Vec<T>) -> Option<&T> {
    let len = list.len();
    let mut rng = rand::thread_rng();
    let mut prob = rng.gen_range(0f64..=1f64);

    for (idx, elem) in list.iter().enumerate() {
        let weight = 1f64 / (2 as usize).pow(idx as u32 + (len != idx + 1) as u32) as f64;

        prob -= weight;

        if prob <= 0.0 {
            return Some(elem);
        }
    }

    // fallback in case of float rounding errors i suppose
    list.choose(&mut rng)
}

fn dhcp_client(name: String, index: i32, mac: [u8; 6]) {
    unsafe {
        libc::sleep(5);
    }
    let mut name = name;
    let mut socket_nl = rtnetlink::create_netlink_socket(false).unwrap();
    let mut rng = rand::thread_rng();
    // Before we can do anything else, we need to construct an LinkAddr for the mac ff:ff:ff:ff:ff:ff

    let mut socket = rawsocket::create_raw_socket(index, mac).unwrap();

    let client_mac = MacAddress::from_bytes(&mac).unwrap();

    let mut client_addr: Option<Ipv4Addr> = None;
    let mut server_addr: Option<Ipv4Addr> = None;

    // DHCP transaction loop
    'dhcp_transaction: loop {
        let xid: u32 = rng.gen();

        let mut dhcp_state = DHCPTransactionState::Discover;

        'dhcp_message_loop: loop {
            match &dhcp_state {
                DHCPTransactionState::Discover => {
                    loop {
                        println!("Sent DHCPDiscover on {}", name);
                        match socket.send(
                            create_dhcp_packet(
                                xid,
                                client_mac,
                                None,
                                None,
                                vec![
                                    DHCPOption::DHCPMessageType(DHCPMessageType::DHCPDiscover),
                                    DHCPOption::End,
                                ],
                            )
                            .as_bytes(),
                        ) {
                            Ok(_) => break,
                            Err(libc::ENETDOWN) => unsafe {
                                {
                                    #[repr(packed)]
                                    struct Request {
                                        a: libc::nlmsghdr,
                                        b: rtnetlink::ifinfomsg,
                                    }
                                    let mut request = std::mem::zeroed::<Request>();

                                    request.a.nlmsg_len = std::mem::size_of::<Request>() as u32;
                                    request.a.nlmsg_type = libc::RTM_NEWLINK;
                                    request.a.nlmsg_flags = (libc::NLM_F_REQUEST) as u16;
                                    request.b.ifi_index = index;
                                    request.b.ifi_flags = libc::IFF_UP as u32;
                                    request.b.ifi_change = 1;

                                    socket_nl.send(rtnetlink::to_slice(&request)).unwrap();
                                }

                                {
                                    #[repr(packed)]
                                    struct Request {
                                        a: libc::nlmsghdr,
                                        b: rtnetlink::ifinfomsg,
                                    }
                                    let mut request = std::mem::zeroed::<Request>();

                                    request.a.nlmsg_len = std::mem::size_of::<Request>() as u32;
                                    request.a.nlmsg_type = libc::RTM_GETLINK;
                                    request.a.nlmsg_flags = (libc::NLM_F_REQUEST) as u16;
                                    request.b.ifi_index = index;

                                    socket_nl.send(rtnetlink::to_slice(&request)).unwrap();

                                    let mut buffer = [0; 4096];
                                    socket_nl.recv(&mut buffer).unwrap();

                                    let nlmsghdr = &buffer as *const _ as *const libc::nlmsghdr;
                                    if (*nlmsghdr).nlmsg_type != libc::RTM_NEWLINK {
                                        panic!("Wrong message!");
                                    }

                                    let mut n = (*nlmsghdr).nlmsg_len
                                        - std::mem::size_of::<libc::nlmsghdr>() as u32
                                        - std::mem::size_of::<rtnetlink::ifinfomsg>() as u32;
                                    let mut rtattr = (&buffer as *const _ as *const u8).offset(
                                        std::mem::size_of::<libc::nlmsghdr>() as isize
                                            + std::mem::size_of::<rtnetlink::ifinfomsg>() as isize,
                                    )
                                        as *const rtnetlink::rtattr;

                                    while rtnetlink::rta_ok(rtattr, &mut n) {
                                        match (*rtattr).rta_type {
                                            libc::IFLA_IFNAME => {
                                                name = zascii(&std::ptr::read(
                                                    rtnetlink::rta_data(rtattr) as *const _
                                                        as *const [libc::c_char; libc::IFNAMSIZ],
                                                ));
                                            }
                                            _ => (),
                                        }

                                        rtattr = rtnetlink::rta_next(rtattr, &mut n);
                                    }
                                }

                                libc::sleep(10);
                            },
                            Err(_) => panic!("Failed to send on {}", name),
                        }
                    }
                    dhcp_state = DHCPTransactionState::WaitingAfterDiscover;
                }

                DHCPTransactionState::WaitingAfterDiscover => {
                    let mut packet: [u8; 574] = [0; 574];
                    let (_, addr) = socket.recv(&mut packet).unwrap();

                    let udppacket_raw: dhcprs::udpbuilder::RawUDPPacket =
                        unsafe { std::ptr::read(packet.as_ptr() as *const _) };
                    let udppacket: dhcprs::udpbuilder::UDPPacket = udppacket_raw.into();

                    if udppacket.source_port != 67 {
                        // Not a BOOTP reply, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let bootppacket_raw: dhcprs::bootp::RawBOOTPPacket =
                        unsafe { std::ptr::read(udppacket.get_data().as_ptr() as *const _) };
                    let bootppacket: dhcprs::bootp::BOOTPPacket = bootppacket_raw.into();

                    if bootppacket.xid != xid {
                        // Not a reply to us, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let options =
                        dhcprs::dhcp::DHCPOption::from_bytes(&bootppacket.get_vend()[4..]);

                    if !options
                        .iter()
                        .find(|&x| {
                            if let DHCPOption::DHCPMessageType(DHCPMessageType::DHCPOffer) = x {
                                true
                            } else {
                                false
                            }
                        })
                        .is_some()
                    {
                        // We got a response but it wasn't the expected message, try again with another transaction.
                        continue 'dhcp_transaction;
                    }

                    // Valid DHCPOffer received, process it.

                    client_addr = bootppacket.yiaddr;
                    server_addr = bootppacket.siaddr;

                    println!(
                        "Got client address: {}",
                        client_addr.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
                    );
                    println!(
                        "Got server address: {}",
                        server_addr.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
                    );

                    // Update the linkaddr to be the server's actual hardware address rather than the broadcast MAC.
                    socket.set_destination_to(addr);

                    dhcp_state = DHCPTransactionState::Request;
                }

                DHCPTransactionState::Request => {
                    println!("Sent DHCPRequest on {}", name);
                    socket
                        .send(
                            create_dhcp_packet(
                                xid,
                                client_mac,
                                None,
                                None,
                                vec![
                                    DHCPOption::DHCPMessageType(DHCPMessageType::DHCPRequest),
                                    DHCPOption::RequestIPAddress(client_addr.unwrap()),
                                    DHCPOption::ServerIdentifier(server_addr.unwrap()),
                                    DHCPOption::ParameterRequest(vec![1, 3, 6, 28, 121]),
                                    DHCPOption::End,
                                ],
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    dhcp_state = DHCPTransactionState::WaitAfterRequest;
                }

                DHCPTransactionState::WaitAfterRequest => {
                    let mut packet: [u8; 574] = [0; 574];
                    socket.recv(&mut packet).unwrap();

                    let udppacket_raw: dhcprs::udpbuilder::RawUDPPacket =
                        unsafe { std::ptr::read(packet.as_ptr() as *const _) };
                    let udppacket: dhcprs::udpbuilder::UDPPacket = udppacket_raw.into();

                    if udppacket.source_port != 67 {
                        // Not a BOOTP reply, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let bootppacket_raw: dhcprs::bootp::RawBOOTPPacket =
                        unsafe { std::ptr::read(udppacket.get_data().as_ptr() as *const _) };
                    let bootppacket: dhcprs::bootp::BOOTPPacket = bootppacket_raw.into();

                    if bootppacket.xid != xid {
                        // Not a reply to us, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let options =
                        dhcprs::dhcp::DHCPOption::from_bytes(&bootppacket.get_vend()[4..]);

                    if !options
                        .iter()
                        .find(|&x| {
                            if let DHCPOption::DHCPMessageType(DHCPMessageType::DHCPACK) = x {
                                true
                            } else {
                                false
                            }
                        })
                        .is_some()
                    {
                        // Wasn't an ACK, probably NAK, try again.
                        println!("Did not receive ACK from DHCPRequest, sleeping for 10secs before continuing.");
                        std::thread::sleep(core::time::Duration::new(10, 0));
                        continue 'dhcp_transaction;
                    }

                    let mut sleep_time = 0;
                    let mut subnet_mask = Ipv4Addr::new(0, 0, 0, 0);
                    let mut router = Vec::new();
                    let mut dns = Vec::new();
                    let mut classless_static_routes = Vec::new();
                    let mut broadcast = None;

                    let mut renew_time = None;
                    let mut rebind_time = None;

                    for option in options {
                        println!("Received: {:?}", option);

                        match option {
                            DHCPOption::IPAddressLeaseTime(n) => sleep_time = n,
                            DHCPOption::SubnetMask(m) => subnet_mask = m,
                            DHCPOption::Router(v) => router = v,
                            DHCPOption::DomainNameServer(v) => dns = v,
                            DHCPOption::ClasslessStaticRoute(v) => classless_static_routes = v,

                            DHCPOption::RenewalTime(t) => renew_time = Some(t),
                            DHCPOption::RebindingTime(t) => rebind_time = Some(t),
                            DHCPOption::BroadcastAddress(a) => broadcast = Some(a),

                            _ => (),
                        }
                    }

                    unsafe {
                        {
                            #[repr(packed)]
                            struct Request {
                                a: libc::nlmsghdr,
                                b: rtnetlink::ifaddrmsg,
                                c: rtnetlink::rtattr,
                                d: [u8; 4],
                                e: rtnetlink::rtattr,
                                f: [u8; 4],
                                g: rtnetlink::rtattr,
                                h: rtnetlink::ifa_cacheinfo,
                            }
                            let mut request = std::mem::zeroed::<Request>();

                            request.a.nlmsg_len = std::mem::size_of::<Request>() as u32;
                            request.a.nlmsg_type = libc::RTM_NEWADDR;
                            request.a.nlmsg_flags =
                                (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_REPLACE)
                                    as u16;
                            request.b.ifa_family = libc::AF_INET as u8;
                            request.b.ifa_index = index;
                            request.b.ifa_prefixlen = u32::from(subnet_mask).leading_ones() as u8;
                            request.c.rta_type = libc::IFA_LOCAL;
                            request.c.rta_len =
                                std::mem::size_of::<(rtnetlink::rtattr, [u8; 4])>() as u16;
                            request.d = client_addr.unwrap().octets();
                            request.e.rta_type = libc::IFA_BROADCAST;
                            request.e.rta_len =
                                std::mem::size_of::<(rtnetlink::rtattr, [u8; 4])>() as u16;
                            if let Some(broadcast) = broadcast {
                                request.f = broadcast.octets();
                            } else {
                                request.f = ((u32::from(client_addr.unwrap())
                                    & u32::from(subnet_mask))
                                    | (!u32::from(subnet_mask)))
                                .to_be_bytes();
                            }
                            request.g.rta_type = libc::IFA_CACHEINFO;
                            request.g.rta_len = std::mem::size_of::<(
                                rtnetlink::rtattr,
                                rtnetlink::ifa_cacheinfo,
                            )>() as u16;
                            request.h.ifa_preferred =
                                renew_time.unwrap_or((sleep_time as f32 * 0.5) as u32);
                            request.h.ifa_valid =
                                rebind_time.unwrap_or((sleep_time as f32 * 0.875) as u32);

                            socket_nl.send(rtnetlink::to_slice(&request)).unwrap();
                        }

                        {
                            #[repr(packed)]
                            struct Request {
                                a: libc::nlmsghdr,
                                b: rtnetlink::rtmsg,
                                c: rtnetlink::rtattr,
                                d: [u8; 4],
                                e: rtnetlink::rtattr,
                                f: libc::c_int,
                                g: rtnetlink::rtattr,
                                h: rtnetlink::rta_cacheinfo,
                            }

                            let mut request = std::mem::zeroed::<Request>();

                            request.a.nlmsg_len = std::mem::size_of::<Request>() as u32;
                            request.a.nlmsg_type = libc::RTM_NEWROUTE;
                            request.a.nlmsg_flags =
                                (libc::NLM_F_REQUEST | libc::NLM_F_CREATE) as u16;
                            request.b.rtm_family = libc::AF_INET as u8;
                            request.b.rtm_table = libc::RT_TABLE_MAIN;
                            request.b.rtm_type = libc::RTN_UNICAST;
                            request.b.rtm_protocol = 16; // DHCP
                            request.b.rtm_scope = libc::RT_SCOPE_LINK;
                            request.b.rtm_dst_len = u32::from(subnet_mask).leading_ones() as u8;
                            request.c.rta_type = libc::RTA_DST;
                            request.c.rta_len =
                                std::mem::size_of::<(rtnetlink::rtattr, [u8; 4])>() as u16;
                            request.d = client_addr.unwrap().octets();
                            request.e.rta_type = libc::RTA_OIF;
                            request.e.rta_len =
                                std::mem::size_of::<(rtnetlink::rtattr, libc::c_int)>() as u16;
                            request.f = index;
                            request.g.rta_type = libc::RTA_CACHEINFO;
                            request.g.rta_len = std::mem::size_of::<(
                                rtnetlink::rtattr,
                                rtnetlink::rta_cacheinfo,
                            )>() as u16;
                            request.h.rta_expires =
                                rebind_time.unwrap_or((sleep_time as f32 * 0.875) as u32);

                            socket_nl.send(rtnetlink::to_slice(&request)).unwrap();
                        }

                        {
                            #[repr(packed)]
                            struct Request {
                                a: libc::nlmsghdr,
                                b: rtnetlink::rtmsg,
                                c: rtnetlink::rtattr,
                                d: [u8; 4],
                                e: rtnetlink::rtattr,
                                f: libc::c_int,
                                g: rtnetlink::rtattr,
                                h: rtnetlink::rta_cacheinfo,
                            }

                            let mut request = std::mem::zeroed::<Request>();

                            request.a.nlmsg_len = std::mem::size_of::<Request>() as u32;
                            request.a.nlmsg_type = libc::RTM_NEWROUTE;
                            request.a.nlmsg_flags =
                                (libc::NLM_F_REQUEST | libc::NLM_F_CREATE) as u16;
                            request.b.rtm_family = libc::AF_INET as u8;
                            request.b.rtm_table = libc::RT_TABLE_MAIN;
                            request.b.rtm_type = libc::RTN_UNICAST;
                            request.b.rtm_protocol = 16; // DHCP
                            request.b.rtm_scope = libc::RT_SCOPE_UNIVERSE;
                            request.b.rtm_dst_len = 0;
                            request.c.rta_type = libc::RTA_GATEWAY;
                            request.c.rta_len =
                                std::mem::size_of::<(rtnetlink::rtattr, [u8; 4])>() as u16;
                            request.d = pick_weighted(&router).unwrap().octets();
                            request.e.rta_type = libc::RTA_OIF;
                            request.e.rta_len =
                                std::mem::size_of::<(rtnetlink::rtattr, libc::c_int)>() as u16;
                            request.f = index;
                            request.g.rta_type = libc::RTA_CACHEINFO;
                            request.g.rta_len = std::mem::size_of::<(
                                rtnetlink::rtattr,
                                rtnetlink::rta_cacheinfo,
                            )>() as u16;
                            request.h.rta_expires =
                                rebind_time.unwrap_or((sleep_time as f32 * 0.875) as u32);

                            socket_nl.send(rtnetlink::to_slice(&request)).unwrap();
                        }

                        {
                            #[repr(packed)]
                            struct Request {
                                a: libc::nlmsghdr,
                                b: rtnetlink::rtmsg,
                                c: rtnetlink::rtattr,
                                d: [u8; 4],
                                e: rtnetlink::rtattr,
                                f: [u8; 4],
                                g: rtnetlink::rtattr,
                                h: libc::c_int,
                            }

                            for (prefix, prefix_len, router) in classless_static_routes {
                                let mut request = std::mem::zeroed::<Request>();

                                request.a.nlmsg_len = std::mem::size_of::<Request>() as u32;
                                request.a.nlmsg_type = libc::RTM_NEWROUTE;
                                request.a.nlmsg_flags =
                                    (libc::NLM_F_REQUEST | libc::NLM_F_CREATE) as u16;
                                request.b.rtm_family = libc::AF_INET as u8;
                                request.b.rtm_table = libc::RT_TABLE_MAIN;
                                request.b.rtm_type = libc::RTN_UNICAST;
                                request.b.rtm_protocol = 16; // DHCP
                                request.b.rtm_scope = libc::RT_SCOPE_UNIVERSE;
                                request.b.rtm_dst_len = prefix_len;
                                request.c.rta_type = libc::RTA_DST;
                                request.c.rta_len =
                                    std::mem::size_of::<(rtnetlink::rtattr, [u8; 4])>() as u16;
                                request.d = prefix.octets();
                                request.e.rta_type = libc::RTA_GATEWAY;
                                request.e.rta_len =
                                    std::mem::size_of::<(rtnetlink::rtattr, [u8; 4])>() as u16;
                                request.f = router.octets();
                                request.g.rta_type = libc::RTA_OIF;
                                request.g.rta_len =
                                    std::mem::size_of::<(rtnetlink::rtattr, libc::c_int)>() as u16;
                                request.h = index;

                                socket_nl.send(rtnetlink::to_slice(&request)).unwrap();
                            }
                        }

                        let mut f = std::fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open("/etc/resolv.conf")
                            .unwrap();
                        for server in dns {
                            f.write_all(
                                ("nameserver ".to_string() + &server.to_string() + "\n").as_bytes(),
                            )
                            .unwrap();
                        }
                        f.flush().unwrap();
                    }

                    println!(
                        "Sleeping for {} for lease time to elapse.",
                        renew_time.unwrap_or((sleep_time as f32 * 0.5) as u32)
                    );
                    std::thread::sleep(core::time::Duration::new(
                        renew_time.unwrap_or((sleep_time as f32 * 0.5) as u32) as u64,
                        0,
                    ));
                    dhcp_state = DHCPTransactionState::Renew
                }

                DHCPTransactionState::Renew => {
                    println!("[Renew] Sent DHCPRequest on {}", name);
                    let _ = socket.send(
                        create_dhcp_packet(
                            xid,
                            client_mac,
                            client_addr,
                            None,
                            vec![
                                DHCPOption::DHCPMessageType(DHCPMessageType::DHCPRequest),
                                DHCPOption::ParameterRequest(vec![1, 3, 6, 28, 121]),
                                DHCPOption::End,
                            ],
                        )
                        .as_bytes(),
                    );
                    dhcp_state = DHCPTransactionState::WaitAfterRequest;
                }
            }
        }
    }
}

fn zascii(slice: &[libc::c_char]) -> String {
    String::from_iter(
        slice
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8 as char),
    )
}

fn main() {
    let mut thread_map: HashMap<i32, libc::c_int> = HashMap::new();
    let iterator = rtnetlink::new_interface_iterator().unwrap();

    for message in iterator {
        let interface: rtnetlink::InterfaceDetails;

        match message {
            rtnetlink::MessageType::NewLink(i) => {
                interface = i;
                let name = zascii(&interface.name);
                println!("New Link");

                if let None = thread_map.get(&interface.index) {
                    println!("Starting DHCP on {}", name);
                    unsafe {
                        match libc::fork() {
                            x if x < 0 => panic!("Failed to fork!"),
                            0 => dhcp_client(name, interface.index, interface.hwaddr),
                            pid => {
                                println!("Started DHCP on {} PID {}", name, pid);
                                thread_map.insert(interface.index, pid);
                            }
                        }
                    }
                }
            }
            rtnetlink::MessageType::DelLink(i) => {
                interface = i;
                let name = zascii(&interface.name);
                println!("Del Link");

                if let Some(pid) = thread_map.get(&interface.index) {
                    println!("Stopping DHCP on {}", name);
                    unsafe {
                        libc::kill(*pid, libc::SIGTERM);
                    }
                    thread_map.remove(&interface.index);
                }
            }
        }

        let name = zascii(&interface.name);

        println!("Name: {}", name);
        println!(
            "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            interface.hwaddr[0],
            interface.hwaddr[1],
            interface.hwaddr[2],
            interface.hwaddr[3],
            interface.hwaddr[4],
            interface.hwaddr[5]
        );
        println!("Index: {}", interface.index);
    }
}
