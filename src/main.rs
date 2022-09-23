use nix::sys::socket::*;
use std::net::Ipv4Addr;
use eui48::MacAddress;
use rand::prelude::*;

use dhcprs::dhcp::DHCPOption;
use dhcprs::dhcp::DHCPMessageType;

fn create_dhcp_packet(xid: u32, mac: MacAddress, source_ip: Option<Ipv4Addr>, dest_ip: Option<Ipv4Addr>, options: Vec<dhcprs::dhcp::DHCPOption>) -> dhcprs::udpbuilder::RawUDPPacket {
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
        vend
    );

    let udppacket = dhcprs::udpbuilder::UDPPacket::new(
        source_ip.unwrap_or(Ipv4Addr::new(0,0,0,0)),
        dest_ip.unwrap_or(Ipv4Addr::new(255,255,255,255)),
        68,
        67,
        dhcprs::bootp::RawBOOTPPacket::from(bootppacket).as_bytes().try_into().unwrap()
    );

    return dhcprs::udpbuilder::RawUDPPacket::from(udppacket);
}

enum DHCPTransactionState {
    Discover,
    WaitingAfterDiscover,
    Request,
    WaitAfterRequest,

}

fn dhcp_client(name: String, mac: LinkAddr) {
    let mut rng = rand::thread_rng();
    // Before we can do anything else, we need to construct an LinkAddr for the mac ff:ff:ff:ff:ff:ff

    println!("Starting DHCP on interface {}", name);

    let sockaddr_ll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_halen: mac.halen() as u8,
        sll_hatype: mac.hatype(),
        sll_ifindex: mac.ifindex() as i32,
        sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
        sll_pkttype: mac.pkttype(),
        sll_protocol: 0x0008
    };

    let mut linkaddr = unsafe {LinkAddr::from_raw(&sockaddr_ll as *const libc::sockaddr_ll as *const libc::sockaddr, Some(20)).expect("Failed to create linkaddr!")};

    // Create and bind the socket
    let socket = socket(AddressFamily::Packet, SockType::Datagram, SockFlag::empty(), SockProtocol::Udp).expect("Failed to create socket! Permission issue?");
    assert!(setsockopt(socket, sockopt::Broadcast, &true).is_ok());
    assert!(bind(socket, &linkaddr).is_ok());

    let client_mac = MacAddress::from_bytes(&mac.addr().unwrap()).unwrap();

    let mut client_addr: Option<Ipv4Addr> = None;
    let mut server_addr: Option<Ipv4Addr> = None;

    // DHCP transaction loop
    'dhcp_transaction: loop {
        let xid: u32 = rng.gen();

        let mut dhcp_state = DHCPTransactionState::Discover;

        'dhcp_message_loop: loop {
            match &dhcp_state {
                DHCPTransactionState::Discover => {
                    println!("Sent DHCPDiscover on {}", name);
                    let _ = sendto(socket, create_dhcp_packet(xid, client_mac, None, None, vec![
                        DHCPOption::DHCPMessageType(DHCPMessageType::DHCPDiscover),
                        DHCPOption::End
                    ]).as_bytes(), &linkaddr, MsgFlags::empty()).unwrap();
                    dhcp_state = DHCPTransactionState::WaitingAfterDiscover;
                }

                DHCPTransactionState::WaitingAfterDiscover => {
                    let mut packet: [u8; 574] = [0; 574];
                    let (bytes, addr) = recvfrom::<LinkAddr>(socket, &mut packet).unwrap();

                    println!("Received {} bytes on {}", bytes, name);

                    let udppacet_raw: dhcprs::udpbuilder::RawUDPPacket = unsafe {std::ptr::read(packet.as_ptr() as *const _)};
                    let udppacket: dhcprs::udpbuilder::UDPPacket = udppacet_raw.into();
                    
                    if udppacket.source_port != 67 {
                        // Not a BOOTP reply, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let bootppacket_raw: dhcprs::bootp::RawBOOTPPacket = unsafe {std::ptr::read(udppacket.get_data().as_ptr() as *const _)};
                    let bootppacket: dhcprs::bootp::BOOTPPacket = bootppacket_raw.into();

                    if bootppacket.xid != xid {
                        // Not a reply to us, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let options = dhcprs::dhcp::DHCPOption::from_bytes(&bootppacket.get_vend()[4..]);

                    if !options.iter().find(|&x| if let DHCPOption::DHCPMessageType(DHCPMessageType::DHCPOffer) = x {true} else {false}).is_some() {
                        // We got a response but it wasn't the expected message, try again with another transaction.
                        continue 'dhcp_transaction;
                    }

                    // Valid DHCPOffer received, process it.

                    client_addr = bootppacket.yiaddr;
                    server_addr = bootppacket.siaddr;

                    println!("Got client address: {}", client_addr.unwrap_or(Ipv4Addr::new(0,0,0,0)));
                    println!("Got server address: {}", server_addr.unwrap_or(Ipv4Addr::new(0,0,0,0)));

                    // Update the linkaddr to be the server's actual hardware address rather than the broadcast MAC.
                    let mut mac: [u8; 8] = [0; 8];
                    mac[..6].copy_from_slice(&addr.unwrap().addr().unwrap());
                    let new_sockaddr_ll = libc::sockaddr_ll {
                        sll_family: sockaddr_ll.sll_family,
                        sll_halen: sockaddr_ll.sll_halen,
                        sll_hatype: sockaddr_ll.sll_hatype,
                        sll_ifindex: sockaddr_ll.sll_ifindex,
                        sll_addr: mac,
                        sll_pkttype: sockaddr_ll.sll_pkttype,
                        sll_protocol: sockaddr_ll.sll_protocol
                    };

                    linkaddr = unsafe {LinkAddr::from_raw(&new_sockaddr_ll as *const libc::sockaddr_ll as *const libc::sockaddr, Some(20)).expect("Failed to update linkaddr to server's hardware address!")};

                    dhcp_state = DHCPTransactionState::Request;
                }

                DHCPTransactionState::Request => {
                    println!("Sent DHCPRequest on {}", name);
                    let _ = sendto(socket, create_dhcp_packet(xid, client_mac, client_addr, server_addr, vec![
                        DHCPOption::DHCPMessageType(DHCPMessageType::DHCPRequest),
                        DHCPOption::ParameterRequest(vec![1, 3, 6, 28]),
                        DHCPOption::End
                    ]).as_bytes(), &linkaddr, MsgFlags::empty());
                    dhcp_state = DHCPTransactionState::WaitAfterRequest;
                }

                DHCPTransactionState::WaitAfterRequest => {
                    let mut packet: [u8; 574] = [0; 574];
                    let (bytes, _) = recvfrom::<LinkAddr>(socket, &mut packet).unwrap();
                    println!("Received {} bytes on {}", bytes, name);

                    let udppacet_raw: dhcprs::udpbuilder::RawUDPPacket = unsafe {std::ptr::read(packet.as_ptr() as *const _)};
                    let udppacket: dhcprs::udpbuilder::UDPPacket = udppacet_raw.into();
                    
                    if udppacket.source_port != 67 {
                        // Not a BOOTP reply, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let bootppacket_raw: dhcprs::bootp::RawBOOTPPacket = unsafe {std::ptr::read(udppacket.get_data().as_ptr() as *const _)};
                    let bootppacket: dhcprs::bootp::BOOTPPacket = bootppacket_raw.into();

                    if bootppacket.xid != xid {
                        // Not a reply to us, get the next packet.
                        continue 'dhcp_message_loop;
                    };

                    let options = dhcprs::dhcp::DHCPOption::from_bytes(&bootppacket.get_vend()[4..]);

                    if !options.iter().find(|&x| if let DHCPOption::DHCPMessageType(DHCPMessageType::DHCPACK) = x {true} else {false}).is_some() {
                        // Wasn't an ACK, probably NAK, try again.
                        println!("Did not receive ACK from DHCPRequest, sleeping for 10secs before continuing.");
                        std::thread::sleep(core::time::Duration::new(10, 0));
                        continue 'dhcp_transaction;
                    }

                    let mut sleep_time = 0;

                    for option in options {
                        println!("Received: {:?}", option);

                        match option {
                            DHCPOption::IPAddressLeaseTime(n) => {
                                sleep_time = n
                            }

                            _ => ()
                        }
                    }

                    println!("Sleeping for {} for lease time to elapse.", sleep_time);
                    std::thread::sleep(core::time::Duration::new(sleep_time.into(), 0));
                }

                _ => ()
            }
        }        
    }
}

fn main() {
    let threads: Vec<std::thread::JoinHandle<()>> = nix::ifaddrs::getifaddrs().unwrap()
        .filter(|x| x.address.is_some())
        .filter(|x| x.address.unwrap().as_link_addr().is_some())
        .filter(|x| x.address.unwrap().as_link_addr().unwrap().hatype() == 1) // Only perform DHCP on Ethernet interfaces.
        .map(|x| (x.interface_name, *x.address.unwrap().as_link_addr().unwrap()))
        .map(|(name, mac)| std::thread::spawn(move || { dhcp_client(name, mac)} ))
        .collect();
    
    for thread in threads {
        let _ = thread.join();
    }
}