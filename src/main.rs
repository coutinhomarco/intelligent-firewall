use pcap::{Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

// Configuration constants
// Duration for which an IP will remain blocked after detection
const BLOCK_DURATION: Duration = Duration::from_secs(600); // 10 minutes
                                                           // Number of suspicious connections before triggering a block
const SCAN_THRESHOLD: u32 = 3;

// Struct to track scanning behavior for each IP address
#[derive(Clone)]
struct ScanInfo {
    count: u32,
    timestamp: SystemTime,
}

// Struct to manage blocked IPs and their unblock schedule
struct BlockTask {
    ip: IpAddr,
    unblock_time: SystemTime,
}

/// Checks if an IP is currently blocked in iptables
/// Returns true if the IP is found in the iptables rules
fn is_ip_blocked(ip: &IpAddr) -> bool {
    let output = Command::new("sudo")
        .args(&["iptables", "-L", "-n"])
        .output()
        .expect("Failed to execute iptables command");

    String::from_utf8_lossy(&output.stdout).contains(&ip.to_string())
}

/// Adds an IP address to iptables DROP rules
/// Prevents all incoming traffic from the specified IP
fn block_ip(ip: &IpAddr) {
    if is_ip_blocked(ip) {
        println!("IP {} is already blocked. Skipping...", ip);
        return;
    }
    println!("Blocking IP: {}", ip);
    Command::new("sudo")
        .args(&[
            "iptables",
            "-A",
            "INPUT",
            "-s",
            &ip.to_string(),
            "-j",
            "DROP",
        ])
        .status()
        .expect("Failed to block IP");
}

/// Removes an IP address from iptables DROP rules
/// Restores normal traffic flow from the specified IP
fn unblock_ip(ip: &IpAddr) {
    println!("Unblocking IP: {}", ip);
    Command::new("sudo")
        .args(&[
            "iptables",
            "-D",
            "INPUT",
            "-s",
            &ip.to_string(),
            "-j",
            "DROP",
        ])
        .status()
        .expect("Failed to unblock IP");
}

/// Processes each network packet to detect potential port scanning
/// Analyzes TCP packets for SYN flags without ACK (typical of port scans)
/// Updates scan tracking information and triggers blocks when threshold is exceeded
fn handle_packet(
    ethernet: &EthernetPacket,
    scan_tracker: &Arc<Mutex<HashMap<IpAddr, ScanInfo>>>,
    unblock_tasks: &Arc<Mutex<Vec<BlockTask>>>,
) {
    // Extract IPv4 packet from Ethernet frame
    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        // Extract TCP packet from IPv4 packet
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            // Check for SYN flag without ACK (potential port scan)
            if tcp.get_flags() & 0b010010 == 0b000010 {
                let src_ip = IpAddr::V4(ipv4.get_source());
                let port = tcp.get_destination();
                println!("Scan detected on port {} from {}", port, src_ip);

                let mut tracker = scan_tracker.lock().unwrap();
                let current_time = SystemTime::now();

                // Initialize or update scan tracking for this IP
                let scan_info = tracker.entry(src_ip).or_insert(ScanInfo {
                    count: 0,
                    timestamp: current_time,
                });

                // Reset counter if BLOCK_DURATION has passed
                if current_time.duration_since(scan_info.timestamp).unwrap() > BLOCK_DURATION {
                    scan_info.count = 0;
                    scan_info.timestamp = current_time;
                }

                scan_info.count += 1;

                // Block IP if it exceeds the threshold
                if scan_info.count > SCAN_THRESHOLD {
                    println!(
                        "IP {} exceeded scan limit, blocking for 10 minutes...",
                        src_ip
                    );
                    block_ip(&src_ip);
                    let unblock_time = current_time + BLOCK_DURATION;
                    println!("IP {} will be unblocked at {:?}", src_ip, unblock_time);
                    unblock_tasks.lock().unwrap().push(BlockTask {
                        ip: src_ip,
                        unblock_time,
                    });
                }
            }
        }
    }
}

/// Periodically checks and removes blocks that have expired
fn unblock_expired_ips(unblock_tasks: &Arc<Mutex<Vec<BlockTask>>>) {
    let mut tasks = unblock_tasks.lock().unwrap();
    let now = SystemTime::now();
    tasks.retain(|task| {
        if now >= task.unblock_time {
            unblock_ip(&task.ip);
            false
        } else {
            true
        }
    });
}

fn main() {
    // Verify root privileges (required for packet capture and iptables)
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("This program must be run with root privileges!");
        std::process::exit(1);
    }

    // Display all available network interfaces
    let devices = Device::list().unwrap();
    println!("Available devices:");
    for device in &devices {
        println!(
            "  {}: {}",
            device.name,
            device.desc.as_deref().unwrap_or("No description")
        );
    }

    // Select the first available network interface
    let device = devices.into_iter().next().expect("No devices found");
    println!("Using device: {}", device.name);

    // Initialize thread-safe data structures for tracking scans and blocks
    let scan_tracker = Arc::new(Mutex::new(HashMap::new()));
    let unblock_tasks = Arc::new(Mutex::new(Vec::new()));

    // Configure and open packet capture
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true) // Enable promiscuous mode
        .snaplen(65535) // Capture entire packet
        .open()
        .expect("Failed to open device");

    // Clone Arc references for the packet capture thread
    let tracker_clone = Arc::clone(&scan_tracker);
    let unblock_tasks_clone = Arc::clone(&unblock_tasks);

    // Spawn packet capture thread
    thread::spawn(move || {
        while let Ok(packet) = cap.next() {
            if let Some(ethernet) = EthernetPacket::new(packet.data) {
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    handle_packet(&ethernet, &tracker_clone, &unblock_tasks_clone);
                }
            }
        }
    });

    // Main loop: Check for expired blocks every 5 seconds
    loop {
        unblock_expired_ips(&unblock_tasks);
        thread::sleep(Duration::from_secs(5));
    }
}
