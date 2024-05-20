
extern crate getopts;
extern crate config;
extern crate tun;
extern crate pnet;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::Command;
use config::{Config, File};
use getopts::Options;
use tun::Device;
use pnet::packet::{Packet, ipv4::Ipv4Packet};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::util::MacAddr;

#[derive(Debug, Deserialize)]
struct Application {
    from: String,
    to: String,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    num_threads: u32,
    subnet: String,
    applications: Vec<Application>,
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn read_config_file(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn setup_interface(config: &ConfigFile, device: &mut Device) -> io::Result<()> {
    let mut commands: Vec<String> = Vec::new();

    // Assign subnet to the tun interface
    commands.push(format!("ip addr add {} dev {}", config.subnet, device.name()));

    // Execute commands
    for cmd in commands {
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(io::ErrorKind::Other, format!("Command failed: {}", stderr)));
        }
    }

    // Set the interface up
    Command::new("ip")
        .arg("link")
        .arg("set")
        .arg("dev")
        .arg(device.name())
        .arg("up")
        .output()?;

    Ok(())
}

fn run_command(config_path: &str) -> io::Result<()> {
    let mut settings = Config::default();

    // Read the config file
    settings.merge(File::with_name(config_path))?;

    // Deserialize the config file into a struct
    let config: ConfigFile = settings.try_into()?;

    // Create tun interface
    let mut dev = Device::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Setup interface
    setup_interface(&config, &mut dev)?;

    // Buffer to read packets into
    let mut packet_buffer = [0u8; 1504]; // Maximum size of an Ethernet frame

    loop {
        // Read a packet from the tun interface
        let bytes_read = dev.recv(&mut packet_buffer)?;

        // Parse the packet
        let packet = match Ipv4Packet::new(&packet_buffer[..bytes_read]) {
            Some(packet) => packet,
            None => {
                eprintln!("Error parsing IPv4 packet");
                continue;
            }
        };

        // Check if the total size of the packet matches the number of bytes read
        if packet_buffer.len() != bytes_read {
            eprintln!("Error: Packet size mismatch");
            continue;
        }

        // Find the matching application for the destination address
        let mut matched_app: Option<&Application> = None;
        for app in &config.applications {
            if app.from == packet.get_destination().to_string() {
                matched_app = Some(app);
                break;
            }
        }

        // If no matching application is found, drop the packet
        let matched_app = match matched_app {
            Some(app) => app,
            None => {
                eprintln!("Error: No matching application found for destination address {}", packet.get_destination());
                continue;
            }
        };

        // Modify the packet destination address to the "to" address of the matched application
        let to_address = matched_app.to.parse().unwrap(); // Assuming to is always a valid IPv4 address
        packet.set_destination(to_address);

        // Get the next protocol
        let next_protocol = packet.get_next_level_protocol();

        // If the next protocol is TCP or UDP, we'll implement TLS processing later
        // For now, just send the modified packet back to the tun interface
        match next_protocol {
            IpNextHeaderProtocol::Tcp | IpNextHeaderProtocol::Udp => {
                dev.send(&packet_buffer[..bytes_read])?;
            },
            _ => {
                // For other protocols, just send the modified packet back to the tun interface
                dev.send(&packet_buffer[..bytes_read])?;
            }
        }
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("c", "config", "set config file path", "PATH");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let config_path = match matches.opt_str("c") {
        Some(path) => path,
        None => {
            eprintln!("Error: Config file path is required");
            print_usage(&program, opts);
            return;
        }
    };

    match run_command(&config_path) {
        Ok(_) => (),
        Err(e) => eprintln!("Error: {}", e),
    }
}

