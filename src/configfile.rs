
extern crate config;

use std::net::{Ipv4Addr};

use config::{Config, File as CFile, FileFormat};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Application {
    pub name: String,
    pub dest: Ipv4Addr,
    pub phony: Option<Ipv4Addr>,
    pub origin: Option<Ipv4Addr>,
    pub ports: Option<Vec<u16>>,
    pub state: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    pub name: String,
    pub num_threads: usize,
    pub origin: Ipv4Addr,
    pub address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub mtu: u16,
    pub phony_range_start: Option<u8>,
    pub applications: Vec<Application>,
}

fn config_sanity_check(config: &mut ConfigFile) -> Result<(), String> {
    // num threads
    if config.num_threads > 128 {
        return Err("Seriosuly?".into());
    }


    if config.phony_range_start.is_none() {
        config.phony_range_start = Some(config.address.octets()[3] + 1);
    }

    let addr = config.address.octets();
    for pos in 0..config.applications.len() {
        if config.applications[pos].phony.is_none() {
            let phony_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], config.phony_range_start.unwrap() + pos as u8);
            config.applications[pos].phony = Some(phony_addr);
        }
        if config.applications[pos].origin.is_none() {
            config.applications[pos].origin = Some(config.origin.clone())
        }
    }

    if config.applications.len() < config.num_threads {
        eprintln!("Warning: you have configured shredder to use {} threads when there are only {} aplications, this renders {} threads completely obsolete",
                  config.num_threads,
                  config.applications.len(),
                  config.num_threads - config.applications.len());
    }

    // address
    Ok(())
}

pub fn read_config_file(config_file: String) -> Result<ConfigFile, String> {
    let mut config_builder = Config::builder()
        .add_source(CFile::new(&config_file, FileFormat::Json))
        .set_default("name", "shredder-tun").or_else(|e| {return Err(format!("default/name: {}", e.to_string()))}).unwrap()
        .set_default("mtu", 1500).or_else(|e| {return Err(format!("default/mtu: {}", e.to_string()))}).unwrap();

    let mut config: ConfigFile;

    match config_builder.build() {
        Ok(c) => {
            config = match c.try_deserialize() {
                Ok(s)=>s,
                Err(m) => { return Err(format!("Error while unpacking json config: {}", m.to_string())); }
            }
        },
        Err(m) => {
            return Err(format!("Error while reading config file: {}", m.to_string()));
        }
    }

    config_sanity_check(&mut config)?;

    Ok(config)
}
