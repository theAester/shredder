# Shredder
The ip packet shredder. This is an anticensorship attempt for bypassing SNI whitelisting on CloudFlare IPs.

When configured, shredder can run multiple applications for multiple outbound IP addresses to chop the tcp/ip packet corresponding to the TLS HELLO into many fragments.

Use this on your local(gateway) server and -on most ISPs- you can connect to your remote server even if your ip/domain has been blacklisted.

# Installation
Precompiled executable releases will be available soon

# Compiling from source
This is a cargo project, install the rust toolchain using rustup and then:
```shell
cargo build --release
```
to just build the application or
```shell
cargo install --path .
```
to install it locally.

# Configuration and usage
The command synopsis is
```shell
shredder COMMAND [OPTIONS]
COMMAND=run
OPTIONS:
  -c | --config <config file path>
  -h | --help
```
For now all you can do is run the shredder service. You need to provide a config file. Below is a [sample config file](https://github.com/theAester/shredder/blob/master/test.json)
```json
{
	"num_threads": 1,
	"address": "10.1.1.1",
	"subnet_mask": "255.255.255.0",
	"origin": "144.44.44.44",
	"applications": [
		{
			"name": "test0",
			"dest": "5.5.5.155"
		},
		{
			"name": "test1",
			"dest": "84.33.33.33",
			"ports": [80, 443]
		}
	]
}
```
- `num_threads` is the number of threads in the threadpool. This has to be less than or equal to the number of applications being run.
- `address` is the ip address for the `tun` interface that the application is going to create to intercept the packets
- `subnet_mask` the subnet mask to assign to the `tun` network
- `mtu` is optional, the maximum transmission unit of the `tun` intercept. The default is 1500
- `phony_range_start` is optional, specifies the beggingin the the range of addresses used as phonies for applications, if not specified, it's set to one after `address`
- `origin` is the IP address of the current device
- `applications` a list of applications

each application has the following fields:
- `name` is an arbitrary name, used to make logs more readable
- `dest` is the destination address of the intercepted packets for this application.**\***
- `ports` is optional, when specified shredder will only intercept outgoing packets whose destination port is specified in the list
- `phony` is the phony address associated to the application. When not set, shredder will apply a sequential address to each application automatically.**\*\***

---

**\*** Keep in mind that shredder is designed with proxy frameworks like V2Ray in mind, there is always a next hop address for an outbound connection, to which the data is transmitted.

**\*\*** Phony addresses are basically like a NAT hidden address, used to demultiplex the returning packets, even though it doesn't seem necessary at all at first, 
since shredder only shreds the outbound packets and sends them off and does nothing to the inbound data. However I ran into some issues with the conntrack when i tried
to let the data go back directly to the inital process, meaning that i was forced to stand completely in the middle of the connection (not just one way of it) and thus
the phony addresses.
