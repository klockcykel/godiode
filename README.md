![presentation title page](https://github.com/klockcykel/godiode/raw/main/titlepage.png)

# DIY Data Diode
Simple DIY gigabit data diode (hardware and software). Presented at SEC-T 2021.

## Hardware
By doing a simple hardware mod to a fiber converter you can build your own data diode for around €60. See the /hardware folder for [modding instructions](https://github.com/klockcykel/godiode/blob/main/hardware/README.md#diy-optical-gigabit-data-diode)

## Software
PoC golang code for reliable file transfers over a data diode. With recommended OS optimizations it should reach 750+ Mbit/s file transfers.

### Build instructions
With local golang available
```
# apt install golang
cd src && go build -o ../bin/godiode . ; cd .. 
```

With golang in docker
```
# apt install golang
docker-compose run --rm build
```

The built binary will end up in _./bin/godiode_

### Running
### Usage
```
Usage: godiode <options> send|receive <dir>
  -baddr string
    	bind address
  -bw int
    	throttle bw to X Mbit/s (sender only)
  -conf string
    	JSON config file (default "/etc/godiode.json")
  -delete
    	delete files (receiver only)
  -interface string
    	interface to bind to
  -maddr string
    	multicast address (default "239.252.28.12:5432")
  -packetsize int
    	maximum UDP payload size (default 1472)
  -secret string
    	HMAC secret
  -tmpdir string
    	tmp dir to use (receiver only)
  -verbose
    	verbose output
```
#### Receiver
Replace eth0 with nic connected to diode, received data will end up in ./in
```
mkdir -p in/ && ./bin/godiode --verbose --interface eth0 receive in/
```
Or using docker...
```
docker-compose run --rm godiode --verbose --interface eth0 receive /in
```

#### Sender
Place folder structure to transfer under ./out and replace IP with whatever you assigned the nic connected to the diode.
```
mkdir -p out && ./bin/godiode --verbose --baddr 10.72.0.1:1234 send out/
```
Or using docker...
```
docker-compose run --rm godiode --verbose --baddr 10.72.0.1:1234 send /out
```

### Optimize for speed
#### Use jumbo frames
For optimal performance it's recommended to use jumbo frames. Enable on your interfaces (both sender and receiver):
```
# replace eth0 with nic connected to diode
sudo ip link set mtu 9000 eth0
```
Instruct sender/receiver to use larger packets with _maxpacket_-flag to godiode
```
godiode --packetsize 8972 send /out
```

#### Increase send/receive buffers
Receiver will try and allocate a receive buffer of 300xPacketsize, so with jumbo frames the net.core.rm_max should be set to at least 2700000 in either /etc/sysctl.conf or manually with
```
sudo sysctl net.core.rmem_max=2700000
```




