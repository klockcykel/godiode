# godiode
PoC for reliable file transfers over a data diode. Presented at SEC-T 2021.

## Build instructions
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

## Running
### Receiver
Replace eth0 with nic connected to diode, received data will end up in ./in
```
mkdir -p in/ && ./bin/godiode --verbose --interface eth0 receive in/
```
Or using docker...
```
docker-compose run --rm godiode --verbose --interface eth0 receive /in
```

### Sender
Place folder structure to transfer under ./out and replace IP with whatever you assigned the nic connected to the diode.
```
mkdir -p out && ./bin/godiode --verbose --baddr 10.72.0.1:1234 send out/
```
Or using docker...
```
docker-compose run --rm godiode --verbose --baddr 10.72.0.1:1234 send /out
```

## Optimize for speed
### Use jumbo frames
For optimal performance it's recommended to use jumbo frames. Enable on your interfaces (both sender and receiver):
```
# replace eth0 with nic connected to diode
sudo ip link set mtu 9000 eth0
```
Instruct sender/receiver to use larger packets with _maxpacket_-flag to godiode
```
godiode --packetsize 8972 send /out
```

### Increase send/receive buffers
Receiver will try and allocate a receive buffer of 300xPacketsize, so with jumbo frames the net.core.rm_max should be set to at least 2700000 in either /etc/sysctl.conf or manually with
```
sudo sysctl net.core.rmem_max=2700000
```




