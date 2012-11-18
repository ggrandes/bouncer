# Simple Bouncer (TCP)

SimpleBouncer is an open source (Apache License, Version 2.0) Java application. Do not require any external lib.

---

## Config (bouncer.conf)
Config file must be in class-path, general format is:

    # <left-addr> <left-port> <right-addr> <right-port> [options]

* Options are comma separated:
    * Loadbalancing/Failover (only one option can be used)
        * **LB=ORDER**: active failover-only in DNS order
        * **LB=RR**: active LoadBalancing in DNS order (round-robin)
        * **LB=RAND**: activate LoadBalancing in DNS random order
    * **TUN=SSL**: activate SSL tunneling (origin is plain, destination is SSL)
    * **MUX=IN**: activate input-terminator multiplexor (for reverse tunnels)
    * **MUX=OUT**: activate output-initiator multiplexor (for reverse tunnels)

##### Example config of simple forward:

    # <listen-addr> <listen-port> <remote-addr> <remote-port> [options]
    0.0.0.0 1234 127.1.2.3 9876
    127.0.0.1 5678 encrypted.google.com 443 LB=RR,TUN=SSL
    
##### Example config of Reverse tunnels (equivalent ssh -p 5555 192.168.2.1 -R 127.0.0.1:8080:192.168.1.1:80)

###### Machine-A (MUX-OUT):

    # <remote-addr> <remote-port> <remote-tun-addr> <remote-tun-port> MUX-OUT
    192.168.1.1 80 192.168.2.1 5555 MUX=OUT

###### Machine-B (MUX-IN):
 
    # <listen-tun-addr> <listen-tun-port> <listen-addr> <listen-port> MUX-IN
    192.168.2.1 5555 127.0.0.1 8080 MUX=IN
 
## DOC

#### Schema about Reverse Tunneling:
    
![Reverse Tunneling](https://raw.github.com/ggrandes/bouncer/master/doc/reverse_tunneling.png "Reverse Tunneling")

1. Machine-A (MUX-OUT) init connection to Machine-B (MUX-IN)
2. Machine-D (Client) init connection to Machine-B
3. Machine-B request to Machine-A new SubChannel over MUX (Tunnel).
4. Machine-A open connection to Machine-C (Server).
5. Done: Machine-D is able to speak with Machine-C

###### Notes about security:

* Machine-B (MUX-IN) should be in DMZ.
* Machine-A (MUX-OUT) and Machine-C (Server) may be in internal network.

#### Schema about Forward port:
    
![Forward port](https://raw.github.com/ggrandes/bouncer/master/doc/forward_port.png "Forward port")

1. Machine-A (Client) init connection to Machine-B (Bouncer)
2. Machine-B init connection to Machine-C (Server)
3. Done: Machine-A is able to speak with Machine-C

###### Notes about security:

* Machine-A (Client) may be in Internal network.
* Machine-B (Bouncer) may be in DMZ.
* Machine-C (Server) may be in External network.

---

## Compile (handmade)

    mkdir classes
    javac -d classes/ src/net/bouncer/SimpleBouncer.java
    jar cvf bouncer.jar -C classes/ .

## Running

    java -cp .:bouncer.jar net.bouncer.SimpleBouncer

---

## TODOs

* NIO?
* Custom timeout by binding
* Multiple remote-addr (not only multi DNS A-record)?
* Use Log4J

## DONEs

* Reload config (v1.1)
* Thread pool/control (v1.2)
* Reverse tunnels (like ssh -R) (v1.2)

## MISC
Current harcoded values:

* Buffer length for I/O: 4096bytes (2 buffers for connection)
* Connection timeout: 30seconds
* Read timeout: 5minutes
* Reload config check time interval: 10seconds


---
Inspired in [rinetd](http://www.boutell.com/rinetd/), [stunnel](https://www.stunnel.org/static/stunnel.html) and [openssh](http://www.openssh.org/), this bouncer is Java-minimalistic version.
