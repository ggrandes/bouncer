# Simple Bouncer (TCP)

SimpleBouncer is an open source (Apache License, Version 2.0) Java network proxy. Do not require any external lib.

---

## DOC

#### Schema about Forward port (you need ONE bouncer):
    
![Forward port](https://raw.github.com/ggrandes/bouncer/master/doc/forward_port.png "Forward port")

1. Machine-A (Client) init connection to Machine-B (Bouncer)
2. Machine-B init connection to Machine-C (Server)
3. Done: Machine-A is able to speak with Machine-C

###### Notes about security:

* Machine-A (Client) may be in Internal network.
* Machine-B (Bouncer) may be in DMZ.
* Machine-C (Server) may be in External network.

#### Schema about Reverse Tunneling (you need TWO bouncers):
    
![Reverse Tunneling](https://raw.github.com/ggrandes/bouncer/master/doc/reverse_tunneling.png "Reverse Tunneling")

###### Machine-A and Machine-B are Bouncers in Client-Server configuration.

1. Machine-A (MUX-OUT) init connection to Machine-B (MUX-IN)
2. Machine-D (Client) init connection to Machine-B
3. Machine-B request to Machine-A new SubChannel over MUX (Tunnel).
4. Machine-A open connection to Machine-C (Server).
5. Done: Machine-D is able to speak with Machine-C

###### Notes about security:

* Machine-B (MUX-IN) should be in DMZ.
* Machine-A (MUX-OUT) and Machine-C (Server) may be in internal network.

---

## Config (bouncer.conf)
Config file must be in class-path, general format is:

    # <left-addr> <left-port> <right-addr> <right-port> [options]

###### Options are comma separated:

* Options for outgoing connections
    * Loadbalancing/Failover (only one option can be used)
        * **LB=ORDER**: active failover-only in DNS order
        * **LB=RR**: active LoadBalancing in DNS order (round-robin)
        * **LB=RAND**: activate LoadBalancing in DNS random order
* Options for Simple Forward (rinetd)
    * **TUN=SSL**: activate SSL tunneling (origin is plain, destination is SSL)
* Options for Reverse Tunneling (MUX)
    * Select operation of MUX (only one option can be used)
        * **MUX=IN**: activate input-terminator multiplexor
        * **MUX=OUT**: activate output-initiator multiplexor
    * Options for encryption (optional -AES or SSL or NONE-):
        * **MUX=AES**: activate AES encryption in multiplexor (see AES=key)
            * **AES=key**: specify the key for AES (no white spaces)
        * **MUX=SSL**: activate SSL encryption in multiplexor (see SSL=xxx) `[TODO]`
            * **SSL=server.crt:server.key:client.crt**: specify files for SSL config (server/mux-in)
            * **SSL=client.crt:client.key:server.crt**: specify files for SSL config (client/mux-out)

###### Notes about security:

* If use SSL "files.crt/.key" must be in class-path like "bouncer.conf"
* If use SSL be careful about permissions of "files.key" (unix 600 may be good)
* Maybe if AES key is used, you need to protect the "bouncer.conf"

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
* JMX?
* Multiple remote-addr (not only multi DNS A-record)?
* Use Log4J
* Limit number of connections
* Limit absolute timeout/TTL of a connection
* Encryption MUX/Tunnel (SSL/TLS) (v1.5)

## DONEs

* Reload config (v1.1)
* Thread pool/control (v1.2)
* Reverse tunnels (like ssh -R) over MUX (multiplexed channels) (v1.2)
* FlowControl in MUX (v1.3)
* Custom timeout by binding (v1.4)
* Encryption MUX/Tunnel (AES+PreSharedSecret) (v1.4)
* Manage better the read timeouts (full-duplex) (v1.4)

## MISC
Current harcoded values:

* Buffer length for I/O: 4096bytes
* Output Buffers: 3
* TCP SO_SNDBUF/SO_RCVBUF: BufferLength * OutputBuffers 
* Connection timeout: 30seconds
* Read timeout: 5minutes
* Reload config check time interval: 10seconds
* Reset Initialization Vector (IV) for AES: { Iterations: 64K, Data: 16MB }


---
Inspired in [rinetd](http://www.boutell.com/rinetd/), [stunnel](https://www.stunnel.org/static/stunnel.html) and [openssh](http://www.openssh.org/), this bouncer is Java-minimalistic version.
