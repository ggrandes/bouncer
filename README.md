# Simple Bouncer (TCP)

SimpleBouncer is an open source (Apache License, Version 2.0) Java network proxy. Do not require any external lib.

### Current Stable Version is [1.5.5](https://maven-release.s3.amazonaws.com/release/net/bouncer/bouncer/1.5.5/bouncer-1.5.5.jar)

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

## Config (params)

    # To redir stdout/stderr to (auto-daily-rotated) files you can use:
    -Dlog.stdOutFile=/var/log/bouncer.out -Dlog.stdErrFile=/var/log/bouncer.err
    # To log to stdout too:
    -Dlog.stdToo=true 

###### Filenames are a base-pattern, output files they will be: bouncer.xxx.YEAR-MONTH-DAY (bouncer.xxx.2012-12-31)

## Config (bouncer.properties)
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
            * **AES=key**: specify the key for AES (no white spaces, no comma sign, no equals sign)
        * **MUX=SSL**: activate SSL encryption in multiplexor (see SSL=xxx)
            * **SSL=server.crt:server.key:client.crt**: specify files for SSL config (server/mux-in)
            * **SSL=client.crt:client.key:server.crt**: specify files for SSL config (client/mux-out)

###### Notes about security:

* If use MUX=SSL
    * Keys/Certificates are pairs, must be configured in the two ends (MUX-IN & MUX-OUT)
    * files.crt are X.509 public certificates
    * files.key are RSA Keys in PKCS#8 format (no encrypted)
    * files.crt/.key must be in class-path like "bouncer.properties"
    * be careful about permissions of "files.key" (unix permission 600 may be good)
* If use MUX=AES, you need to protect the "bouncer.properties" from indiscrete eyes (unix permission 600 may be good)

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
 
##### Same example config of Reverse tunnels but SSL

###### Machine-A (MUX-OUT):

    # <remote-addr> <remote-port> <remote-tun-addr> <remote-tun-port> MUX-OUT
    192.168.1.1 80 192.168.2.1 5555 MUX=OUT,MUX=SSL,SSL=peerA.crt:peerA.key:peerB.crt

###### Machine-B (MUX-IN):
 
    # <listen-tun-addr> <listen-tun-port> <listen-addr> <listen-port> MUX-IN
    192.168.2.1 5555 127.0.0.1 8080 MUX=IN,MUX=SSL,SSL=peerB.crt:peerB.key:peerA.crt
 
###### For Encryption Tunnels with AES (no SSL) you can use `MUX=AES,AES=password` in both sides 

---

## RSA Key / X.509 Certificate Generation for MUX-SSL (optional)

    java -cp .:bouncer-x.y.z.jar net.bouncer.KeyGenerator <bits> <days> <CommonName> <filename-without-extension>

## Running (Linux)

    ./linux/bouncer.sh <start|stop|restart|reload|status>

---

## TODOs

* NIO?
* JMX?
* Multiple remote-addr (not only multi DNS A-record)?
* Use Log4J
* Limit number of connections
* Limit absolute timeout/TTL of a connection
* Configurable retry-sleeps
* Allow different tunnels over same MUX(IN/OUT)

## DONEs

* Reload config (v1.1)
* Thread pool/control (v1.2)
* Reverse tunnels (like ssh -R) over MUX (multiplexed channels) (v1.2)
* FlowControl in MUX (v1.3)
* Custom timeout by binding (v1.4)
* Encryption MUX/Tunnel (AES+PreSharedSecret) (v1.4)
* Manage better the read timeouts (full-duplex) (v1.4)
* Encryption MUX/Tunnel (SSL/TLS) (v1.5)
* Key Generator for MUX-SSL/TLS (v1.5)
* Audit threads / connections (v1.5)
* Improved FlowControl in MUX (v1.5)
* Allow redir stdout/stderr to File, with auto daily-rotate (v1.5.1)

## MISC
Current harcoded values:

* Buffer length for I/O: 4096bytes
* IO-Buffers: 8
* TCP `SO_SNDBUF`/`SO_RCVBUF`: BufferLength * IO-Buffers 
* Connection timeout: 30seconds
* Read timeout: 5minutes
* MUX Read timeout / keep-alive: 30seconds
* MUX-IN Error retry sleep: 0.5/1seconds
* MUX-OUT Error retry sleep: 5seconds
* Reload config check time interval: 10seconds
* Reset Initialization Vector (IV) for MUX-AES: { Iterations: 64K, Data: 16MB }
* For MUX-AES encryption/[transformation](http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJCEProvider) are AES/CBC/PKCS5Padding
* For MUX-SSL supported Asymmetric Keys are RSA
* For MUX-SSL enabled [Protocols](http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider) are:
    * `TLSv1`
    * `SSLv3`
* For MUX-SSL enabled [CipherSuites](http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider) are:
    * `TLS_RSA_WITH_AES_256_CBC_SHA`
        * For AES-256 you need [JCE Unlimited Strength](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html) 
    * `TLS_RSA_WITH_AES_128_CBC_SHA`
    * `SSL_RSA_WITH_3DES_EDE_CBC_SHA`
    * `SSL_RSA_WITH_RC4_128_SHA`
* Shutdown/Reload timeout: 30seconds

---

## Throughput Benchmark

<table>
  <tr>
    <th></th>
    <th>Direct</th>
    <th>Forward</th>
    <th>MUX</th>
    <th>MUX-AES</th>
    <th>MUX-SSL</th>
  </tr>
  <tr>
    <th>Mbytes</th>
    <td>39.9</td>
    <td>31.2</td>
    <td>20.8</td>
    <td>7.0</td>
    <td>7.4</td>
  </tr>
  <tr>
    <th>Mbits</th>
    <td>319</td>
    <td>249</td>
    <td>166</td>
    <td>56</td>
    <td>59</td>
  </tr>
</table>

###### All test run on localhost. Values are not accurate, but orientative. Higher better.


---
Inspired in [rinetd](http://www.boutell.com/rinetd/), [stunnel](https://www.stunnel.org/static/stunnel.html) and [openssh](http://www.openssh.org/), this bouncer is Java-minimalistic version.
