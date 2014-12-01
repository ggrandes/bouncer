# Bouncer (TCP)

Bouncer is an open source (Apache License, Version 2.0) Java network proxy. Do not require any external lib.

### Current Stable Version is [2.0.1](https://maven-release.s3.amazonaws.com/release/org/javastack/bouncer/2.0.1/bouncer-2.0.1-bin.zip)

---

## DOC

#### Schema about Forward / Port Redirector (you need ONE bouncer):
    
![Forward / Port Redirector](https://raw.github.com/ggrandes/bouncer/master/doc/forward_port.png "Forward / Port Redirector")

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

###### Filenames are a base-pattern, output files they will be: bouncer.xxx.YEAR-MONTH-DAY (bouncer.xxx.2014-12-01)

## Config (bouncer.conf)
Config file must be in class-path `${BOUNCER_HOME}/conf/`, general format is:

    # Forward / Port Redirector
    # <listen-addr> <listen-port> <remote-addr> <remote-port> [opts]
    
    # Reverse Tunneling (Bouncer 2.x syntax)
    # <mux-listen|tun-listen> <mux-name> <listen-addr> <listen-port> [opts]
    # <mux-connect|tun-connect> <mux-name> <remote-addr> <remote-port> [opts]

###### Options are comma separated:

* Options for outgoing connections
    * Loadbalancing/Failover (only one option can be used)
        * **LB=ORDER**: active failover-only in DNS order
        * **LB=RR**: active LoadBalancing in DNS order (round-robin)
        * **LB=RAND**: activate LoadBalancing in DNS random order
* Options for Forward / Port Redirector (rinetd)
    * **TUN=SSL**: activate SSL/TLS tunneling (origin is plain, destination is SSL/TLS, like stunnel)
* Options for Reverse Tunneling (MUX)
    * **TUN_ID=number**: When use Bouncer 2.x syntax you can create multiple Tunnels over same mux, use this ID for associate both ends.
    * Select operation of MUX (only one option can be used) in Bouncer 1.x config
        * **MUX=IN**: activate input-terminator multiplexor (Bouncer 2.x syntax: `mux-listen, tun-listen`)
        * **MUX=OUT**: activate output-initiator multiplexor (Bouncer 2.x syntax: `mux-connect, tun-connect`)
    * Options for encryption (optional -AES or SSL or NONE-):
        * **MUX=AES**: activate AES encryption in multiplexor (see AES=sharedsecret)
            * **AES=sharedsecret**: specify the password for AES (no white spaces, no comma sign, no equals sign)
            * **AESBITS=bits** (optional): specify the keysize for AES (default: `128`)
            * **AESALG=algorithm** (optional): specify the transformation for AES (default: `AES/CTR/NoPadding`)
        * **MUX=SSL**: activate SSL/TLS encryption in multiplexor (see SSL=xxx)
            * **SSL=server.crt:server.key:client.crt**: specify files for SSL/TLS config (server/mux-in)
            * **SSL=client.crt:client.key:server.crt**: specify files for SSL/TLS config (client/mux-out)

###### Notes about security:

* If use MUX=SSL
    * Keys/Certificates are pairs, must be configured in the two ends (MUX-IN & MUX-OUT)
    * files.crt are X.509 public certificates
    * files.key are RSA Keys in PKCS#8 format (no encrypted)
    * files.crt/.key must be in class-path `${BOUNCER_HOME}/keys/`
    * be careful about permissions of "files.key" (unix permission 600 may be good)
* If use MUX=AES, you need to protect the "bouncer.conf" from indiscrete eyes (unix permission 600 may be good)

##### Example config of Forward / Port Redirector (rinetd style):

    # <listen-addr> <listen-port> <remote-addr> <remote-port> [opts]
    0.0.0.0 1234 127.1.2.3 9876
    127.0.0.1 5678 encrypted.google.com 443 LB=RR,TUN=SSL
    
##### Example config of Reverse Tunnels (equivalent ssh -p 5555 192.168.2.1 -R 127.0.0.1:8080:192.168.1.1:80)

###### Machine-A (MUX-OUT):

    ### Bouncer 1.x legacy syntax ###
    # <remote-addr> <remote-port> <remote-tun-addr> <remote-tun-port> MUX-OUT
    192.168.1.1 80 192.168.2.1 5555 MUX=OUT
    
    ### Bouncer 2.x syntax, with support for multi-port ###
    # <mux-connect|tun-connect> <mux-name> <remote-addr> <remote-port> [opts]
    mux-connect mux1 127.0.0.1 5555
    tun-connect mux1 192.168.2.1 80 TUN_ID=1
    tun-connect mux1 192.168.2.1 22 TUN_ID=2

###### Machine-B (MUX-IN):
 
    ### Bouncer 1.x legacy syntax ###
    # <listen-tun-addr> <listen-tun-port> <listen-addr> <listen-port> MUX-IN
    192.168.2.1 5555 127.0.0.1 8080 MUX=IN

    ### Bouncer 2.x syntax, with support for multi-port ###
    # <mux-listen|tun-listen> <mux-name> <listen-addr> <listen-port> [opts]
    mux-listen mux1 192.168.2.1 5555
    tun-listen mux1 127.0.0.1 8080 TUN_ID=1
    tun-listen mux1 127.0.0.1 2222 TUN_ID=2
 
##### Same example config of Reverse tunnels but SSL/TLS

###### Machine-A (MUX-OUT):

    ### Bouncer 1.x legacy syntax ###
    # <remote-addr> <remote-port> <remote-tun-addr> <remote-tun-port> MUX-OUT
    192.168.1.1 80 192.168.2.1 5555 MUX=OUT,MUX=SSL,SSL=peerA.crt:peerA.key:peerB.crt
    
    ### Bouncer 2.x syntax, with support for multi-port ###
    # <mux-connect|tun-connect> <mux-name> <remote-addr> <remote-port> [opts]
    mux-connect mux1 127.0.0.1 5555 MUX=SSL,SSL=peerA.crt:peerA.key:peerB.crt
    tun-connect mux1 192.168.2.1 80 TUN_ID=1
    tun-connect mux1 192.168.2.1 22 TUN_ID=2

###### Machine-B (MUX-IN):
 
    ### Bouncer 1.x legacy syntax ###
    # <listen-tun-addr> <listen-tun-port> <listen-addr> <listen-port> MUX-IN
    192.168.2.1 5555 127.0.0.1 8080 MUX=IN,MUX=SSL,SSL=peerB.crt:peerB.key:peerA.crt

    ### Bouncer 2.x syntax, with support for multi-port ###
    # <mux-listen|tun-listen> <mux-name> <listen-addr> <listen-port> [opts]
    mux-listen mux1 192.168.2.1 5555 MUX=SSL,SSL=peerB.crt:peerB.key:peerA.crt
    tun-listen mux1 127.0.0.1 8080 TUN_ID=1
    tun-listen mux1 127.0.0.1 2222 TUN_ID=2

###### For Encryption Tunnels with AES (no SSL/TLS) you can use `MUX=AES,AES=sharedsecret` in both sides 

---

## Running (Linux)

    ./bin/bouncer.sh <start|stop|restart|reload|status>

## RSA Key / X.509 Certificate Generation for MUX-SSL (optional)

    ./bin/bouncer.sh keygen <bits> <days> <CommonName> <filename-without-extension>

## Enabling Strong Ciphers with BouncyCastleProvider

You can improve security, simply download **bcprov-jdk15on-`XXX`.jar** from [BouncyCastle](http://www.bouncycastle.org/latest_releases.html) and copy jar file to `${BOUNCER_HOME}/lib/` 

---

## TODOs

* NIO?
* JMX?
* Multiple remote-addr (not only multi DNS A-record)?
* Use Log4J
* Limit number of connections
* Limit absolute timeout/TTL of a connection
* Configurable retry-sleeps

## DONEs

* Reload config (v1.1)
* Thread pool/control (v1.2)
* Reverse tunnels (like ssh -R) over MUX (multiplexed channels) (v1.2)
* FlowControl in MUX (v1.3)
* Custom timeout by binding (v1.4)
* Encryption MUX/Tunnel (AES+PreSharedSecret) (v1.4)
* Encryption MUX/Tunnel (SSL/TLS) (v1.5)
* Key Generator for MUX-SSL/TLS (v1.5)
* Audit threads / connections (v1.5)
* Improved FlowControl in MUX (v1.5)
* Allow redir stdout/stderr to File, with auto daily-rotate (v1.5.1)
* Enable TLSv1.2 ciphers (v1.5.8)
* Added Elliptic Curve Diffie-Hellman Ephemeral Cipher Suites (v1.5.9)
* Zip Packaging (Maven Assembly) (v1.5.9)
* Allow AutoRegister JCE BouncyCastleProvider (v1.5.9)
* Configurable [CipherSuites](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider) for SSL/TLS (v1.6.0)
    * For AES-256 you need [JCE Unlimited Strength](http://www.oracle.com/technetwork/es/java/javase/downloads/jce-7-download-432124.html) 
* Allow different tunnels over same MUX(IN/OUT) (v2.0.1)
* BufferPool for reduce GC pressure (v2.0.1)

## MISC
Current harcoded values:

* Buffer Pool size: 4 (per thread)
* Buffer length for I/O: 4096bytes
* IO-Buffers: 8
* TCP `SO_SNDBUF`/`SO_RCVBUF`: BufferLength * IO-Buffers 
* Connection timeout: 30seconds
* Read timeout: 5minutes
* MUX Keep-Alive: 30seconds
* MUX-IN Error retry sleep: 0.5/1seconds
* MUX-OUT Error retry sleep: 5seconds
* Reload config check time interval: 10seconds
* For MUX-AES [Password-Based Key Derivation Function](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJCEProvider) for 4 keys (2 for Cipher, 2 for Mac) is PBKDF2WithHmacSHA1
* For MUX-AES default [Cipher](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJCEProvider) is AES/CTR/NoPadding (128 bits)
* For MUX-AES [Mac](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJCEProvider) for Authenticated encryption (Encrypt-then-MAC) is HmacSHA256
* For MUX-AES Randomized IV per-message is used. 
* For MUX-AES Rekey is done every 32768 messages (2^15).
* For MUX-AES Anti-replay window for messages (time): 5minutes
* For MUX-AES Anti-replay sequence for messages: 31bits
* For MUX-SSL supported Asymmetric Keys are RSA
* For MUX-SSL enabled [Protocols](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider) are:
    * `TLSv1.2`
    * `TLSv1.1`
    * `TLSv1`
    * `SSLv3` DISABLED [POODLE CVE-2014-3566](http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3566)
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
