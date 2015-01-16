package org.javastack.bouncer;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class ProxyProtocol {
	private static final ProxyProtocol singleton = new ProxyProtocol();

	public static ProxyProtocol getInstance() {
		return singleton;
	}

	/**
	 * Generate Haproxy PROXY protocol v1 header.
	 * 
	 * <pre>
	 * "PROXY &lt;TCP4|TCP6&gt; &lt;srcaddr&gt; &lt;dstaddr&gt; &lt;srcport&gt; &lt;dstport&gt;\r\n"
	 * "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"
	 * </pre>
	 * 
	 * <a href="http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt">PROXY protocol</a>
	 * 
	 * @param sock
	 * @return
	 */
	public String formatV1(final Socket sock) {
		final InetAddress srcAddr = sock.getInetAddress();
		final InetAddress dstAddr = sock.getLocalAddress();
		final String proto;
		if (srcAddr instanceof Inet4Address) {
			proto = "TCP4";
		} else if (srcAddr instanceof Inet6Address) {
			proto = "TCP6";
		} else {
			return "PROXY UNKNOWN\r\n";
		}
		final int srcPort = sock.getPort();
		final int dstPort = sock.getLocalPort();
		final StringBuilder sb = new StringBuilder(56);
		sb.append("PROXY") //
				.append(' ').append(proto) //
				.append(' ').append(srcAddr.getHostAddress()) //
				.append(' ').append(dstAddr.getHostAddress()) //
				.append(' ').append(srcPort) //
				.append(' ').append(dstPort) //
				.append('\r').append('\n');
		return sb.toString();
	}

	/**
	 * Generate HELO proxy header (Apache mod_myfixip -legacy header-).
	 * 
	 * <pre>
	 * &quot;HELO&lt;ipv4binary32BitAddress&gt;&quot;
	 * </pre>
	 * 
	 * <a href="https://github.com/ggrandes/apache22-modules/blob/master/mod_myfixip.c">mod_myfixip</a>
	 * 
	 * @param addr
	 * @return
	 */
	public byte[] formatHELO(final Inet4Address addr) {
		final byte[] b = addr.getAddress();
		return new byte[] {
				// HELO
				'H', 'E', 'L', 'O',
				// IPv4
				b[0], b[1], b[2], b[3]
		};
	}

	/**
	 * Simple Test
	 */
	public static void main(final String[] args) throws Throwable {
		final ServerSocket listen = new ServerSocket(9876);
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					final Socket client = new Socket("127.0.0.2", 9876);
					client.close();
				} catch (Exception e) {
					e.printStackTrace(System.out);
				}
			}
		}).start();
		final Socket remote = listen.accept();
		System.out.println(new ProxyProtocol().formatV1(remote));
		remote.close();
	}
}
