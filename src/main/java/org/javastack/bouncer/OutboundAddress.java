package org.javastack.bouncer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Random;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Representation of remote destination
 */
class OutboundAddress extends BouncerAddress {
	final String host;
	final int port;
	final Options opts;

	SSLFactory sslFactory = null;
	InetAddress[] addrs = null;
	int roundrobin = 0;

	OutboundAddress(final ServerContext context, final String host, final int port, final Options opts) {
		super(context);
		this.host = host;
		this.port = port;
		this.opts = opts;
	}

	@Override
	void setSSLFactory(final SSLFactory sslFactory) {
		this.sslFactory = sslFactory;
	}

	@Override
	Options getOpts() {
		return opts;
	}

	@Override
	public String toString() {
		return host + ":" + port;
	}

	@Override
	void resolve() throws UnknownHostException {
		try {
			roundrobin = 0;
			addrs = InetAddress.getAllByName(host);
		} catch (UnknownHostException e) {
			Log.error(this.getClass().getSimpleName() + " Error resolving " + String.valueOf(this));
			throw e;
		}
		Log.info(this.getClass().getSimpleName() + " Resolved " + String.valueOf(this) + " ["
				+ fromArrAddress(addrs) + "]");
	}

	Socket connect() {
		if (addrs == null) {
			return null;
		}
		final int filterFlags = (Options.LB_ORDER | Options.LB_RR | Options.LB_RAND);
		Socket remote = null;
		switch (opts.getFlags(filterFlags)) {
			case Options.LB_ORDER:
				for (InetAddress addr : addrs) {
					remote = connect(addr);
					if (remote != null)
						break;
				}
				break;
			case Options.LB_RR:
				final int rrbegin = roundrobin;
				// Use local var to avoid synchronized block
				int rr = rrbegin;
				do {
					remote = connect(addrs[rr]);
					rr = ((rr + 1) % addrs.length);
					roundrobin = rr;
					if (remote != null)
						break;
				} while (roundrobin != rrbegin);
				break;
			case Options.LB_RAND:
				final Random r = new Random();
				remote = connect(addrs[(r.nextInt(Integer.MAX_VALUE) % addrs.length)]);
				break;
		}
		if (remote != null) {
			try {
				context.registerSocket(remote);
				final Integer pReadTimeout = opts.getInteger(Options.P_READ_TIMEOUT);
				if (pReadTimeout != null) {
					remote.setSoTimeout(pReadTimeout);
				}
			} catch (SocketException e) {
				Log.error(this.getClass().getSimpleName() + " Error setting parameters to socket: " + remote);
			}
		}
		return remote;
	}

	Socket connect(final InetAddress addr) {
		final boolean isSSL = opts.isOption(Options.TUN_SSL | Options.MUX_SSL);
		Socket sock = null;
		try {
			Log.info(this.getClass().getSimpleName() + " Connecting to " + addr + ":" + port
					+ (isSSL ? " (SSL)" : ""));
			if (opts.isOption(Options.MUX_SSL)) {
				sock = sslFactory.createSSLSocket();
			} else if (opts.isOption(Options.TUN_SSL)) {
				final SocketFactory factory = SSLSocketFactory.getDefault();
				sock = factory.createSocket();
				// Disable SSLv3 - POODLE [issue #5]
				if (sock instanceof SSLSocket) {
					final SSLSocket ss = ((SSLSocket) sock);
					ss.setEnabledProtocols(context.getCipherSuites().getProtocols());
					ss.setEnabledCipherSuites(context.getCipherSuites().getClientCipherSuites());
				}
			} else {
				sock = new Socket();
			}
			Integer pConnectTimeout = opts.getInteger(Options.P_CONNECT_TIMEOUT);
			if (pConnectTimeout == null) {
				pConnectTimeout = Constants.CONNECT_TIMEOUT;
			}
			sock.connect(new InetSocketAddress(addr, port), pConnectTimeout);
			if (sock instanceof SSLSocket) {
				((SSLSocket) sock).startHandshake();
			}
		} catch (IOException e) {
			Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port
					+ (isSSL ? " (SSL) " : " ") + e.toString());
			IOHelper.closeSilent(sock);
			sock = null;
		} catch (Exception e) {
			Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port
					+ (isSSL ? " (SSL)" : ""), e);
			IOHelper.closeSilent(sock);
			sock = null;
		}
		if ((sock != null) && sock.isConnected()) {
			Log.info(this.getClass().getSimpleName() + " Connected to " + addr + ":" + port
					+ (isSSL ? " (SSL) " + getSocketProtocol(sock) : ""));
			return sock;
		}
		return null;
	}

	String getSocketProtocol(final Socket sock) {
		if (sock instanceof SSLSocket) {
			final SSLSocket sslSock = (SSLSocket) sock;
			final SSLSession session = sslSock.getSession();
			return session.getProtocol() + ":" + session.getCipherSuite();
		}
		return "";
	}
}
