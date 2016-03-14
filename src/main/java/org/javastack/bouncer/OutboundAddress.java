package org.javastack.bouncer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Representation of remote destination
 */
class OutboundAddress extends BouncerAddress {
	final String host;
	final int port;
	final Options opts;
	final StickyStore<InetAddress, InetAddress> stickies;

	SSLFactory sslFactory = null;
	InetAddress[] addrs = null;
	int roundrobin = 0;

	OutboundAddress(final ServerContext context, final String host, final int port, final Options opts) {
		super(context);
		this.host = host;
		this.port = port;
		this.opts = opts;
		this.stickies = StickyStore.getInstance(opts.getStickyConfig());
		//
		context.stickyRegister(stickies);
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
		if (checkUpdateResolv()) {
			final String[] hosts = host.split(",");
			final ArrayList<InetAddress> addresses = new ArrayList<InetAddress>(hosts.length);
			final ArrayList<String> unknownHosts = new ArrayList<String>(1);
			for (int i = 0; i < hosts.length; i++) {
				final String host = hosts[i];
				try {
					final InetAddress[] addrs = InetAddress.getAllByName(host);
					if (opts.isOption(Options.LB_ORDER) && (addrs.length > 1)) {
						Arrays.sort(addrs, InetAddressComparator.getInstance());
					}
					addresses.addAll(Arrays.asList(addrs));
				} catch (UnknownHostException e) {
					Log.error(this.getClass().getSimpleName() + " Error resolving " + host);
					unknownHosts.add(host);
				}
			}
			if (addresses.isEmpty() && !unknownHosts.isEmpty()) {
				throw new UnknownHostException(unknownHosts.toString());
			}
			this.addrs = addresses.toArray(new InetAddress[addresses.size()]);
			Log.info(this.getClass().getSimpleName() + " Resolved " + String.valueOf(this) + " ["
					+ fromArrAddress(addrs) + "]");
		} else {
			Log.info(this.getClass().getSimpleName() + " Resolve (cached) " + String.valueOf(this) + " ["
					+ fromArrAddress(addrs) + "]");
		}
	}

	Socket connect() throws UnknownHostException {
		return connectFrom(null);
	}

	Socket connectFrom(final InetAddress stickyAddr) throws UnknownHostException {
		resolve();
		if (addrs == null) {
			return null;
		}
		Socket remote = null;
		// First, try sticky, if any...
		if ((stickies != null) && (stickyAddr != null)) {
			final InetAddress dstAddr = stickies.get(stickyAddr);
			if (dstAddr != null) {
				for (final InetAddress addr : addrs) {
					if (addr.equals(dstAddr)) {
						Log.error(this.getClass().getSimpleName() + " Sticky id=" + stickyAddr + " result="
								+ addr);
						remote = connect0(addr);
						break;
					}
				}
			}
		}
		// Else, try another host...
		if (remote == null) {
			final int filterFlags = (Options.LB_ORDER | Options.LB_RR | Options.LB_RAND);
			int begin = 0;
			InetAddress[] addrs = this.addrs;
			if (addrs.length > 1) {
				switch (opts.getFlags(filterFlags)) {
					case Options.LB_ORDER:
						break;
					case Options.LB_RR:
						begin = roundrobin;
						break;
					case Options.LB_RAND:
						addrs = this.addrs.clone();
						Collections.shuffle(Arrays.asList(addrs));
						break;
				}
			}
			// Use local var to avoid synchronized block
			int rr = begin;
			do {
				final InetAddress addr = addrs[rr];
				remote = connect0(addr);
				rr = ((rr + 1) % addrs.length);
				roundrobin = rr;
				if (remote != null) {
					break;
				}
			} while (roundrobin != begin);
		}
		if (remote != null) {
			try {
				if ((stickies != null) && (stickyAddr != null)) {
					final InetAddress currentSticky = stickies.get(stickyAddr);
					if (!remote.getInetAddress().equals(currentSticky)) {
						final StickyConfig stickyCfg = opts.getStickyConfig();
						if (stickyCfg.isReplicated()) {
							context.stickyLocalUpdateNotify(stickyCfg.clusterId, stickyCfg.replicationId,
									stickyAddr, remote.getInetAddress());
						}
						stickies.put(stickyAddr, remote.getInetAddress());
					}
				}
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

	private Socket connect0(final InetAddress dstAddr) {
		final boolean isSSL = opts.isOption(Options.TUN_SSL | Options.MUX_SSL);
		Socket sock = null;
		try {
			Log.info(getClass().getSimpleName() + " Connecting to " + dstAddr + ":" + port
					+ (isSSL ? " (SSL)" : ""));
			if (opts.isOption(Options.MUX_SSL)) {
				sock = sslFactory.createSSLSocket();
			} else if (opts.isOption(Options.TUN_SSL) && (sslFactory != null)) {
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
			sock.connect(new InetSocketAddress(dstAddr, port), pConnectTimeout);
			if (sock instanceof SSLSocket) {
				((SSLSocket) sock).startHandshake();
			}
		} catch (IOException e) {
			Log.error(this.getClass().getSimpleName() + " Error connecting to " + dstAddr + ":" + port
					+ (isSSL ? " (SSL) " : " ") + e.toString());
			IOHelper.closeSilent(sock);
			sock = null;
		} catch (Exception e) {
			Log.error(this.getClass().getSimpleName() + " Error connecting to " + dstAddr + ":" + port
					+ (isSSL ? " (SSL)" : ""), e);
			IOHelper.closeSilent(sock);
			sock = null;
		}
		if ((sock != null) && sock.isConnected()) {
			Log.info(this.getClass().getSimpleName() + " Connected to " + dstAddr + ":" + port
					+ (isSSL ? " (SSL) " + SSLFactory.getSocketProtocol(sock) : ""));
			return sock;
		}
		context.getStatistics().incFailedConnections();
		return null;
	}
}
