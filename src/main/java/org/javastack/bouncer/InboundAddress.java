package org.javastack.bouncer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;

/**
 * Representation of listen address
 */
class InboundAddress extends BouncerAddress {
	final String host;
	final int port;
	final Options opts;

	SSLFactory sslFactory = null;
	InetAddress[] addrs = null;

	InboundAddress(final ServerContext context, final String host, final int port, final Options opts) {
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
		return (host.equals("0.0.0.0") ? "*" : host) + ":" + port;
	}

	@Override
	void resolve() throws UnknownHostException {
		if (checkUpdateResolv()) {
			addrs = InetAddress.getAllByName(host);
			Log.info(this.getClass().getSimpleName() + " Resolved " + String.valueOf(this) + //
					" [" + fromArrAddress(addrs) + "]");
		} else {
			Log.info(this.getClass().getSimpleName() + " Resolve (cached) " + String.valueOf(this) + //
					" [" + fromArrAddress(addrs) + "]");
		}
	}

	InetSocketAddress[] getSocketAddress() {
		final InetSocketAddress[] socks = new InetSocketAddress[addrs.length];
		for (int i = 0; i < socks.length; i++) {
			socks[i] = new InetSocketAddress(addrs[i], port);
		}
		return socks;
	}

	ServerSocket listen() throws IOException {
		resolve();
		final ServerSocket listen;
		if (opts.isOption(Options.MUX_SSL | Options.TUN_ENDSSL)) {
			listen = sslFactory.createSSLServerSocket();
		} else {
			listen = new ServerSocket();
		}
		InetSocketAddress bind = new InetSocketAddress(addrs[0], port);
		context.registerSocket(listen);
		try {
			listen.setReuseAddress(true);
			listen.bind(bind);
		} catch (IOException e) {
			throw new IOException("Error binding socket: " + String.valueOf(bind), e);
		}
		return listen;
	}
}
