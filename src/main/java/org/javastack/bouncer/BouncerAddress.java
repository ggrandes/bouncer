package org.javastack.bouncer;

import java.net.InetAddress;
import java.net.UnknownHostException;

public abstract class BouncerAddress {
	final ServerContext context;
	long lastResolv = 0;

	BouncerAddress(final ServerContext context) {
		this.context = context;
	}

	abstract void setSSLFactory(final SSLFactory sslFactory);

	abstract Options getOpts();

	abstract void resolve() throws UnknownHostException;

	boolean checkUpdateResolv() {
		final long now = System.currentTimeMillis();
		if (lastResolv + Constants.DNS_CACHE_TIME < now) {
			lastResolv = now;
			return true;
		}
		return false;
	}

	static String fromArrAddress(final InetAddress[] addrs) {
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < addrs.length; i++) {
			final InetAddress addr = addrs[i];
			if (i > 0)
				sb.append(",");
			sb.append(addr.getHostAddress());
		}
		return sb.toString();
	}
}
