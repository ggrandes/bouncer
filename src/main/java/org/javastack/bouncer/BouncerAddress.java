package org.javastack.bouncer;

import java.net.InetAddress;
import java.net.UnknownHostException;

public abstract class BouncerAddress {
	final ServerContext context;

	BouncerAddress(final ServerContext context) {
		this.context = context;
	}

	abstract void setSSLFactory(final SSLFactory sslFactory);

	abstract Options getOpts();

	abstract void resolve() throws UnknownHostException;

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
