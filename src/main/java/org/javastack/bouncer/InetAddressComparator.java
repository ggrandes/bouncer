package org.javastack.bouncer;

import java.net.InetAddress;
import java.util.Comparator;

public class InetAddressComparator implements Comparator<InetAddress> {
	private static final InetAddressComparator singleton = new InetAddressComparator();

	public static InetAddressComparator getInstance() {
		return singleton;
	}

	@Override
	public int compare(final InetAddress o1, final InetAddress o2) {
		final byte[] a1 = o1.getAddress();
		final byte[] a2 = o2.getAddress();
		final int len = Math.min(a1.length, a2.length);
		for (int i = 0; i < len; i++) {
			int b1 = (int) a1[i] & 0xFF;
			int b2 = (int) a2[i] & 0xFF;
			if (b1 == b2) {
				continue;
			} else if (b1 < b2) {
				return -1;
			} else {
				return 1;
			}
		}
		if (a1.length < a2.length) {
			return -1;
		}
		if (a1.length > a2.length) {
			return 1;
		}
		return 0;
	}
}
