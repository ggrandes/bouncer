package org.javastack.bouncer;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class IpAddress {
	public static final byte[] getBytesByCIDR(final int bits, final boolean ipv6) {
		final int totalBits = (ipv6 ? 128 : 32);
		if (bits < 0 || bits > totalBits)
			throw new IllegalArgumentException("Illegal CIDR prefix");
		final byte[] bytes = new byte[totalBits >> 3];
		for (int offset = 0; offset < bits; offset++) {
			bytes[offset >> 3] |= (1 << (7 - (offset & 7)));
		}
		return bytes;
	}

	public static final InetAddress getAddressByBytes(final byte[] bytes) {
		try {
			return InetAddress.getByAddress(bytes);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	public static final InetAddress getAddressByCIDR(final int bits, final boolean ipv6) {
		return getAddressByBytes(getBytesByCIDR(bits, ipv6));
	}

	public static final void applyMask(final byte[] srcAddress, final byte[] mask) {
		for (int i = 0; i < srcAddress.length; i++) {
			srcAddress[i] &= mask[i];
		}
	}

	public static final InetAddress getAddressMasked(final InetAddress addr, final int bits) {
		final byte[] bytes = addr.getAddress();
		final byte[] mask = getBytesByCIDR(bits, bytes.length == 16);
		applyMask(bytes, mask);
		return getAddressByBytes(bytes);
	}
}
