package org.javastack.bouncer;

/**
 * Fast int/long/byte[] to Hex String (left-zero-padding)
 */
public class SimpleHex {
	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

	public static String intAsHex(final int input) {
		final char[] sb = new char[8];
		final int len = (sb.length - 1);
		for (int i = 0; i <= len; i++) { // MSB
			sb[i] = HEX_CHARS[((int) (input >>> ((len - i) << 2))) & 0xF];
		}
		return new String(sb);
	}

	public static String longAsHex(final long input) {
		final char[] sb = new char[16];
		final int len = (sb.length - 1);
		for (int i = 0; i <= len; i++) { // MSB
			sb[i] = HEX_CHARS[((int) (input >>> ((len - i) << 2))) & 0xF];
		}
		return new String(sb);
	}

	public static String bytesAsHex(final byte[] input) {
		final int len = input.length;
		final char[] sb = new char[len << 1];
		for (int i = 0, j = 0; i < len; i++) { // MSB
			final int b = input[i];
			sb[j++] = HEX_CHARS[0xF & b >> 4];
			sb[j++] = HEX_CHARS[0xF & b];
		}
		return new String(sb);
	}

	/**
	 * Simple Test
	 */
	public static void main(String[] args) {
		System.out.println(intAsHex(0x1A3B5C7D));
		System.out.println(longAsHex(0x123456789ABCDEF0L));
		System.out.println(bytesAsHex(new byte[] {
				(byte) 0xAF, (byte) 0x91, (byte) 0x53, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
				(byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0, (byte) 0xFF, (byte) 0x17, (byte) 0xAA,
		}));
	}
}
