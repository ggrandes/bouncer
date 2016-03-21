package org.javastack.bouncer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import javax.net.ssl.SSLSocket;

public class IOHelper {
	private static final Charset UTF8 = Charset.forName("UTF-8");
	private static final String MD_ALG = "MD5";
	private static final int LENGTH_MAGIC = 0xA42C0000;

	public static final int fullRead(final InputStream is, final byte[] buf, final int len)
			throws IOException {
		int readed;
		if (len > 0) {
			int total = 0;
			while (total < len) {
				readed = is.read(buf, total, len - total);
				if (readed < 0)
					break;
				total += readed;
			}
			return total;
		}
		return 0;
	}

	public static final void intToByteArray(final int v, final byte[] buf, final int offset) {
		buf[offset + 0] = (byte) ((v >> 24) & 0xFF);
		buf[offset + 1] = (byte) ((v >> 16) & 0xFF);
		buf[offset + 2] = (byte) ((v >> 8) & 0xFF);
		buf[offset + 3] = (byte) ((v >> 0) & 0xFF);
	}

	public static final int intFromByteArray(final byte[] buf, final int offset) {
		int v = 0;
		v |= ((((int) buf[offset + 0]) & 0xFF) << 24);
		v |= ((((int) buf[offset + 1]) & 0xFF) << 16);
		v |= ((((int) buf[offset + 2]) & 0xFF) << 8);
		v |= ((((int) buf[offset + 3]) & 0xFF) << 0);
		return v;
	}

	public static final void longToByteArray(final long v, final byte[] buf, final int offset) {
		buf[offset + 0] = (byte) ((v >> 56) & 0xFF);
		buf[offset + 1] = (byte) ((v >> 48) & 0xFF);
		buf[offset + 2] = (byte) ((v >> 40) & 0xFF);
		buf[offset + 3] = (byte) ((v >> 32) & 0xFF);
		buf[offset + 4] = (byte) ((v >> 24) & 0xFF);
		buf[offset + 5] = (byte) ((v >> 16) & 0xFF);
		buf[offset + 6] = (byte) ((v >> 8) & 0xFF);
		buf[offset + 7] = (byte) ((v >> 0) & 0xFF);
	}

	public static final long longFromByteArray(final byte[] buf, final int offset) {
		long v = 0;
		v |= ((((long) buf[offset + 0]) & 0xFF) << 56);
		v |= ((((long) buf[offset + 1]) & 0xFF) << 48);
		v |= ((((long) buf[offset + 2]) & 0xFF) << 40);
		v |= ((((long) buf[offset + 3]) & 0xFF) << 32);
		v |= ((((long) buf[offset + 4]) & 0xFF) << 24);
		v |= ((((long) buf[offset + 5]) & 0xFF) << 16);
		v |= ((((long) buf[offset + 6]) & 0xFF) << 8);
		v |= ((((long) buf[offset + 7]) & 0xFF) << 0);
		return v;
	}

	public static int intIdFromString(final String in) {
		try {
			final MessageDigest md = MessageDigest.getInstance(MD_ALG);
			final byte[] b = md.digest(in.getBytes(UTF8));
			return (IOHelper.intFromByteArray(b, 0) ^ IOHelper.intFromByteArray(b, 4)
					^ IOHelper.intFromByteArray(b, 8) ^ IOHelper.intFromByteArray(b, 12))
					& Integer.MAX_VALUE;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static long longIdFromString(final String in) {
		try {
			final MessageDigest md = MessageDigest.getInstance(MD_ALG);
			final byte[] b = md.digest(in.getBytes(UTF8));
			return (IOHelper.longFromByteArray(b, 0) ^ IOHelper.longFromByteArray(b, 8)) & Long.MAX_VALUE;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static final void toWireWithHeader(final OutputStream os, final byte[] buf, final int len)
			throws IOException {
		final byte[] header = new byte[4]; // Integer
		if (len > 0xFFFF) { // Limit to 64KB
			throw new IOException("Packet length overflow (" + len + ")");
		}
		intToByteArray((len & 0xFFFF) | LENGTH_MAGIC, header, 0);
		os.write(header, 0, header.length);
		os.write(buf, 0, len);
		os.flush();
	}

	public static final byte[] fromWireWithHeader(final InputStream is) throws IOException {
		final byte[] header = new byte[4]; // Integer
		int readed = -1;
		readed = fullRead(is, header, header.length);
		if (readed <= 0) {
			throw new EOFException("EOF");
		}
		if (readed != header.length) {
			throw new IOException("Invalid HEADER");
		}
		int len = intFromByteArray(header, 0);
		if ((len & 0xFFFF0000) != LENGTH_MAGIC) {
			throw new IOException("Invalid MAGIC");
		}
		len &= 0xFFFF; // Limit to 64KB
		if (len > (Constants.BUFFER_LEN << 1)) {
			throw new IOException("Packet length overflow (" + len + ")");
		}
		final byte[] buf = new byte[len];
		readed = fullRead(is, buf, buf.length);
		if (readed != buf.length) {
			throw new IOException("Invalid BODY");
		}
		return buf;
	}

	public static void setupSocket(final ServerSocket sock) throws SocketException {
		sock.setReuseAddress(true);
		sock.setSoTimeout(Constants.ACCEPT_TIMEOUT);
		sock.setReceiveBufferSize(Math.max(sock.getReceiveBufferSize(), Constants.BUFFER_LEN
				* Constants.IO_BUFFERS));
	}

	public static void setupSocket(final Socket sock) throws SocketException {
		sock.setKeepAlive(true);
		sock.setReuseAddress(true);
		sock.setSoTimeout(Constants.READ_TIMEOUT);
		sock.setSendBufferSize(Math.max(sock.getSendBufferSize(), Constants.BUFFER_LEN * Constants.IO_BUFFERS));
		sock.setReceiveBufferSize(Math.max(sock.getReceiveBufferSize(), Constants.BUFFER_LEN
				* Constants.IO_BUFFERS));
	}

	public static void closeSilent(final Reader ir) {
		if (ir == null)
			return;
		try {
			ir.close();
		} catch (Exception ign) {
		}
	}

	public static void closeSilent(final InputStream is) {
		if (is == null)
			return;
		try {
			is.close();
		} catch (Exception ign) {
		}
	}

	public static void closeSilent(final OutputStream os) {
		if (os == null)
			return;
		try {
			os.flush();
		} catch (Exception ign) {
		}
		try {
			os.close();
		} catch (Exception ign) {
		}
	}

	public static void closeSilent(final Socket sock) {
		if (sock == null)
			return;
		if (!(sock instanceof SSLSocket)) {
			try {
				sock.shutdownInput();
			} catch (Exception ign) {
			}
			try {
				sock.shutdownOutput();
			} catch (Exception ign) {
			}
		}
		try {
			sock.close();
		} catch (Exception ign) {
		}
	}

	public static void closeSilent(final ServerSocket sock) {
		if (sock == null)
			return;
		try {
			sock.close();
		} catch (Exception ign) {
		}
	}

	public static String socketRemoteToString(final Socket socket) {
		return socket.getRemoteSocketAddress().toString();
	}
}
