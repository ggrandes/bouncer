package org.javastack.bouncer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.javastack.bouncer.GenericPool.GenericPoolFactory;

public class MuxPacket implements Message {
	public static final GenericPoolFactory<MuxPacket> GENERIC_POOL_FACTORY = new GenericPoolFactory<MuxPacket>() {
		@Override
		public MuxPacket newInstance() {
			return new MuxPacket();
		}
	};

	private static final int payLoadLengthMAGIC = 0x69420000;
	private static final int MUX_SYN = 0x80 << 24;
	private static final int MUX_FIN = 0x40 << 24;
	private static final int MUX_ACK = 0x20 << 24;
	private static final int MUX_NOP = 0x10 << 24;

	private final byte[] header = new byte[8];
	private final byte[] payload = new byte[Constants.BUFFER_LEN];
	private int idChannel = 0; 		// 4 bytes (SYN/FIN/ACK/NOP flags in hi-nibble)
	private int payLoadLength = 0; 	// 4 bytes (magic in hi-nibble)

	private MuxPacket() {
		// Nothing
	}

	private MuxPacket(final int idChannel, final int payloadLength, final byte[] payload) {
		this.idChannel = idChannel & 0x00FFFFFF;
		this.payLoadLength = (payloadLength & 0xFFFF); // Limit to 64KB
		if ((payLoadLength > 0) && (payload != null)) {
			System.arraycopy(payload, 0, this.payload, 0, payloadLength);
		}
	}

	@Override
	public int getIdChannel() {
		return (idChannel & 0x00FFFFFF);
	}

	@Override
	public int getBufferLen() {
		return (payLoadLength & 0xFFFF);
	}

	@Override
	public byte[] getBuffer() {
		return payload;
	}

	/**
	 * Get IdEndPoint from Payload
	 * 
	 * @return
	 */
	public int getIdEndPoint() {
		if (payLoadLength < 4)
			return 0;
		final int idEndPoint = IOHelper.intFromByteArray(payload, 0);
		return (idEndPoint & 0x00FFFFFF);
	}

	/**
	 * Get Source Address from Payload
	 * 
	 * @return
	 */
	public InetAddress getSourceAddress() {
		// idEndPoint(4) + IPlength(1) + IPbytes(4/16)
		if (payLoadLength >= (4 + 1 + 4)) { // IPv4 (9) / IPv6 (20)
			try {
				int off = 4;
				final int len = payload[off++];
				return InetAddress.getByAddress(Arrays.copyOfRange(payload, off, off + len));
			} catch (UnknownHostException e) {
				Log.error(this.getClass().getSimpleName() + "::getSourceAddress " + e.toString(), e);
			}
		}
		return null;
	}

	/**
	 * SYN
	 * 
	 * @param idChannel
	 * @param idEndPoint
	 */
	public void syn(final int idChannel, final int idEndPoint, final InetAddress srcAddr2) {
		final byte[] srcAddr = srcAddr2.getAddress();
		// idEndPoint(4) + IPlength(1) + IPbytes(4/16)
		this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_SYN);
		this.payLoadLength = 4 + 1 + srcAddr.length; // IPv4 (4+1+4) / IPv6 (4+1+16)
		int offset = 0;
		IOHelper.intToByteArray(idEndPoint, payload, offset);  // 4
		offset += 4;
		payload[offset++] = (byte) (srcAddr.length & 0x7F);    // 1
		System.arraycopy(srcAddr, 0, payload, offset, srcAddr.length); // IPv4 (4) / IPv6 (16)
		offset += srcAddr.length;
	}

	/**
	 * SYN+ACK
	 * 
	 * @param idChannel
	 */
	public void syn(final int idChannel) {
		this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_SYN);
		this.payLoadLength = 0;
	}

	public void fin(final int idChannel) {
		this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_FIN);
		this.payLoadLength = 0;
	}

	public void ack(final int idChannel, final int size) {
		this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_ACK);
		this.payLoadLength = size;
	}

	public void nop(final int idChannel) {
		this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_NOP);
		this.payLoadLength = 0;
	}

	public boolean syn() {
		return ((idChannel & MUX_SYN) != 0);
	}

	public boolean fin() {
		return ((idChannel & MUX_FIN) != 0);
	}

	public boolean ack() {
		return ((idChannel & MUX_ACK) != 0);
	}

	public int ackSize() {
		if (((idChannel & MUX_ACK) != 0)) {
			return (payLoadLength & 0xFFFF);
		}
		return 0;
	}

	public boolean nop() {
		return ((idChannel & MUX_NOP) != 0);
	}

	@Override
	public void put(final int idChannel, final int payloadLength, final byte[] payload) {
		this.idChannel = (idChannel & 0x00FFFFFF);
		this.payLoadLength = (payloadLength & 0xFFFF); // Limit to 64KB
		if ((payLoadLength > 0) && (payload != null)) {
			System.arraycopy(payload, 0, this.payload, 0, this.payLoadLength);
		}
	}

	@Override
	public void clear() {
		idChannel = 0;
		payLoadLength = 0;
		Arrays.fill(header, (byte) 0);
		Arrays.fill(payload, (byte) 0);
	}

	@Override
	public void toWire(final OutputStream os) throws IOException {
		IOHelper.intToByteArray(idChannel, header, 0);
		IOHelper.intToByteArray((payLoadLength | (payLoadLengthMAGIC & 0xFFFF0000)), header, 4);
		// write header
		os.write(header);
		// write payload
		if (!ack() && ((payLoadLength & 0xFFFF) > 0))
			os.write(payload, 0, payLoadLength);
		os.flush();
	}

	@Override
	public void fromWire(final InputStream is) throws IOException {
		int len;
		// read header
		len = IOHelper.fullRead(is, header, header.length);
		if (len <= 0) {
			clear();
			throw new EOFException("EOF");
		}
		if (len != header.length) {
			final String err = "Invalid HEADER (expected: " + header.length + " readed: " + len + ")";
			clear();
			throw new IOException(err);
		}
		idChannel = IOHelper.intFromByteArray(header, 0);
		payLoadLength = IOHelper.intFromByteArray(header, 4);
		// Check payLoadLength
		if ((payLoadLength & 0xFFFF) > Constants.BUFFER_LEN) {
			final String err = "Invalid PayLoadLength (max expected: " + Constants.BUFFER_LEN + " readed: "
					+ (payLoadLength & 0xFFFF) + ")";
			clear();
			throw new IOException(err);
		}
		// Check MAGIC
		if ((payLoadLength & 0xFFFF0000) != (payLoadLengthMAGIC & 0xFFFF0000)) {
			final String err = "Invalid MAGIC (expected: " + (payLoadLengthMAGIC & 0xFFFF0000) + " readed: "
					+ (payLoadLength & 0xFFFF0000) + ")";
			clear();
			throw new IOException(err);
		}
		payLoadLength &= 0xFFFF; // Limit to 64KB
		// read payload
		if (!ack() && (payLoadLength > 0)) {
			len = IOHelper.fullRead(is, payload, payLoadLength);
			if (len != payLoadLength) {
				final String err = "Invalid PAYLOAD (expected: " + payLoadLength + " readed: " + len + ")";
				clear();
				throw new IOException(err);
			}
		}
	}

	@Override
	public String toString() {
		final StringBuffer sb = new StringBuffer();
		sb.append("MuxPacket[").append("id=").append(getIdChannel()).append(' ').append("len=")
				.append(getBufferLen()).append("]");
		if (syn()) {
			sb.append("[SYN]");
		} else if (fin()) {
			sb.append("[FIN]");
		} else if (ack()) {
			sb.append("[ACK]");
		} else if (nop()) {
			sb.append("[NOP]");
		} else {
			// if (!ack() && (payLoadLength > 0)) sb.append(new String(payload, 0, payLoadLength));
		}
		return sb.toString();
	}
}
