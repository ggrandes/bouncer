package org.javastack.bouncer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import org.javastack.bouncer.GenericPool.GenericPoolFactory;

public class RawPacket implements Message {
	public static final GenericPoolFactory<RawPacket> GENERIC_POOL_FACTORY = new GenericPoolFactory<RawPacket>() {
		@Override
		public RawPacket newInstance() {
			return new RawPacket();
		}
	};

	private final byte[] payload = new byte[Constants.BUFFER_LEN];
	private int idChannel;
	private int payLoadLength = 0;

	private RawPacket() {
		// Nothing
	}

	public void setIdChannel(final int idChannel) {
		this.idChannel = (idChannel & 0x00FFFFFF);
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
		payLoadLength = 0;
		Arrays.fill(payload, (byte) 0);
	}

	@Override
	public void toWire(final OutputStream os) throws IOException {
		os.write(payload, 0, payLoadLength);
		os.flush();
	}

	@Override
	public void fromWire(final InputStream is) throws IOException {
		try {
			payLoadLength = is.read(payload, 0, payload.length);
			if (payLoadLength < 0) {
				throw new EOFException("EOF");
			}
		} catch (IOException e) {
			clear();
			throw e;
		}
	}

	@Override
	public String toString() {
		final StringBuffer sb = new StringBuffer();
		sb.append("RawPacket[").append("id=").append(getIdChannel()).append(" ").append("len=")
				.append(getBufferLen()).append("]");
		// if (payLoadLength > 0) sb.append(new String(payload, 0, payLoadLength));
		return sb.toString();
	}
}
