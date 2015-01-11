package org.javastack.bouncer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.util.Arrays;

import org.javastack.bouncer.GenericPool.GenericPoolFactory;

public class ClusterPacket {
	public static final GenericPoolFactory<ClusterPacket> GENERIC_POOL_FACTORY = new GenericPoolFactory<ClusterPacket>() {
		@Override
		public ClusterPacket newInstance() {
			return new ClusterPacket();
		}
	};
	public static final int CLUSTER_MSG_TYPE_NOP = 0x01; 			// No Operation
	public static final int CLUSTER_MSG_TYPE_HELLO = 0x02; 			// Hello
	public static final int CLUSTER_MSG_TYPE_STICKY_UPDATE = 0x03; 	// Sticky Update
	public static final int CLUSTER_MSG_TYPE_SYNC_BEGIN = 0x04; 	// Sync Begin
	public static final int CLUSTER_MSG_TYPE_SYNC_END = 0x05; 		// Sync End

	// magic (1) | msg-type (1) | length (2) | data-variable-length
	private static final int MAGIC = 0x42;

	private final byte[] payload = new byte[64];
	private int payLoadLength = 0; 	// 2 bytes (lo-nibble)

	private int msgType = 0;
	private long clusterId = 0;
	private long replicationId = 0;
	private InetAddress stickyAddr = null;
	private InetAddress mapAddr = null;

	private ClusterPacket() {
		// Nothing
	}

	public void clear() {
		msgType = 0;
		payLoadLength = 0;
		clusterId = 0;
		replicationId = 0;
		stickyAddr = null;
		mapAddr = null;
	}

	public void hello() {
		this.msgType = CLUSTER_MSG_TYPE_HELLO;
		this.payLoadLength = 0;
	}

	public void nop() {
		this.msgType = CLUSTER_MSG_TYPE_NOP;
		this.payLoadLength = 0;
	}

	public void rawType(final int msgType) {
		this.msgType = msgType;
		this.payLoadLength = 0;
	}

	public void put(final long clusterId, final long replicationId, final InetAddress stickyAddr,
			final InetAddress mapAddr) {
		this.msgType = CLUSTER_MSG_TYPE_STICKY_UPDATE;
		this.clusterId = clusterId;
		this.replicationId = replicationId;
		this.stickyAddr = stickyAddr;
		this.mapAddr = mapAddr;
	}

	public int getMsgType() {
		return msgType;
	}

	public long getClusterId() {
		return clusterId;
	}

	public long getReplicationId() {
		return replicationId;
	}

	public InetAddress getStickyAddr() {
		return stickyAddr;
	}

	public InetAddress getMapAddr() {
		return mapAddr;
	}

	public void toWire(final OutputStream os) throws IOException {
		switch (msgType) {
			case CLUSTER_MSG_TYPE_SYNC_BEGIN:
			case CLUSTER_MSG_TYPE_SYNC_END:
			case CLUSTER_MSG_TYPE_NOP:
			case CLUSTER_MSG_TYPE_HELLO: {
				// Head
				os.write(MAGIC);
				os.write(msgType);
				os.write(0);
				os.write(0);
				break;
			}
			case CLUSTER_MSG_TYPE_STICKY_UPDATE: {
				final byte[] p1 = stickyAddr.getAddress();
				final byte[] p2 = mapAddr.getAddress();
				// head: magic(1) | msgType(1) | payloadLength(2) | payload(N)
				// payload: clusterId(8) | replicationId(8) |
				// stickyLen(1) | stickyAddr(4-16) | mapLen(1) | mapAddr(4-16)
				payLoadLength = 8 + 8 + 1 + p1.length + 1 + p2.length;
				//
				// Head
				os.write(MAGIC);
				os.write(msgType);
				os.write(payLoadLength >> 8);
				os.write(payLoadLength);
				//
				// PayLoad
				os.write((int) (clusterId >> 56));
				os.write((int) (clusterId >> 48));
				os.write((int) (clusterId >> 40));
				os.write((int) (clusterId >> 32));
				os.write((int) (clusterId >> 24));
				os.write((int) (clusterId >> 16));
				os.write((int) (clusterId >> 8));
				os.write((int) (clusterId));
				os.write((int) (replicationId >> 56));
				os.write((int) (replicationId >> 48));
				os.write((int) (replicationId >> 40));
				os.write((int) (replicationId >> 32));
				os.write((int) (replicationId >> 24));
				os.write((int) (replicationId >> 16));
				os.write((int) (replicationId >> 8));
				os.write((int) (replicationId));
				os.write(p1.length);
				os.write(p1);
				os.write(p2.length);
				os.write(p2);
				//
				break;
			}
			default:
				throw new IOException("Unknown MSG_TYPE");
		}
		os.flush();
	}

	public void fromWire(final InputStream is) throws IOException {
		final int magic = is.read(); // magic(1)
		// Check MAGIC
		if (magic != MAGIC) {
			final String err = "Invalid MAGIC (expected: " + MAGIC + " readed: " + magic + ")";
			clear();
			throw new IOException(err);
		}
		this.msgType = is.read(); // msgType(1)
		this.payLoadLength = ((is.read() << 8) | is.read()); // payloadLength(2)
		final int len = IOHelper.fullRead(is, this.payload, this.payLoadLength);
		switch (this.msgType) {
			case CLUSTER_MSG_TYPE_STICKY_UPDATE:
				break;
			default: // nobody messages
				return;
		}
		// Check payLoadLength
		if (len <= 0) {
			clear();
			throw new EOFException("EOF");
		}
		if (len != payLoadLength) {
			final String err = "Invalid PAYLOAD (expected: " + payLoadLength + " readed: " + len + ")";
			clear();
			throw new IOException(err);
		}
		// Process payload
		int offset = 0;
		this.clusterId = IOHelper.longFromByteArray(payload, offset);
		offset += 8;
		this.replicationId = IOHelper.longFromByteArray(payload, offset);
		offset += 8;
		final int p1Len = payload[offset++];
		final byte[] p1 = Arrays.copyOfRange(payload, offset, offset + p1Len);
		offset += p1Len;
		final int p2Len = payload[offset++];
		final byte[] p2 = Arrays.copyOfRange(payload, offset, offset + p2Len);
		this.stickyAddr = InetAddress.getByAddress(p1);
		this.mapAddr = InetAddress.getByAddress(p2);
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		sb.append("msgType=").append(msgType);
		if (msgType == CLUSTER_MSG_TYPE_STICKY_UPDATE) {
			sb.append(" clusterId=").append(clusterId);
			sb.append(" replicationId=").append(replicationId);
			sb.append(" stickyAddr=").append(stickyAddr != null ? stickyAddr.getHostAddress() : null);
			sb.append(" mapAddr=").append(mapAddr != null ? mapAddr.getHostAddress() : null);
		}
		return sb.toString();
	}
}
