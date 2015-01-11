package org.javastack.bouncer;

public class StickyConfig {
	public static final StickyConfig NULL = new StickyConfig(Type.NULL, 0, 0, 0, 0, 0);
	public final Type type;
	public final int bitmask;
	public final int elements;
	public final int ttlsec;
	public final long clusterId;
	public final long replicationId;

	public StickyConfig(final Type type, final int bitmask, final int elements, final int ttlsec,
			final long clusterId, final long replicationId) {
		this.type = type;
		this.bitmask = bitmask;
		this.elements = elements;
		this.ttlsec = ttlsec;
		this.clusterId = clusterId;
		this.replicationId = replicationId;
	}

	public boolean isReplicated() {
		return ((clusterId > 0) && (replicationId > 0));
	}

	public enum Type {
		/**
		 * NULL
		 */
		NULL,
		/**
		 * MEMORY
		 */
		MEM;
	}
}
