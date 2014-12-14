package org.javastack.bouncer;

import java.util.concurrent.atomic.AtomicLong;

public class ClientId {
	private static final AtomicLong atomicId = new AtomicLong(0);
	private static final ThreadLocal<Long> localId = new ThreadLocal<Long>() {
		@Override
		protected Long initialValue() {
			return atomicId.incrementAndGet();
		}
	};

	public static long newId() {
		return atomicId.incrementAndGet();
	}

	public static long getId() {
		return localId.get();
	}

	public static void setId(final Long id) {
		localId.set(id);
	}
	
	/**
	 * Free thread local resources
	 */
	public static void destroy() {
		localId.remove();
	}
}
