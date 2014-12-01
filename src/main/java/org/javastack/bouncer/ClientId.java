package org.javastack.bouncer;

import java.util.concurrent.atomic.AtomicInteger;

public class ClientId {
	private static final AtomicInteger atomicId = new AtomicInteger(0);
	private static final ThreadLocal<Integer> localId = new ThreadLocal<Integer>() {
		@Override
		protected Integer initialValue() {
			return atomicId.incrementAndGet();
		}
	};

	public static int newId() {
		return atomicId.incrementAndGet();
	}

	public static int getId() {
		return localId.get();
	}

	public static void setId(final Integer id) {
		localId.set(id);
	}
	
	/**
	 * Free thread local resources
	 */
	public static void destroy() {
		localId.remove();
	}
}
