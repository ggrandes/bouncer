package org.javastack.bouncer;

import java.util.concurrent.ArrayBlockingQueue;

/**
 * GenericPool that uses ThreadLocal
 */
public class GenericPool<T> {
	private final GenericPoolFactory<T> factory;
	private final ThreadLocal<ArrayBlockingQueue<T>> local;

	public GenericPool(final GenericPoolFactory<T> factory, final int size) {
		this.factory = factory;
		this.local = new ThreadLocal<ArrayBlockingQueue<T>>() {
			@Override
			protected ArrayBlockingQueue<T> initialValue() {
				return new ArrayBlockingQueue<T>(size);
			}
		};
	}

	/**
	 * Get Object from Pool
	 * 
	 * @return
	 */
	public T checkout() {
		final T obj = local.get().poll();
		if (obj == null) {
			return factory.newInstance();
		}
		return obj;
	}

	/**
	 * Release Object to the Pool
	 * 
	 * @param obj
	 */
	public void release(final T obj) {
		local.get().offer(obj);
	}

	/**
	 * Free thread local resources
	 */
	public void destroy() {
		local.remove();
	}

	public static interface GenericPoolFactory<T> {
		public T newInstance();
	}
}
