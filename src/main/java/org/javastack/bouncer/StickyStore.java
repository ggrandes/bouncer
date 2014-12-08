package org.javastack.bouncer;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;

public abstract class StickyStore<K extends InetAddress, V extends InetAddress> {
	/**
	 * Get Instance of StickyStore
	 * 
	 * @param stickyConfig
	 * @return
	 */
	public static <K extends InetAddress, V extends InetAddress> StickyStore<K, V> getInstance(
			final StickyConfig stickyConfig) {
		switch (stickyConfig.type) {
			case MEM:
				return new StickyStoreMEM<K, V>(stickyConfig);
		}
		return null;
	}

	/**
	 * Put Sticky
	 * 
	 * @param key
	 * @param value
	 */
	public abstract void put(final K key, final V value);

	/**
	 * Get Sticky value
	 * 
	 * @param key
	 * @return
	 */
	public abstract V get(final K key);

	static class StickyStoreMEM<K extends InetAddress, V extends InetAddress> extends StickyStore<K, V> {
		private final StickyConfig stickyConfig;
		private final Map<K, V> stickies;

		private StickyStoreMEM(final StickyConfig stickyConfig) {
			this.stickyConfig = stickyConfig;
			this.stickies = createMap();
		}

		private final Map<K, V> createMap() {
			return new LinkedHashMap<K, V>(16, 0.75f, true) {
				private static final long serialVersionUID = 42L;

				protected boolean removeEldestEntry(final Map.Entry<K, V> eldest) {
					return size() > stickyConfig.elements;
				}
			};
		}

		@Override
		public synchronized void put(final K key, final V value) {
			@SuppressWarnings("unchecked")
			final K keyMask = (K) IpAddress.getAddressMasked(key, stickyConfig.bitmask);
			stickies.put(keyMask, value);
		}

		@Override
		public synchronized V get(final K key) {
			@SuppressWarnings("unchecked")
			final K keyMask = (K) IpAddress.getAddressMasked(key, stickyConfig.bitmask);
			return stickies.get(keyMask);
		}
	}
}
