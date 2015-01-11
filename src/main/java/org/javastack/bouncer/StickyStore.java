package org.javastack.bouncer;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public abstract class StickyStore<K extends InetAddress, V extends InetAddress> {
	protected final StickyConfig stickyConfig;

	protected StickyStore(final StickyConfig stickyConfig) {
		this.stickyConfig = stickyConfig;
	}

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
			case NULL:
				return new StickyStoreNULL<K, V>();
		}
		return null;
	}

	public StickyConfig getConfig() {
		return stickyConfig;
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

	/**
	 * Return inmutable list of associations
	 * 
	 * @return
	 */
	public abstract List<StickyEntry<K, V>> getEntries();

	static class StickyEntry<K extends InetAddress, V extends InetAddress> {
		public final K key;
		public final V value;

		StickyEntry(final K key, final V value) {
			this.key = key;
			this.value = value;
		}
	}

	static class StickyStoreMEM<K extends InetAddress, V extends InetAddress> extends StickyStore<K, V> {
		private final Map<K, TSEntry<V>> stickies;

		private StickyStoreMEM(final StickyConfig stickyConfig) {
			super(stickyConfig);
			this.stickies = createMap();
		}

		private final Map<K, TSEntry<V>> createMap() {
			return new LinkedHashMap<K, TSEntry<V>>(16, 0.75f, true) {
				private static final long serialVersionUID = 42L;

				protected boolean removeEldestEntry(final Map.Entry<K, TSEntry<V>> eldest) {
					return size() > stickyConfig.elements;
				}
			};
		}

		@SuppressWarnings("unchecked")
		private final K maskKey(final K key) {
			return (K) IpAddress.getAddressMasked(key, stickyConfig.bitmask);
		}

		@Override
		public synchronized void put(final K key, final V value) {
			stickies.put(maskKey(key), new TSEntry<V>(value));
		}

		@Override
		public synchronized V get(final K key) {
			final TSEntry<V> e = stickies.get(maskKey(key));
			if (e != null) {
				final long now = System.currentTimeMillis();
				if (e.ts + (stickyConfig.ttlsec * 1000) >= now) {
					return e.value;
				}
			}
			return null;
		}

		@Override
		public synchronized List<StickyEntry<K, V>> getEntries() {
			final ArrayList<StickyEntry<K, V>> l = new ArrayList<StickyEntry<K, V>>();
			for (final Entry<K, TSEntry<V>> e : stickies.entrySet()) {
				l.add(new StickyEntry<K, V>(e.getKey(), e.getValue().value));
			}
			return l;
		}

		static class TSEntry<E> {
			final long ts;
			final E value;

			public TSEntry(final E value) {
				this.ts = System.currentTimeMillis();
				this.value = value;
			}
		}
	}

	static class StickyStoreNULL<K extends InetAddress, V extends InetAddress> extends StickyStore<K, V> {
		private StickyStoreNULL() {
			super(StickyConfig.NULL);
		}

		@Override
		public void put(final K key, final V value) {
		}

		@Override
		public V get(final K key) {
			return null;
		}

		@Override
		public List<StickyEntry<K, V>> getEntries() {
			return Collections.emptyList();
		}
	}

	/**
	 * Simple Text
	 */
	public static void main(final String[] args) throws Throwable {
		StickyConfig cfg = new StickyConfig(StickyConfig.Type.MEM, 32, 2, 1, 0, 0);
		StickyStore<InetAddress, InetAddress> store = StickyStore.getInstance(cfg);
		InetAddress a1 = InetAddress.getByName("127.0.0.1");
		store.put(a1, a1);
		InetAddress a2 = InetAddress.getByName("127.0.0.2");
		store.put(a2, a2);
		InetAddress a3 = InetAddress.getByName("127.0.0.3");
		store.put(a3, a3);
		//
		System.out.println(store.get(a1));
		System.out.println(store.get(a2));
		System.out.println(store.get(a3));
		Thread.sleep(1100);
		System.out.println(store.get(a3));
	}
}
