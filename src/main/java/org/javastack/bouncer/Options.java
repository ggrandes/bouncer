package org.javastack.bouncer;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

public class Options {
	public static final String S_NULL = "";
	public static final Integer I_NULL = Integer.valueOf(0);
	// Load Balancing Policies
	// @formatter:off
	public static final int LB_ORDER = 0x00000000; 	// Original order, pick next only on error
	public static final int LB_RR    = 0x00000001; 	// Round robin
	public static final int LB_RAND  = 0x00000002; 	// Random pick
	public static final int TUN_SSL  = 0x00000010; 	// Client is Plain, Remote is SSL (like stunnel)
	public static final int MUX_AES  = 0x00000020; 	// Encryption of MUX with AES+PreSharedKey
	public static final int MUX_SSL  = 0x00000040; 	// Encryption of MUX with SSL/TLS
	public static final int MUX_OUT  = 0x00000100; 	// Multiplexor initiator (outbound)
	public static final int MUX_IN   = 0x00000200; 	// Multiplexor terminator (inbound)
	// @formatter:on
	//
	public static final String P_AES = "AES";
	public static final String P_AES_ALG = "AESALG";
	public static final String P_AES_BITS = "AESBITS";
	public static final String P_SSL = "SSL";
	public static final String P_CONNECT_TIMEOUT = "CONNECT_TIMEOUT";
	public static final String P_READ_TIMEOUT = "READ_TIMEOUT";
	public static final String P_MUX_NAME = "MUX_NAME";
	public static final String P_TUN_ID = "TUN_ID";
	//
	@SuppressWarnings("serial")
	private final static Map<String, Integer> MAP_FLAGS = Collections
			.unmodifiableMap(new HashMap<String, Integer>() {
				{
					put("LB=ORDER", LB_ORDER);
					put("LB=RR", LB_RR);
					put("LB=RAND", LB_RAND);
					put("TUN=SSL", TUN_SSL);
					put("MUX=OUT", MUX_OUT);
					put("MUX=IN", MUX_IN);
					put("MUX=AES", MUX_AES);
					put("MUX=SSL", MUX_SSL);
				}
			});
	//
	int flags;
	@SuppressWarnings("serial")
	final Map<String, String> strParams = Collections.synchronizedMap(new HashMap<String, String>() {
		{
			put(P_MUX_NAME, S_NULL); 	// MUX_NAME=<muxName> // FIXME
			put(P_AES, S_NULL); 		// AES=<key>
			put(P_AES_ALG, S_NULL); 	// AESALG=<cipherAlgorithm>
			put(P_SSL, S_NULL); 		// SSL=server.crt:server.key:client.crt (MUX-IN) ||
								// SSL=client.crt:client.key:server.crt (MUX-OUT)
		}
	});
	@SuppressWarnings("serial")
	final Map<String, Integer> intParams = Collections.synchronizedMap(new HashMap<String, Integer>() {
		{
			put(P_CONNECT_TIMEOUT, I_NULL); // CONNECT_TIMEOUT=millis
			put(P_READ_TIMEOUT, I_NULL); 	// READ_TIMEOUT=millis
			put(P_TUN_ID, I_NULL); 			// TUN_ID=<idEndPoint> // FIXME
			put(P_AES_BITS, I_NULL); 		// AESBITS=<keyLengthInBits>
		}
	});

	public Options(final String strOpts) {
		this.flags = parseOptions(strOpts);
	}

	// Clone Constructor
	public Options(final Options old) {
		this.flags = old.flags;
		for (Entry<String, String> e : old.strParams.entrySet()) {
			strParams.put(e.getKey(), e.getValue());
		}
		for (Entry<String, Integer> e : old.intParams.entrySet()) {
			intParams.put(e.getKey(), e.getValue());
		}
	}

	public int getFlags(final int filterBits) {
		return (flags & filterBits);
	}

	public void setFlags(final int bits) {
		flags |= bits;
	}

	public void unsetFlags(final int bits) {
		flags &= ~bits;
	}

	public String getString(final String name) {
		final String value = strParams.get(name);
		if (value == S_NULL) {
			return null;
		}
		return value;
	}

	public void setString(final String name, String value) {
		if (value == null) {
			value = S_NULL;
		}
		strParams.put(name, value);
	}

	public Integer getInteger(final String name, final Integer def) {
		final Integer value = intParams.get(name);
		if (value == I_NULL) {
			return def;
		}
		return value;
	}

	public Integer getInteger(final String name) {
		return getInteger(name, null);
	}

	public void setInteger(final String name, Integer value) {
		if (value == null) {
			value = I_NULL;
		}
		intParams.put(name, value);
	}

	/**
	 * Helper (remove options that only apply to MUX)
	 */
	public Options unsetOptionsMUX() {
		unsetFlags(MUX_OUT | MUX_IN | MUX_AES | MUX_SSL);
		setString(P_AES, null);
		setString(P_SSL, null);
		return this;
	}

	/**
	 * Helper (remove options that only apply to Plain Connections)
	 */
	public Options unsetOptionsPlain() {
		unsetFlags(TUN_SSL);
		return this;
	}

	/**
	 * Check is specified flag is active
	 * 
	 * @param opt
	 * @param FLAG
	 * @return true or false
	 */
	public boolean isOption(final int FLAG) {
		return ((flags & FLAG) != 0);
	}

	/**
	 * Return options in numeric form (bitwise-flags)
	 * 
	 * @param string to parse
	 * @return int with enabled flags
	 */
	int parseOptions(final String str) {
		final String[] opts = str.split(",");
		int ret = 0;
		for (String opt : opts) {
			final int KEY = 0, VALUE = 1;
			final String[] optKV = opt.split("=");
			// Process Flags
			final Integer i = MAP_FLAGS.get(opt.toUpperCase());
			if (i != null) {
				ret |= i.intValue();
			}
			// Process String Params
			final String s = strParams.get(optKV[KEY].toUpperCase());
			if (s != null) {
				strParams.put(optKV[KEY], optKV[VALUE]);
			}
			// Process Integer Params
			final Integer ii = intParams.get(optKV[KEY].toUpperCase());
			if (ii != null) {
				intParams.put(optKV[KEY], Integer.valueOf(optKV[VALUE]));
			}
		}
		return ret;
	}

	/**
	 * For humans, return options parsed/validated
	 * 
	 * @return human readable string
	 */
	@Override
	public synchronized String toString() {
		int i = 0;
		final StringBuilder sb = new StringBuilder();
		// Flags
		for (Entry<String, Integer> e : MAP_FLAGS.entrySet()) {
			final String key = e.getKey();
			final Integer value = e.getValue();
			if ((flags & value) != 0) {
				if (i > 0)
					sb.append(",");
				sb.append(key);
				i++;
			}
		}
		// Strings
		for (Entry<String, String> e : strParams.entrySet()) {
			final String key = e.getKey();
			final String value = e.getValue();
			if (value != S_NULL) {
				if (i > 0)
					sb.append(",");
				sb.append(key).append("=").append(value);
				i++;
			}
		}
		// Integers
		for (Entry<String, Integer> e : intParams.entrySet()) {
			final String key = e.getKey();
			final Integer value = e.getValue();
			if (value != I_NULL) {
				if (i > 0)
					sb.append(",");
				sb.append(key).append("=").append(value);
				i++;
			}
		}
		return sb.toString();
	}

	public void setMuxName(final String muxName) {
		strParams.put(P_MUX_NAME, muxName);
	}

	public String getMuxName() {
		return getString(P_MUX_NAME);
	}

	public Integer getTunID() {
		return getInteger(P_TUN_ID);
	}
}