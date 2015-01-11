package org.javastack.bouncer;

public class Constants {
	public static final String VERSION_FILE = "/bouncer-version.mf";
	public static final String SUITES_FILE = "/ciphersuites.conf";

	// System properties (logs)
	public static final String PROP_OUT_FILE = "log.stdOutFile";
	public static final String PROP_ERR_FILE = "log.stdErrFile";
	public static final String PROP_OUT_STDTOO = "log.stdToo";

	public static final int RELOAD_CONFIG = 10000; 			// Default 10seconds
	public static final int RELOAD_TIMEOUT = 30000; 		// Default 30seconds timeout
	public static final int STATISTICS_PRINT_INTVL = 30000; // Default 30seconds
	public static final int BUFFER_LEN = 4096; 				// Default 4k page
	public static final int IO_BUFFERS = 8; 				// Default 8 buffers
	public static final int BUFFER_POOL_SIZE = 4;			// Default 4 elements (per thread)
	public static final int CONNECT_TIMEOUT = 30000; 		// Default 30seconds timeout
	public static final int ACCEPT_TIMEOUT = 1000; 			// Default 1second timeout
	public static final int READ_TIMEOUT = 300000; 			// Default 5min timeout
	public static final int MUX_READ_TIMEOUT = 2000;		// Default 2seconds timeout
	public static final int MUX_KEEP_ALIVE = 30000; 		// Default 30seconds timeout
	public static final int DNS_CACHE_TIME = 2000; 			// Default 2seconds
	public static final int CLUSTER_READ_TIMEOUT = 2000;	// Default 2seconds timeout
	public static final int CLUSTER_KEEP_ALIVE = 10000;		// Default 10seconds

	public static final String SEALER_PBKDF_ALG = "PBKDF2WithHmacSHA1";	// Default PBKDF2WithHmacSHA1
	public static final String SEALER_MD_ALG = "SHA1";					// Default SHA1
	public static final String SEALER_HMAC_ALG = "HmacSHA256";			// Default HmacSHA256
	// AES/CBC/PKCS5Padding | AES/CTR/NoPadding | AES/GCM/NoPadding | Blowfish/CTR/NoPadding
	public static final String SEALER_CIPHER_ALG = "AES/CTR/NoPadding";	// Default AES/CTR/NoPadding
	public static final int SEALER_CIPHER_MIN_KEY_BITS = 128;			// Minimal 128bits
	public static final int SEALER_REKEY_PACKETS = 0x7FFF;				// Default 32K packets
	public static final int SEALER_TS_WINDOW = 300; 					// Default 5min
}
