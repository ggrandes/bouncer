/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package net.bouncer;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;

/**
 * Simple TCP Bouncer
 *
 * @author Guillermo Grandes / guillermo.grandes[at]gmail.com
 */
public class SimpleBouncer {
	public static final String VERSION = "1.5beta1";
	//
	private static final int BUFFER_LEN = 4096; 		// Default 4k page
	private static final int OUTPUT_BUFFERS = 3;
	private static final int CONNECT_TIMEOUT = 30000;	// Default 30seconds timeout
	private static final int READ_TIMEOUT = 300000;		// Default 5min timeout
	private static final long RELOAD_CONFIG = 10000;	// Default 10seconds
	private static final String CONFIG_FILE = "/bouncer.conf";
	// For graceful reload
	private Set<Awaiter> reloadables = Collections.synchronizedSet(new HashSet<Awaiter>());
	private CyclicBarrier shutdownBarrier = null;

	private ExecutorService threadPool = Executors.newCachedThreadPool(); 

	class StandardAdapter implements EventListener {
		@Override
		public void event(Event evt) {
			Log.info(this.getClass().getSimpleName() + " " + evt);
		}
	}

	// ============================== Plain Connections

	class GenericAcceptator implements Shutdownable, Awaiter, Runnable {
		InboundAddress inboundAddress;
		EventListener eventListener;
		ServerSocket listen;
		volatile boolean shutdown = false;
		//
		GenericAcceptator(InboundAddress inboundAddress, EventListener eventListener) {
			this.inboundAddress = inboundAddress;
			this.eventListener = eventListener;
		}
		//
		@Override
		public void setShutdown() {
			shutdown = true;
			closeSilent(listen);
		}
		//
		private void notify(Event evt) {
			if (eventListener != null)
				eventListener.event(evt);
		}
		//
		@Override
		public void run() {
			try {
				inboundAddress.resolve();
				listen = inboundAddress.listen();
				Log.info(this.getClass().getSimpleName() + " started: " + inboundAddress);
				notify(new EventLifeCycle(this, true));
				while (!shutdown) {
					Socket client = listen.accept();
					setupSocket(client);
					Integer pReadTimeout = inboundAddress.getOpts().getInteger(Options.P_READ_TIMEOUT);
					if (pReadTimeout != null) {
						client.setSoTimeout(pReadTimeout);
					}
					Log.info(this.getClass().getSimpleName() + " New client from=" + client);
					notify(new EventNewSocket(this, client));
				}
			}
			catch (UnknownHostException e) {
				Log.error(this.getClass().getSimpleName() + " " + e.toString());
			}
			catch (Exception e) {
				if (!listen.isClosed()) {
					Log.error(this.getClass().getSimpleName() + " Generic exception", e);
				}
			}
			finally {
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown(this);
				Log.info(this.getClass().getSimpleName() + " end");
				notify(new EventLifeCycle(this, false));
			}
		}
	}

	class GenericConnector implements Shutdownable, Runnable {
		OutboundAddress outboundAddress;
		EventListener eventListener;
		Socket remote = null;
		volatile boolean shutdown = false;
		//
		GenericConnector(OutboundAddress outboundAddress, EventListener eventListener) {
			this.outboundAddress = outboundAddress;
			this.eventListener = eventListener;
		}
		//
		@Override
		public void setShutdown() {
			shutdown = true;
			closeSilent(remote);
		}
		//
		private void notify(Event evt) {
			if (eventListener != null)
				eventListener.event(evt);
		}
		//
		@Override
		public void run() {
			try {
				Log.info(this.getClass().getSimpleName() + " started: " + outboundAddress);
				notify(new EventLifeCycle(this, true));
				while (!shutdown) {
					// Remote
					outboundAddress.resolve();
					remote = outboundAddress.connect();
					if (remote != null) {
						break;
					}
					Log.info(this.getClass().getSimpleName() + " cannot connect (waiting for retry): " + outboundAddress);
					Thread.sleep(5000);
					return;
				}
				notify(new EventNewSocket(this, remote));
			}
			catch (UnknownHostException e) {
				Log.error(this.getClass().getSimpleName() + " " + e.toString());
			}
			catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " Generic exception", e);
			}
			finally {
				// Close all
				//closeSilent(remote);
				Log.info(this.getClass().getSimpleName() + " ended: " + outboundAddress);
				notify(new EventLifeCycle(this, false));
			}
		}
	}

	// rinetd Style
	class RinetdStyleAdapterLocal implements EventListener {
		OutboundAddress right;
		ArrayList<GenericConnector> connections = new ArrayList<GenericConnector>();
		//
		RinetdStyleAdapterLocal(OutboundAddress right) {
			this.right = right;
		}
		@Override
		public void event(Event evt) {
			Log.info(this.getClass().getSimpleName() + "::event " + evt);
			if (evt instanceof EventNewSocket) {
				EventNewSocket event = (EventNewSocket) evt;
				Socket client = event.sock;
				GenericConnector connection = new GenericConnector(right, new RinetdStyleAdapterRemote(client));
				connections.add(connection);
				doTask(connection);
			}
		}
	}
	class RinetdStyleAdapterRemote implements EventListener {
		Socket client;
		//
		RinetdStyleAdapterRemote(Socket client) {
			this.client = client;
		}
		@Override
		public void event(Event evt) {
			Log.info(this.getClass().getSimpleName() + "::event " + evt);
			if (evt instanceof EventNewSocket) {
				EventNewSocket event = (EventNewSocket) evt;
				Socket remote = event.sock;
				Log.info(this.getClass().getSimpleName() + " Bouncer from " + client + " to " + remote);
				try {
					final PlainSocketTransfer st1 = new PlainSocketTransfer(client, remote);
					final PlainSocketTransfer st2 = new PlainSocketTransfer(remote, client);
					st1.setBrother(st2);
					st2.setBrother(st1);
					doTask(st1);
					doTask(st2);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + "::event Exception", e);
				}
			}
		}
	}

	/**
	 * Transfer data between sockets
	 */
	class PlainSocketTransfer implements Shutdownable, Runnable {
		final byte[] buf = new byte[BUFFER_LEN];
		final Socket sockin;
		final Socket sockout;
		final InputStream is;
		final OutputStream os;
		volatile boolean shutdown = false;
		//
		long keepalive = System.currentTimeMillis();
		PlainSocketTransfer brother = null;
		//
		PlainSocketTransfer(final Socket sockin, final Socket sockout) throws IOException {
			this.sockin = sockin;
			this.sockout = sockout;
			this.is = sockin.getInputStream();
			this.os = sockout.getOutputStream();
		}
		public void setBrother(final PlainSocketTransfer brother) {
			this.brother = brother;
		}
		@Override
		public void setShutdown() {
			shutdown = true;
		}
		@Override
		public void run() {
			try {
				while (true) {
					try {
						if (transfer()) {
							keepalive = System.currentTimeMillis();
							continue;
						}
					} catch (SocketTimeoutException e) {
						Log.info(this.getClass().getSimpleName() + " " + e.toString());
						if (brother == null) break;
						try {
							if ((System.currentTimeMillis() - brother.keepalive) > sockin.getSoTimeout()) {
								break;
							}
						} catch (Exception brk) {
							break;
						}
					}					
				}
			} catch (Exception e) {
				try {
					if ((sockin instanceof SSLSocket) && (!sockin.isClosed())) {
						Thread.sleep(100);
					}
				} catch (Exception ign) {}
				if (!sockin.isClosed() && !shutdown) {
					Log.error(this.getClass().getSimpleName() + " " + e.toString() + " " + sockin);
				}
			} finally {
				closeSilent(is);
				closeSilent(os);
				Log.info(this.getClass().getSimpleName() + " Connection closed " + sockin);
			}
		}
		boolean transfer() throws IOException {
			int len = is.read(buf, 0, buf.length);
			if (len < 0) {
				return false;
			}
			os.write(buf, 0, len);
			os.flush();
			return true;
		}
	}

	// ============================== Global code

	public static void main(final String[] args) throws Exception {
		final SimpleBouncer bouncer = new SimpleBouncer();
		//
		if (Boolean.getBoolean("DEBUG"))
			Log.enableDebug(); // Enable debugging messages
		Log.info("Starting " + bouncer.getClass() + " version " + VERSION + (Log.isDebug() ? " debug-mode": ""));
		// Read config
		final URL urlConfig = bouncer.getClass().getResource(CONFIG_FILE);
		if (urlConfig == null) {
			Log.error("Config not found: (classpath)" + CONFIG_FILE);
			return;
		}
		long lastReloaded = 0;
		while (true) {
			final URLConnection connConfig = urlConfig.openConnection();
			connConfig.setUseCaches(false);
			final long lastModified = connConfig.getLastModified();
			Log.debug("lastReloaded=" + lastReloaded + " getLastModified()=" + connConfig.getLastModified() + " currentTimeMillis()=" + System.currentTimeMillis());
			if (lastModified > lastReloaded) {
				if (lastReloaded > 0) {
					Log.info("Reloading config");
				}
				lastReloaded = lastModified;
				bouncer.reload(connConfig);
			}
			Thread.sleep(RELOAD_CONFIG);
		}
	}

	boolean awaitShutdown(Awaiter caller) {
		boolean ret = false;
		if (shutdownBarrier != null) {
			try {
				shutdownBarrier.await(30000, TimeUnit.MILLISECONDS); // Wait 30 seconds
				ret = true;
			} catch (Exception ign) {}
		}
		if (caller != null)
			reloadables.remove(caller);
		return ret;
	}

	void doTask(final Runnable task) {
		Log.info("New task: " + task);
		threadPool.submit(task);
	}

	void reload(final URLConnection connConfig) throws IOException {
		final InputStream isConfig = connConfig.getInputStream();
		//
		if (!reloadables.isEmpty()) {
			shutdownBarrier = new CyclicBarrier(reloadables.size()+1);
			for (Shutdownable shut : reloadables) {
				Log.info(this.getClass().getSimpleName() + " Shuting down: " + shut.getClass().getSimpleName());
				shut.setShutdown();
			}
			Log.info(this.getClass().getSimpleName() + " Waiting for " + reloadables.size() + " threads to shutdown");
			if (awaitShutdown(null)) {
				Log.info(this.getClass().getSimpleName() + " Shutdown completed");
			} else {
				Log.error(this.getClass().getSimpleName() + " Shutdown Error");
			}
			shutdownBarrier = null;
			reloadables.clear();
		}
		//
		final BufferedReader in = new BufferedReader(new InputStreamReader(isConfig));
		String line = null;
		try {
			while ((line = in.readLine()) != null) {
				// Skip comments
				if (line.trim().startsWith("#")) continue; 
				if (line.trim().equals("")) continue; 
				// Expected format (style rinetd):
				// <bind-addr> <bind-port> <remote-addr> <remote-port> [options]
				final String[] toks = line.split("( |\t)+"); 
				// Invalid number of params
				if (toks.length < 4) { 
					Log.error(this.getClass().getSimpleName() + " Invalid config line: " + line);
					continue;
				}
				// Start bouncers
				final String bindaddr = toks[0];
				final int bindport = Integer.valueOf(toks[1]);
				//
				final String remoteaddr = toks[2];
				final int remoteport = Integer.valueOf(toks[3]);
				//
				final String options = ((toks.length > 4) ? toks[4] : "");
				final Options opts = new Options(options);
				//
				Log.info(this.getClass().getSimpleName() + " Readed bind-addr=" + bindaddr + " bind-port=" + bindport + " remote-addr=" + remoteaddr + " remote-port=" + remoteport + " options{" + opts + "}");
				start(bindaddr, bindport, remoteaddr, remoteport, opts);
			}
		} finally {
			closeSilent(in);
			closeSilent(isConfig);
		}
	}

	void start(final String leftaddr, final int leftport, final String rightaddr, final int rightport, final Options opts) {
		BouncerAddress eleft = null, eright = null;
		SSLFactory sslFactory = null;
		if (opts.isOption(Options.MUX_SSL)) {
			String[] sslConfig = new String[] { "NULL"};
			try {
				sslConfig = opts.getString(Options.P_SSL).split(":");
				sslFactory = new SSLFactory(sslConfig[0], sslConfig[1], sslConfig[2]);
			}
			catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " Error creating SSLFactory("+Arrays.asList(sslConfig)+")", e);
				return;
			}
		}
		try {
			if (opts.isOption(Options.MUX_IN)) {
				Options lopts = new Options(opts).unsetOptionsPlain();
				Options ropts = new Options(opts).unsetOptionsMUX();
				InboundAddress left = new InboundAddress(leftaddr, leftport, lopts); // MUX
				InboundAddress right = new InboundAddress(rightaddr, rightport, ropts); // PLAIN
				left.setSSLFactory(sslFactory);
				eleft = left;
				eright = right;
				new MuxServer(left, right).listenLocal();
			}
			else if (opts.isOption(Options.MUX_OUT)) {
				Options lopts = new Options(opts).unsetOptionsMUX();
				Options ropts = new Options(opts).unsetOptionsPlain();
				OutboundAddress left = new OutboundAddress(leftaddr, leftport, lopts); // PLAIN
				OutboundAddress right = new OutboundAddress(rightaddr, rightport, ropts); // MUX
				right.setSSLFactory(sslFactory);
				eleft = left;
				eright = right;
				new MuxClient(left, right).openRemote();
			}
			else {
				Options lopts = new Options(opts).unsetOptionsMUX();
				Options ropts = new Options(opts).unsetOptionsMUX();
				InboundAddress left = new InboundAddress(leftaddr, leftport, lopts); // PLAIN
				OutboundAddress right = new OutboundAddress(rightaddr, rightport, ropts); // PLAIN
				eleft = left;
				eright = right;
				RinetdStyleAdapterLocal redir = new RinetdStyleAdapterLocal(right);
				GenericAcceptator acceptator = new GenericAcceptator(left, redir);
				reloadables.add(acceptator);
				doTask(acceptator);
			}
		} catch (Exception e) {
			Log.error(this.getClass().getSimpleName() + " Error trying to bounce from " + eleft + " to " + eright, e);
		}
	}

	static void closeSilent(final Reader ir) {
		try { ir.close(); } catch (Exception ign) {}
	}
	static void closeSilent(final InputStream is) {
		try { is.close(); } catch (Exception ign) {}
	}
	static void closeSilent(final OutputStream os) {
		try { os.flush(); } catch (Exception ign) {}
		try { os.close(); } catch (Exception ign) {}
	}
	static void closeSilent(final Socket sock) {
		try { sock.shutdownInput(); } catch (Exception ign) {}
		try { sock.shutdownOutput(); } catch (Exception ign) {}
		try { sock.close(); } catch (Exception ign) {}
	}
	static void closeSilent(final ServerSocket sock) {
		try { sock.close(); } catch (Exception ign) {}
	}

	static void setupSocket(final ServerSocket sock) throws SocketException {
		sock.setReuseAddress(true);
	}
	static void setupSocket(final Socket sock) throws SocketException {
		sock.setKeepAlive(true);
		sock.setReuseAddress(true);
		sock.setSoTimeout(READ_TIMEOUT);
		sock.setSendBufferSize(BUFFER_LEN*OUTPUT_BUFFERS);
		sock.setReceiveBufferSize(BUFFER_LEN*OUTPUT_BUFFERS);
	}

	static String fromArrAddress(final InetAddress[] addrs) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < addrs.length; i++) {
			InetAddress addr = addrs[i];
			if (i > 0) sb.append(",");
			sb.append(addr.getHostAddress());
		}
		return sb.toString();
	}

	interface Shutdownable  {
		public void setShutdown();
	}
	interface Awaiter extends Shutdownable {}

	interface BouncerAddress {
		public String toString();
	}

	/**
	 * Representation of listen address 
	 */
	static class InboundAddress implements BouncerAddress {
		//
		Options opts = null;
		SSLFactory sslFactory = null;
		//
		final String host;
		final int port;
		InetAddress[] addrs = null;
		//
		InboundAddress(final String host, final int port, final Options opts) {
			this.host = host;
			this.port = port;
			this.opts = opts;
		}
		public void setSSLFactory(SSLFactory sslFactory) {
			this.sslFactory = sslFactory;
		}
		Options getOpts() {
			return opts;
		}
		public String toString() {
			return host + ":" + port;
		}
		void resolve() throws UnknownHostException {
			addrs = InetAddress.getAllByName(host);
			Log.info(this.getClass().getSimpleName() + " Resolved host=" + host + " [" + fromArrAddress(addrs) + "]");
		}
		InetSocketAddress[] getSocketAddress() {
			InetSocketAddress[] socks = new InetSocketAddress[addrs.length];
			for (int i = 0; i < socks.length; i++) {
				socks[i] = new InetSocketAddress(addrs[i], port);
			}
			return socks;
		}
		ServerSocket listen() throws IOException {
			ServerSocket listen = null;
			if (opts.isOption(Options.MUX_SSL)) {
				listen = sslFactory.createSSLServerSocket();
			}
			else {
				listen = new ServerSocket();
			}
			InetSocketAddress bind = new InetSocketAddress(addrs[0], port);
			setupSocket(listen);
			listen.bind(bind);
			return listen;
		}
	}

	/**
	 * Representation of remote destination
	 */
	static class OutboundAddress implements BouncerAddress {
		//
		int roundrobin = 0;
		Options opts = null;
		SSLFactory sslFactory = null;
		//
		final String host;
		final int port;
		InetAddress[] addrs = null;
		//
		OutboundAddress(final String host, final int port, final Options opts) {
			this.host = host;
			this.port = port;
			this.opts = opts;
		}
		public void setSSLFactory(SSLFactory sslFactory) {
			this.sslFactory = sslFactory;
		}
		Options getOpts() {
			return opts;
		}
		public String toString() {
			return host + ":" + port;
		}
		void resolve() throws UnknownHostException {
			addrs = InetAddress.getAllByName(host);
			Log.info(this.getClass().getSimpleName() + " Resolved host=" + host + " [" + fromArrAddress(addrs) + "]");
		}
		Socket connect() {
			if (addrs == null) {
				return null;
			}
			final int filterFlags = (Options.LB_ORDER | Options.LB_RR | Options.LB_RAND);
			Socket remote = null;
			switch (opts.getFlags(filterFlags)) {
			case Options.LB_ORDER:
				for (InetAddress addr : addrs) {
					remote = connect(addr);
					if (remote != null) break;
				}
				break;
			case Options.LB_RR:
				final int rrbegin = roundrobin;
				do {
					remote = connect(addrs[roundrobin++]);
					roundrobin %= addrs.length;
					if (remote != null) break;
				} while (roundrobin != rrbegin);
				break;
			case Options.LB_RAND:
				final Random r = new Random();
				remote = connect(addrs[(r.nextInt(Integer.MAX_VALUE) % addrs.length)]);
				break;
			}
			if (remote != null) {
				try {
					setupSocket(remote);
					Integer pReadTimeout = opts.getInteger(Options.P_READ_TIMEOUT);
					if (pReadTimeout != null) {
						remote.setSoTimeout(pReadTimeout);
					}
				} catch (SocketException e) {
					Log.error(this.getClass().getSimpleName() + " Error setting parameters to socket: " + remote);
				}
			}
			return remote;
		}
		Socket connect(final InetAddress addr) {
			final boolean isSSL = opts.isOption(Options.TUN_SSL|Options.MUX_SSL);
			Socket sock = null;
			try {
				Log.info(this.getClass().getSimpleName() + " Connecting to " + addr + ":" + port + (isSSL? " (SSL)": ""));
				if (opts.isOption(Options.MUX_SSL)) {
					sock = sslFactory.createSSLSocket();
				}
				else if (opts.isOption(Options.TUN_SSL)) {
					SocketFactory factory = SSLSocketFactory.getDefault();
					sock = factory.createSocket();
				}
				else {
					sock = new Socket();
				}
				Integer pConnectTimeout = opts.getInteger(Options.P_CONNECT_TIMEOUT);
				if (pConnectTimeout == null) {
					pConnectTimeout = CONNECT_TIMEOUT;
				}
				sock.connect(new InetSocketAddress(addr, port), pConnectTimeout);
				if (sock instanceof SSLSocket) {
					((SSLSocket) sock).startHandshake();
				}
			} catch (SocketTimeoutException e) {
				Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port + (isSSL? " (SSL) ": " ") + e.toString());
			} catch (ConnectException e) {
				Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port + (isSSL? " (SSL) ": " ") + e.toString());
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port + (isSSL? " (SSL)": ""), e);
			}
			if ((sock != null) && sock.isConnected()) {
				Log.info(this.getClass().getSimpleName() + " Connected to " + addr + ":" + port + (isSSL? " (SSL)": ""));
				return sock;
			}
			return null;
		}
	}

	static class Options {
		public static final String S_NULL	= "";
		public static final Integer I_NULL	= Integer.valueOf(0);
		// Load Balancing Policies
		public static final int LB_ORDER 	= 0x00000000; 	// Original order, pick next only on error
		public static final int LB_RR 		= 0x00000001;	// Round robin
		public static final int LB_RAND 	= 0x00000002;	// Random pick
		public static final int TUN_SSL		= 0x00000010;	// Client is Plain, Remote is SSL (like stunnel)
		public static final int MUX_AES		= 0x00000020;	// Encryption of MUX with AES+PreSharedKey
		public static final int MUX_SSL		= 0x00000040;	// Encryption of MUX with SSL/TLS
		public static final int MUX_OUT		= 0x00000100;	// Multiplexor initiator (outbound)
		public static final int MUX_IN		= 0x00000200;	// Multiplexor terminator (inbound)
		//
		public static final String P_AES				= "AES";
		public static final String P_SSL				= "SSL";
		public static final String P_CONNECT_TIMEOUT	= "CONNECT_TIMEOUT";
		public static final String P_READ_TIMEOUT		= "READ_TIMEOUT";
		//
		//
		@SuppressWarnings("serial")
		private final static Map<String, Integer> MAP_FLAGS = Collections.unmodifiableMap(new HashMap<String, Integer>() {
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
				put(P_AES, S_NULL);		// AES=<key>
				put(P_SSL, S_NULL);		// SSL=server.crt:server.key:client.crt (MUX-IN) || SSL=client.crt:client.key:server.crt (MUX-OUT)
			}
		});
		@SuppressWarnings("serial")
		final Map<String, Integer> intParams = Collections.synchronizedMap(new HashMap<String, Integer>() {
			{
				put(P_CONNECT_TIMEOUT, I_NULL);		// CONNECT_TIMEOUT=millis
				put(P_READ_TIMEOUT, I_NULL);		// READ_TIMEOUT=millis
			}
		});
		//
		public Options(String strOpts) {
			this.flags = parseOptions(strOpts);
		}
		// Clone Constructor
		public Options(Options old) {
			this.flags = old.flags;
			for (Entry<String, String> e : old.strParams.entrySet()) {
				strParams.put(e.getKey(), e.getValue());
			}
			for (Entry<String, Integer> e : old.intParams.entrySet()) {
				intParams.put(e.getKey(), e.getValue());
			}
		}
		//
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

		public Integer getInteger(final String name) {
			final Integer value = intParams.get(name);
			if (value == I_NULL) {
				return null;
			}
			return value;
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
			unsetFlags(MUX_OUT|MUX_IN|MUX_AES|MUX_SSL);
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
		 * @param opt
		 * @param FLAG
		 * @return true or false
		 */
		boolean isOption(final int FLAG) {
			return ((flags & FLAG) != 0);
		}

		/**
		 * Return options in numeric form (bitwise-flags)
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
		 * @return human readable string
		 */
		public synchronized String toString() {
			int i = 0;
			final StringBuilder sb = new StringBuilder();
			// Flags
			for (Entry<String, Integer> e : MAP_FLAGS.entrySet()) {
				final String key = e.getKey();
				final Integer value = e.getValue();
				if ((flags & value) != 0) {
					if (i > 0) sb.append(",");
					sb.append(key);
					i++;
				}
			}
			// Strings
			for (Entry<String, String> e : strParams.entrySet()) {
				final String key = e.getKey();
				final String value = e.getValue();
				if (value != S_NULL) {
					if (i > 0) sb.append(",");
					sb.append(key).append("=").append(value);
					i++;
				}
			}
			// Integers
			for (Entry<String, Integer> e : intParams.entrySet()) {
				final String key = e.getKey();
				final Integer value = e.getValue();
				if (value != I_NULL) {
					if (i > 0) sb.append(",");
					sb.append(key).append("=").append(value);
					i++;
				}
			}
			return sb.toString();
		}
	}

	class Event {
	}
	class EventLifeCycle extends Event {
		public final Object caller;
		public final boolean startORstop;
		//
		EventLifeCycle(Object caller, boolean startORstop) {
			this.caller = caller;
			this.startORstop = startORstop;
		}
		public String toString() {
			return (this.getClass().getSimpleName() + " " + caller + " " + (startORstop ? "START" : "STOP"));
		}
	}
	class EventNewSocket extends Event {
		public final Object caller;
		public final Socket sock;
		//
		public EventNewSocket(Object caller, Socket sock) {
			this.caller = caller;
			this.sock = sock;
		}
		public String toString() {
			return (this.getClass().getSimpleName() + " " + caller + " " + sock);
		}
	}
	interface EventListener {
		public void event(Event evt);
	}

	// ============================================ Mux Client

	// MuxClient (MUX=OUT) Local=RAW, Remote=MUX 
	class MuxClient {
		MuxClientMessageRouter router = new MuxClientMessageRouter();
		MuxClientRemote remote;
		HashMap<Integer, MuxClientLocal> mapLocals = new HashMap<Integer, MuxClientLocal>();
		//
		OutboundAddress left;
		OutboundAddress right;

		MuxClient(OutboundAddress left, OutboundAddress right) {
			this.left = left;
			this.right = right;
		}

		void openRemote() throws Exception { // Entry Point
			Log.info(this.getClass().getSimpleName() + "::openRemote " + right);
			remote = new MuxClientRemote(right);
			remote.setRouter(router);
			reloadables.add(remote);
			doTask(remote);
		}

		void openLocal(int id) throws IOException {
			Log.info(this.getClass().getSimpleName() + "::openLocal id=" + id);
			MuxClientLocal local = new MuxClientLocal(left);
			local.setId(id);
			local.setRouter(router);
			synchronized(mapLocals) {
				mapLocals.put(id, local);
			}
			doTask(local);
		}
		void closeLocal(int id) {
			// Send FIN
			try {
				MuxPacket mux = new MuxPacket();
				mux.fin(id);
				remote.sendRemote(mux);
			} catch (Exception ign) {
			}
			//
			synchronized(mapLocals) {
				MuxClientLocal local = mapLocals.remove(id);
				if (local != null) {
					local.setShutdown();
				}
			}
		}
		void sendACK(RawPacket msg) {
			// Send ACK
			try {
				MuxPacket mux = new MuxPacket();
				mux.ack(msg.getIdChannel(), msg.getBufferLen());
				remote.sendRemote(mux);
			} catch (Exception ign) {
			}
		}
		void sendNOP() {
			// Send NOP
			try {
				MuxPacket mux = new MuxPacket();
				mux.nop(0);
				remote.sendRemote(mux);
			} catch (Exception ign) {
			}
		}

		// ============================================

		class MuxClientMessageRouter {
			synchronized void onReceiveFromRemote(MuxClientRemote remote, MuxPacket msg) { // Remote is MUX
				//Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				if (msg.syn()) { // New SubChannel
					try {
						Log.info(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
						openLocal(msg.getIdChannel());
					} catch (ConnectException e) {
						// Send FIN
						closeLocal(msg.getIdChannel());
					} catch (Exception e) {
						Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
						// Send FIN
						closeLocal(msg.getIdChannel());
					}
				}
				else if (msg.fin()) { // End SubChannel
					Log.info(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
					MuxClientLocal local;
					synchronized(mapLocals) {
						local = mapLocals.remove(msg.getIdChannel());
					}
					if (local != null)
						local.setShutdown();
				}
				else if (msg.ack()) { // Flow-Control ACK
					Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
					MuxClientLocal local;
					synchronized(mapLocals) {
						local = mapLocals.get(msg.getIdChannel());
					}
					if (local != null)
						local.unlock(msg.ackSize());
				}
				else if (msg.nop()) { // NOP
					Log.info(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				}
				else { // Data
					Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
					try {
						MuxClientLocal local;
						synchronized(mapLocals) {
							local = mapLocals.get(msg.getIdChannel());
						}
						if (local == null)
							return;
						RawPacket raw = new RawPacket();
						raw.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
						local.sendLocal(raw);
					} catch (Exception e) {
						Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
					}
				}
			}
			synchronized void onReceiveFromLocal(MuxClientLocal local, RawPacket msg) { // Local is RAW
				Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
				try {
					local.lock(msg.getBufferLen());
					MuxPacket mux = new MuxPacket();
					mux.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
					remote.sendRemote(mux);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + "::onReceiveFromLocal " + e.toString(), e);
				}
			}
		}

		abstract class MuxClientConnection implements Shutdownable, Awaiter, Runnable { // Remote is MUX, Local is RAW
			OutboundAddress outboundAddress;
			Socket sock;
			InputStream is;
			OutputStream os;
			MuxClientMessageRouter router;
			boolean shutdown = false;
			//
			public MuxClientConnection(OutboundAddress outboundAddress) throws IOException {
				this.outboundAddress = outboundAddress;
			}
			public void setRouter(MuxClientMessageRouter router) {
				this.router = router;
			}
			@Override
			public void setShutdown() {
				shutdown = true;
				close();
			}
			public void close() {
				closeSilent(is);
				closeSilent(os);
				closeSilent(sock);
			}
		}

		class MuxClientRemote extends MuxClientConnection { // Remote is MUX
			//
			SealerAES seal = null;
			//
			public MuxClientRemote(OutboundAddress outboundAddress) throws Exception {
				super(outboundAddress);
				if (outboundAddress.getOpts().isOption(Options.MUX_AES)) {
					seal = new SealerAES(outboundAddress.getOpts().getString(Options.P_AES));
				}
			}
			public synchronized void sendRemote(MuxPacket msg) throws Exception {
				if (seal != null) {
					// AES encryption
					ByteArrayOutputStream baos = new ByteArrayOutputStream(BUFFER_LEN);
					msg.toWire(baos);
					byte[] encoded = seal.code(baos.toByteArray(), 0, baos.size());
					byte[] iv = seal.getCoder().getIV();
					IOHelper.toWireWithHeader(os, iv, iv.length);
					IOHelper.toWireWithHeader(os, encoded, encoded.length);
				}
				else {
					msg.toWire(os);
				}
			}
			@Override
			public void run() {
				while (!shutdown) {
					while (!shutdown) {
						try {
							Log.info(this.getClass().getSimpleName() + " Connecting: " + outboundAddress);
							outboundAddress.resolve();
							sock = outboundAddress.connect();
							if (sock == null)
								throw new ConnectException();
							is = sock.getInputStream();
							os = sock.getOutputStream();
							Log.info(this.getClass().getSimpleName() + " Connected: " + sock + " SendBufferSize=" + sock.getSendBufferSize() + " ReceiveBufferSize=" + sock.getReceiveBufferSize());
							break;
						}
						catch (Exception e) {
							if (sock != null)
								Log.error(this.getClass().getSimpleName() + " " + e.toString());
							close();
							sock = null;
							try { Thread.sleep(5000); } catch (Exception ign) {}
						}
					}
					while (!shutdown) {
						//
						MuxPacket msg = new MuxPacket();
						try {
							if (seal != null) {
								// AES encryption
								byte[] iv = IOHelper.fromWireWithHeader(is);
								byte[] encoded = IOHelper.fromWireWithHeader(is);
								byte[] decoded = seal.decode(iv, encoded, 0, encoded.length);
								ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
								msg.fromWire(bais);
							}
							else {
								msg.fromWire(is);
							}
							router.onReceiveFromRemote(this, msg);
						} catch (SocketTimeoutException e) {
							Log.debug(this.getClass().getSimpleName() + " " + e.toString());
							sendNOP();
							continue;
						} catch (EOFException e) {
							break;
						} catch (Exception e) {
							if (!sock.isClosed() && !shutdown) {
								if (e.getMessage().equals("Connection reset")) {
									Log.info(this.getClass().getSimpleName() + " " + e.toString());
								} else {
									Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
								}
							}
							break;
						}
					}
					// Close all
					close();
					synchronized(mapLocals) { // Locals are RAW
						for (MuxClientLocal l : mapLocals.values()) {
							l.setShutdown();
						}
						mapLocals.clear();
					}
					try { Thread.sleep(1000); } catch (Exception ign) {}
				}
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown(this);
				Log.info(this.getClass().getSimpleName() + " end");
			}
		}

		class MuxClientLocal extends MuxClientConnection { // Local is RAW
			int id;
			int isLocked = (BUFFER_LEN * OUTPUT_BUFFERS);
			final ArrayBlockingQueue<RawPacket> queue = new ArrayBlockingQueue<RawPacket>(OUTPUT_BUFFERS<<1);
			long keepalive = System.currentTimeMillis();
			//
			public MuxClientLocal(OutboundAddress outboundAddress) throws IOException {
				super(outboundAddress);
				outboundAddress.resolve();
				sock = outboundAddress.connect();
				if (sock == null)
					throw new ConnectException();
				is = sock.getInputStream();
				os = sock.getOutputStream();
				doTask(new Runnable() {
					@Override
					public void run() {
						while (!shutdown) {
							try {						
								RawPacket msg = queue.take();
								msg.toWire(os);
								sendACK(msg); // Send ACK
							} catch (Exception e) {
								Log.error(this.getClass().getSimpleName() + "::sendLocal " + e.toString(), e);
							}
						}
					}
				});
			}
			public void unlock(int size) {
				isLocked += size;
			}
			public void lock(int size) {
				isLocked -= size;
			}
			public boolean isLocked() {
				return (isLocked <= 0);
			}
			public void setId(int id) {
				this.id = id;
			}
			public void sendLocal(final RawPacket msg) throws IOException {
				try {
					queue.put(msg);
					keepalive = System.currentTimeMillis();
				} catch (InterruptedException e) {
					Log.error(this.getClass().getSimpleName() + "::sendLocal " + e.toString(), e);
				}
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
				while (!shutdown) {
					RawPacket msg = new RawPacket();
					try {
						//Log.info(this.getClass().getSimpleName() + "::run fromWire: " + sock);
						while (isLocked()) {
							try { Thread.sleep(1); } catch (Exception ign) {}
						}
						msg.fromWire(is);
						msg.setIdChannel(id);
						//Log.info(this.getClass().getSimpleName() + "::run onReceiveFromLocal: " + sock);
						router.onReceiveFromLocal(this, msg);
					} catch (SocketTimeoutException e) {
						Log.info(this.getClass().getSimpleName() + " " + e.toString());
						try {
							if ((System.currentTimeMillis() - keepalive) > sock.getSoTimeout()) {
								break;
							}
						} catch (Exception brk) {
							break;
						}
					} catch (EOFException e) {
						break;
					} catch (Exception e) {
						if (!sock.isClosed() && !shutdown) {
							if (e.getMessage().equals("Connection reset")) {
								Log.info(this.getClass().getSimpleName() + " " + e.toString());
							} else {
								Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
							}
						}
						break;
					}
				}
				// Send FIN
				closeLocal(id);
				close();
				Log.info(this.getClass().getSimpleName() + " end");
			}
		}
	}

	// ============================================ Mux Server

	// MuxServer (MUX=IN) Local=MUX, Remote=RAW
	class MuxServer {
		MuxServerMessageRouter router = new MuxServerMessageRouter();
		MuxServerListenLocal localListen;
		MuxServerListenRemote remoteListen;
		MuxServerLocal local = null;
		HashMap<Integer, MuxServerRemote> mapRemotes = new HashMap<Integer, MuxServerRemote>();
		//
		InboundAddress left;
		InboundAddress right;
		//
		MuxServer(InboundAddress left, InboundAddress right) {
			this.left = left;
			this.right = right;
		}
		//
		void listenLocal() throws IOException { // Entry Point
			localListen = new MuxServerListenLocal(left); // Local is MUX
			reloadables.add(localListen);
			doTask(localListen);
		}

		void listenRemote() throws IOException {
			remoteListen = new MuxServerListenRemote(right); // Remote is RAW
			reloadables.add(remoteListen);
			doTask(remoteListen);
		}
		void closeRemote(int id) {
			// Send FIN
			try {
				MuxPacket mux = new MuxPacket();
				mux.fin(id);
				local.sendLocal(mux);
			} catch (Exception ign) {
			}
			//
			synchronized(mapRemotes) {
				MuxServerRemote remote = mapRemotes.remove(id);
				if (remote != null) {
					remote.setShutdown();
				}
			}
		}
		void sendACK(RawPacket msg) {
			// Send ACK
			try {
				MuxPacket mux = new MuxPacket();
				mux.ack(msg.getIdChannel(), msg.getBufferLen());
				local.sendLocal(mux);
			} catch (Exception ign) {
			}
		}
		void sendNOP() {
			// Send NOP
			try {
				MuxPacket mux = new MuxPacket();
				mux.nop(0);
				local.sendLocal(mux);
			} catch (Exception ign) {
			}
		}

		class MuxServerMessageRouter {
			synchronized void onReceiveFromLocal(MuxServerLocal local, MuxPacket msg) { // Local is MUX
				//Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
				if (msg.syn()) { 
					// What?
				}
				else if (msg.fin()) { // End SubChannel
					Log.info(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
					MuxServerRemote remote;
					synchronized(mapRemotes) {
						remote = mapRemotes.remove(msg.getIdChannel());
					}
					if (remote != null)
						remote.setShutdown();
				}
				else if (msg.ack()) { // Flow-Control ACK
					Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
					MuxServerRemote remote;
					synchronized(mapRemotes) {
						remote = mapRemotes.get(msg.getIdChannel());
					}
					if (remote != null)
						remote.unlock(msg.ackSize());
				}
				else if (msg.nop()) { // NOP
					Log.info(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
				}
				else { // Data
					Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
					try {
						MuxServerRemote remote;
						synchronized(mapRemotes) {
							remote = mapRemotes.get(msg.getIdChannel());
						}
						if (remote == null)
							return;
						RawPacket raw = new RawPacket();
						raw.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
						remote.sendRemote(raw);
					} catch (Exception e) {
						Log.error(this.getClass().getSimpleName() + "::onReceiveFromLocal " + e.toString(), e);
					}
				}
			}
			synchronized void onReceiveFromRemote(MuxServerRemote remote, RawPacket msg) { // Remote is RAW
				Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				try {
					remote.lock(msg.getBufferLen());
					MuxPacket mux = new MuxPacket();
					mux.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
					local.sendLocal(mux);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
				}
			}
		}

		abstract class MuxServerListen implements Shutdownable, Awaiter, Runnable { // Local is MUX, Remote is RAW
			ServerSocket listen;
			boolean shutdown = false;
			InboundAddress inboundAddress;
			public MuxServerListen(InboundAddress inboundAddress) throws IOException {
				this.inboundAddress = inboundAddress;
				inboundAddress.resolve();
				listen = inboundAddress.listen();
			}
			@Override
			public void setShutdown() {
				shutdown = true;
				close();
			}
			public void close() {
				closeSilent(listen);
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run listen: " + listen);
				while (!shutdown) {
					try {
						Socket socket = listen.accept();
						setupSocket(socket);
						Integer pReadTimeout = inboundAddress.getOpts().getInteger(Options.P_READ_TIMEOUT);
						if (pReadTimeout != null) {
							socket.setSoTimeout(pReadTimeout.intValue());
						}
						if (socket instanceof SSLSocket) {
							((SSLSocket) socket).startHandshake();
						}
						Log.info(this.getClass().getSimpleName() + " new socket: " + socket + " SendBufferSize=" + socket.getSendBufferSize() + " ReceiveBufferSize=" + socket.getReceiveBufferSize());
						attender(socket);
					} catch (Exception e) {
						if (!shutdown)
							Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
						try { Thread.sleep(500); } catch (InterruptedException ign) {}
					}
				}
				close();
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown(this);
				Log.info(this.getClass().getSimpleName() + " end");
			}
			//
			protected abstract void attender(Socket socket) throws Exception;
		}

		class MuxServerListenLocal extends MuxServerListen { // Local is MUX
			public MuxServerListenLocal(InboundAddress inboundAddress) throws IOException {
				super(inboundAddress);
			}
			@Override
			protected synchronized void attender(Socket socket) throws Exception {
				Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
				if (local == null) {
					local = new MuxServerLocal(socket, inboundAddress);
					local.setRouter(router);
					reloadables.add(local);
					listenRemote(); 
					doTask(local);
				}
				else {
					// Only one concurrent client, close the new connection
					closeSilent(socket);
				}
			}
		}

		class MuxServerListenRemote extends MuxServerListen { // Remote is RAW
			public MuxServerListenRemote(InboundAddress inboundAddress) throws IOException {
				super(inboundAddress);
			}
			@Override
			protected synchronized void attender(Socket socket) throws Exception {
				Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
				MuxServerRemote remote = new MuxServerRemote(socket, inboundAddress);
				remote.setRouter(router);
				mapRemotes.put(remote.getId(), remote);
				doTask(remote);
			}
		}

		abstract class MuxServerConnection implements Shutdownable, Awaiter, Runnable { // Local is MUX, Remote is RAW
			Socket sock;
			InboundAddress inboundAddress;
			InputStream is;
			OutputStream os;
			MuxServerMessageRouter router;
			boolean shutdown = false;
			//
			public MuxServerConnection(Socket sock, InboundAddress inboundAddress) throws IOException {
				this.sock = sock;
				this.inboundAddress = inboundAddress;
				is = sock.getInputStream();
				os = sock.getOutputStream();
			}
			public void setRouter(MuxServerMessageRouter router) {
				this.router = router;
			}
			@Override
			public void setShutdown() {
				shutdown = true;
				close();
			}
			public void close() {
				closeSilent(is);
				closeSilent(os);
				closeSilent(sock);
			}
		}

		class MuxServerLocal extends MuxServerConnection { // Local is MUX
			//
			SealerAES seal = null;
			//
			public MuxServerLocal(Socket sock, InboundAddress inboundAddress) throws Exception {
				super(sock, inboundAddress);
				if (inboundAddress.getOpts().isOption(Options.MUX_AES)) {
					seal = new SealerAES(inboundAddress.getOpts().getString(Options.P_AES));
				}
			}
			public synchronized void sendLocal(MuxPacket msg) throws Exception {
				if (seal != null) {
					// AES encryption
					ByteArrayOutputStream baos = new ByteArrayOutputStream(BUFFER_LEN);
					msg.toWire(baos);
					byte[] encoded = seal.code(baos.toByteArray(), 0, baos.size());
					byte[] iv = seal.getCoder().getIV();
					IOHelper.toWireWithHeader(os, iv, iv.length);
					IOHelper.toWireWithHeader(os, encoded, encoded.length);
				}
				else {
					msg.toWire(os);
				}
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
				while (!shutdown) {
					MuxPacket msg = new MuxPacket();
					try {
						if (seal != null) {
							// AES encryption
							byte[] iv = IOHelper.fromWireWithHeader(is);
							byte[] encoded = IOHelper.fromWireWithHeader(is);
							byte[] decoded = seal.decode(iv, encoded, 0, encoded.length);
							ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
							msg.fromWire(bais);
						}
						else {
							msg.fromWire(is);
						}
						router.onReceiveFromLocal(this, msg);
					} catch (SocketTimeoutException e) {
						Log.debug(this.getClass().getSimpleName() + " " + e.toString());
						sendNOP();
						continue;
					} catch (EOFException e) {
						break;
					} catch (Exception e) {
						if (!sock.isClosed() && !shutdown) {
							if (e.getMessage().equals("Connection reset")) {
								Log.info(this.getClass().getSimpleName() + " " + e.toString());
							} else {
								Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
							}
						}
						break;
					}
				}
				// Close all
				close();
				remoteListen.setShutdown();
				synchronized(mapRemotes) { // Remotes are RAW
					for (MuxServerRemote r : mapRemotes.values()) {
						r.setShutdown();
					}
					mapRemotes.clear();
				}
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown(this);
				Log.info(this.getClass().getSimpleName() + " end");
				local = null;
			}
		}

		class MuxServerRemote extends MuxServerConnection { // Remote is RAW
			int id;
			int isLocked = (BUFFER_LEN * OUTPUT_BUFFERS);
			final ArrayBlockingQueue<RawPacket> queue = new ArrayBlockingQueue<RawPacket>(OUTPUT_BUFFERS<<1);
			long keepalive = System.currentTimeMillis();
			//
			public MuxServerRemote(Socket sock, InboundAddress inboundAddress) throws IOException {
				super(sock, inboundAddress);
				id = sock.getPort();
				doTask(new Runnable() {
					@Override
					public void run() {
						while (!shutdown) {
							try {
								RawPacket msg = queue.take();
								msg.toWire(os);
								sendACK(msg); // Send ACK
							} catch (Exception e) {
								Log.error(this.getClass().getSimpleName() + "::sendRemote " + e.toString(), e);
							}
						}
					}
				});
			}
			public void unlock(int size) {
				isLocked += size;
			}
			public void lock(int size) {
				isLocked -= size;
			}
			public boolean isLocked() {
				return (isLocked <= 0);
			}
			public int getId() {
				return id;
			}
			public void sendRemote(final RawPacket msg) throws IOException {
				try {
					queue.put(msg);
					keepalive = System.currentTimeMillis();
				} catch (InterruptedException e) {
					Log.error(this.getClass().getSimpleName() + "::sendRemote " + e.toString(), e);
				}
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
				// Send SYN
				try {
					MuxPacket mux = new MuxPacket();
					mux.syn(id);
					local.sendLocal(mux);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
				}
				//
				while (!shutdown) {
					RawPacket msg = new RawPacket();
					try {
						while (isLocked()) {
							try { Thread.sleep(1); } catch (Exception ign) {}
						}
						msg.fromWire(is);
						msg.setIdChannel(id);
						router.onReceiveFromRemote(this, msg);
					} catch (SocketTimeoutException e) { 
						Log.info(this.getClass().getSimpleName() + " " + e.toString());
						try {
							if ((System.currentTimeMillis() - keepalive) > sock.getSoTimeout()) {
								break;
							}
						} catch (Exception brk) {
							break;
						}
					} catch (EOFException e) {
						break;
					} catch (Exception e) {
						if (!sock.isClosed() && !shutdown) {
							if (e.getMessage().equals("Connection reset")) {
								Log.info(this.getClass().getSimpleName() + " " + e.toString());
							} else {
								Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
							}
						}
						break;
					}
				}
				// Send FIN
				closeRemote(id);
				close();
				Log.info(this.getClass().getSimpleName() + " end");
			}
		}
	}

	// ============================================ Messages

	interface Message {
		public int getIdChannel();
		public int getBufferLen();
		public byte[] getBuffer();
		//
		public void put(int idChannel, int bufferLen, byte[] buffer);
		public void clear();
		public void fromWire(InputStream is) throws IOException;
		public void toWire(OutputStream os) throws IOException;
	}

	static class RawPacket implements Message {
		private int idChannel;
		private int payLoadLength = 0;
		private byte[] payload = new byte[BUFFER_LEN];
		//
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
		//
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
			Arrays.fill(payload, (byte)0);
		}
		//
		@Override
		public void toWire(final OutputStream os) throws IOException {
			os.write(payload, 0, payLoadLength);
			os.flush();
		}
		@Override
		public void fromWire(final InputStream is) throws IOException  {
			try {
				payLoadLength = is.read(payload, 0, payload.length);
				if (payLoadLength < 0) {
					throw new EOFException("EOF");
				}
			}
			catch (IOException e) {
				clear();
				throw e;
			}
		}
		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer();
			sb
			.append("RawPacket[")
			.append("id=").append(getIdChannel()).append(" ")
			.append("len=").append(getBufferLen())
			.append("]");
			//if (payLoadLength > 0) sb.append(new String(payload, 0, payLoadLength));
			return sb.toString();
		}
	}

	static class MuxPacket implements Message {
		private static final int payLoadLengthMAGIC = 0x69420000;
		private static final int MUX_SYN = 0x80000000;
		private static final int MUX_FIN = 0x40000000;
		private static final int MUX_ACK = 0x20000000;
		private static final int MUX_NOP = 0x10000000;
		private byte[] header = new byte[8];
		private int idChannel = 0; 			// 4 bytes (SYN/FIN/ACK/NOP flags in hi-nibble)
		private int payLoadLength = 0;		// 4 bytes (magic in hi-nibble)
		private byte[] payload = new byte[BUFFER_LEN];
		//
		public MuxPacket() {
			// Nothing
		}
		public MuxPacket(final int idChannel, final int payloadLength, final byte[] payload) {
			this.idChannel = idChannel & 0x00FFFFFF;
			this.payLoadLength = (payloadLength & 0xFFFF); // Limit to 64KB
			if ((payLoadLength > 0) && (payload != null)) {
				System.arraycopy(payload, 0, this.payload, 0, payloadLength);
			}
		}
		//
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
		//
		public void syn(final int idChannel) {
			this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_SYN);
			this.payLoadLength = 0;
		}
		public void fin(final int idChannel) {
			this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_FIN);
			this.payLoadLength = 0;
		}
		public void ack(final int idChannel, final int size) {
			this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_ACK);
			this.payLoadLength = size;
		}
		public void nop(final int idChannel) {
			this.idChannel = ((idChannel & 0x00FFFFFF) | MUX_NOP);
			this.payLoadLength = 0;
		}
		public boolean syn() {
			return ((idChannel & MUX_SYN) != 0);
		}
		public boolean fin() {
			return ((idChannel & MUX_FIN) != 0);
		}
		public boolean ack() {
			return ((idChannel & MUX_ACK) != 0);
		}
		public int ackSize() {
			if (((idChannel & MUX_ACK) != 0)) {
				return (payLoadLength & 0xFFFF);
			}
			return 0;
		}
		public boolean nop() {
			return ((idChannel & MUX_NOP) != 0);
		}
		//
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
			idChannel = 0;
			payLoadLength = 0;
			Arrays.fill(header, (byte)0);
			Arrays.fill(payload, (byte)0);
		}
		//
		@Override
		public void toWire(final OutputStream os) throws IOException  {
			IOHelper.intToByteArray(idChannel, header, 0);
			IOHelper.intToByteArray((payLoadLength | (payLoadLengthMAGIC & 0xFFFF0000)), header, 4);
			// write header
			os.write(header);
			// write payload
			if (!ack() && ((payLoadLength & 0xFFFF) > 0))
				os.write(payload, 0, payLoadLength);
			os.flush();
		}
		@Override
		public void fromWire(final InputStream is) throws IOException  {
			int len;
			// read header
			len = IOHelper.fullRead(is, header, header.length);
			if (len <= 0) {
				clear();
				throw new EOFException("EOF");
			}
			if (len != header.length) {
				final String err = "Invalid HEADER (expected: " + header.length + " readed: " + len + ")";
				clear();
				throw new IOException(err);
			}
			idChannel = IOHelper.intFromByteArray(header, 0);
			payLoadLength = IOHelper.intFromByteArray(header, 4);
			// Check payLoadLength
			if ((payLoadLength & 0xFFFF) > BUFFER_LEN) {
				final String err = "Invalid PayLoadLength (max expected: " + BUFFER_LEN + " readed: " + (payLoadLength & 0xFFFF) + ")";
				clear();
				throw new IOException(err);
			}
			// Check MAGIC
			if ((payLoadLength & 0xFFFF0000) != (payLoadLengthMAGIC & 0xFFFF0000)) {
				final String err = "Invalid MAGIC (expected: " + (payLoadLengthMAGIC & 0xFFFF0000) + " readed: " + (payLoadLength & 0xFFFF0000) + ")";
				clear();
				throw new IOException(err);
			}
			payLoadLength &= 0xFFFF; // Limit to 64KB
			// read payload
			if (!ack() && (payLoadLength > 0)) {
				len = IOHelper.fullRead(is, payload, payLoadLength);
				if (len != payLoadLength) {
					final String err = "Invalid PAYLOAD (expected: " + payLoadLength + " readed: " + len + ")";
					clear();
					throw new IOException(err);
				}
			}
		}
		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer();
			sb
			.append("MuxPacket[")
			.append("id=").append(getIdChannel()).append(" ")
			.append("len=").append(getBufferLen())
			.append("]");
			if (syn()) {
				sb.append("[SYN]");
			} else if (fin()) {
				sb.append("[FIN]");
			} else if (ack()) {
				sb.append("[ACK]");
			} else if (nop()) {
				sb.append("[NOP]");
			} else {
				//if (!ack() && (payLoadLength > 0)) sb.append(new String(payload, 0, payLoadLength));
			}
			return sb.toString();
		}
	}

	static class IOHelper {
		private static final int LENGTH_MAGIC = 0xA42C0000;
		//
		public static final int fullRead(final InputStream is, final byte[] buf, final int len) throws IOException {
			int readed;
			if (len > 0) {
				int total = 0;
				while (total < len) {
					readed = is.read(buf, total, len-total);
					if (readed < 0)
						break;
					total += readed;
				}
				return total;
			}
			return 0;
		}
		//
		public static final void intToByteArray(int v, byte[] buf, int offset) {
			buf[offset+0] = (byte)((v >> 24) & 0xFF);
			buf[offset+1] = (byte)((v >> 16) & 0xFF);
			buf[offset+2] = (byte)((v >> 8) & 0xFF);
			buf[offset+3] = (byte)((v >> 0) & 0xFF);
		}
		public static final int intFromByteArray(byte[] buf, int offset) {
			int v = 0;
			v |= ((((int)buf[offset+0]) & 0xFF) << 24);
			v |= ((((int)buf[offset+1]) & 0xFF) << 16);
			v |= ((((int)buf[offset+2]) & 0xFF) << 8);
			v |= ((((int)buf[offset+3]) & 0xFF) << 0);
			return v;
		}
		public static final void toWireWithHeader(OutputStream os, byte[] buf, int len) throws IOException {
			final byte[] header = new byte[4]; // Integer
			if (len > 0xFFFF) { // Limit to 64KB
				throw new IOException("Packet length overflow (" + len + ")");
			}
			intToByteArray((len & 0xFFFF) | LENGTH_MAGIC, header, 0);
			os.write(header, 0, header.length);
			os.write(buf, 0, len);
			os.flush();
		}
		public static final byte[] fromWireWithHeader(InputStream is) throws IOException {
			final byte[] header = new byte[4]; // Integer
			int readed = -1;
			readed = fullRead(is, header, header.length);
			if (readed <= 0) {
				throw new EOFException("EOF");
			}
			if (readed != header.length) {
				throw new IOException("Invalid HEADER");
			}
			int len = intFromByteArray(header, 0);
			if ((len & 0xFFFF0000) != LENGTH_MAGIC) {
				throw new IOException("Invalid MAGIC");
			}
			len &= 0xFFFF; // Limit to 64KB
			if (len > (BUFFER_LEN<<1)) {
				throw new IOException("Packet length overflow (" + len + ")");
			}
			final byte[] buf = new byte[len];
			readed = fullRead(is, buf, buf.length);
			if (readed != buf.length) {
				throw new IOException("Invalid BODY");
			}
			return buf;
		}
	}

	static class SealerAES {
		private static final int RESET_COUNTER = 0xFFFF; // 64K
		private static final int RESET_BYTES = 0xFFFFFF; // 16MB
		//
		final String key;
		//
		Cipher enc;
		Cipher dec;
		//
		byte[] ivEncoder = null;
		int resetCounter = 0;
		int resetLength = 0;
		//
		public SealerAES(final String key) throws Exception {
			this.key = key;
		}
		//
		private final Cipher init(final int cipherMode, final byte[] iv) throws Exception {
			final byte[] keyBuf = md128(key);
			final Cipher cip = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Blowfish, CTR, ISO10126PADDING
			cip.init(cipherMode, new SecretKeySpec(keyBuf, "AES"), new IvParameterSpec(iv));
			return cip;
		}
		private final byte[] md128(final String value) throws Exception {
			final MessageDigest md = MessageDigest.getInstance("SHA1");
			final byte data[] = md.digest(value.getBytes("UTF-8"));
			// For AES-128 we need 128bits of 160bits from SHA1
			final byte ret[] = new byte[128>>3];
			System.arraycopy(data, 0, ret, 0, ret.length);
			return ret;
		}
		private final Cipher getCoder() throws Exception {
			if (enc == null) {
				if (ivEncoder == null) {
					final SecureRandom rnd = new SecureRandom();
					long ts = System.currentTimeMillis();
					ivEncoder = rnd.generateSeed(128>>3);
					Log.info(this.getClass().getSimpleName() + ":" + this.hashCode() + " SecureRandom Seed Generated ts=" + (System.currentTimeMillis() - ts));
				}
				enc = init(Cipher.ENCRYPT_MODE, ivEncoder);
			}
			return enc; 
		}
		private final Cipher getDecoder(final byte[] iv) throws Exception {
			dec = init(Cipher.DECRYPT_MODE, iv);
			return dec;
		}
		public byte[] code(final byte[] buf, final int off, final int len) throws Exception {
			// Full Reset IV in XX iterations or ZZ bytes
			if ((resetCounter++ > RESET_COUNTER) || ((resetLength+=len) > RESET_BYTES)) {
				Log.info(this.getClass().getSimpleName() + ":" + this.hashCode() + " FULL RESET IV resetCounter=" + resetCounter + " resetLength=" + resetLength);
				resetCounter = 0;
				resetLength = 0;
				ivEncoder = null;
			}
			enc = null;
			byte[] encoded = getCoder().doFinal(buf, off, len);
			// Incremental Reset IV
			for (int i = 0; i < ivEncoder.length; i++) {
				ivEncoder[i] ^= encoded[i];
			}
			return encoded;
		}
		public byte[] decode(final byte[] iv, final byte[] buf, final int off, final int len) throws Exception {
			return getDecoder(iv).doFinal(buf, off, len);
		}
		public String toString() {
			return this.getClass().getSimpleName() + "("+key.hashCode()+") [coder=" + enc + ":decoder=" + dec + "]";
		}
	}

	static class SSLFactory {
		private final static char[] DEFAULT_PWD = "changeit".toCharArray();
		//
		private final KeyStore ks;
		private final SSLContext ctx;
		private final SSLParameters sslParams;
		//
		public SSLFactory(String priCert, String priKey, String pubCert) throws Exception {
			ks = initKeyStore(loadX509(priCert), loadPriKey(priKey), loadX509(pubCert));
			ctx = initSSLContext(ks);
			sslParams = setupSSLParams(ctx);
		}
		public SSLServerSocket createSSLServerSocket() throws IOException {
			SSLServerSocketFactory factory = ctx.getServerSocketFactory();
			SSLServerSocket listen = (SSLServerSocket) factory.createServerSocket();
			listen.setEnabledCipherSuites(sslParams.getCipherSuites());
			listen.setEnabledProtocols(sslParams.getProtocols());
			listen.setNeedClientAuth(true); // Force Request Client Certificate
			return listen;
		}
		public SSLSocket createSSLSocket() throws IOException {
			SSLSocketFactory factory = ctx.getSocketFactory();
			SSLSocket sock = (SSLSocket) factory.createSocket();
			sock.setEnabledCipherSuites(sslParams.getCipherSuites());
			sock.setEnabledProtocols(sslParams.getProtocols());
			return sock;
		}
		//
		static SSLParameters setupSSLParams(SSLContext ctx) {
			List<String> protos = new ArrayList<String>();
			protos.add("TLSv1");
			protos.add("SSLv3");
			List<String> suites = new ArrayList<String>();
			suites.add("TLS_RSA_WITH_AES_256_CBC_SHA");
			suites.add("TLS_RSA_WITH_AES_128_CBC_SHA");
			suites.add("SSL_RSA_WITH_3DES_EDE_CBC_SHA");
			suites.add("SSL_RSA_WITH_RC4_128_SHA");
			SSLParameters sslParams = ctx.getSupportedSSLParameters();
			protos.retainAll(Arrays.asList(sslParams.getProtocols()));
			suites.retainAll(Arrays.asList(sslParams.getCipherSuites()));
			sslParams.setProtocols(protos.toArray(new String[0]));
			sslParams.setCipherSuites(suites.toArray(new String[0]));
			return sslParams;
		}
		static PrivateKey loadPriKey(String fileName) throws Exception {
			PrivateKey key = null;
			InputStream is = null;
			try {
				is = fileName.getClass().getResourceAsStream("/" + fileName);
				BufferedReader br = new BufferedReader(new InputStreamReader(is));
				StringBuilder builder = new StringBuilder();
				boolean inKey = false;
				for (String line = br.readLine(); line != null; line = br.readLine()) {
					if (!inKey) {
						if (line.startsWith("-----BEGIN ") && line.endsWith(" PRIVATE KEY-----")) {
							inKey = true;
						}
						continue;
					}
					else {
						if (line.startsWith("-----END ") && line.endsWith(" PRIVATE KEY-----")) {
							inKey = false;
							break;
						}
						builder.append(line);
					}
				}
				//
				byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				key = kf.generatePrivate(keySpec);
			} finally {
				closeSilent(is);
			}
			return key;
		}
		static X509Certificate loadX509(String fileName) throws Exception {
			InputStream is = null;
			X509Certificate crt = null;
			try {
				is = fileName.getClass().getResourceAsStream("/" + fileName);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				crt = (X509Certificate)cf.generateCertificate(is);
			} finally {
				closeSilent(is);
			}
			return crt;
		}
		static KeyStore initKeyStore(X509Certificate priCert, PrivateKey priKey, X509Certificate pubCert) throws Exception {
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			ks.setCertificateEntry(pubCert.getSubjectX500Principal().getName(), pubCert);
			ks.setKeyEntry("private", priKey, DEFAULT_PWD, new Certificate[] { priCert });
			return ks;
		}
		static SSLContext initSSLContext(KeyStore ks) throws Exception {
			SSLContext ctx = SSLContext.getInstance("TLS");
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, DEFAULT_PWD);
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);
			ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			return ctx;
		}
	}

	// ============================================

	/**
	 * Simple logging wrapper (you want log4j/logback/slfj? easy to do!)
	 */
	static class Log {
		private final static SimpleDateFormat ISO8601DATEFORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		private static boolean isDebugEnabled = false;
		//
		static void enableDebug() {
			isDebugEnabled = true;
		}
		static boolean isDebug() {
			return isDebugEnabled;
		}
		static String getTimeStamp() {
			synchronized(ISO8601DATEFORMAT) {
				return ISO8601DATEFORMAT.format(new Date());
			}
		}
		static void debug(final String str) {
			if (isDebugEnabled) {
				System.out.println(getTimeStamp() + " [DEBUG] " + "[" + Thread.currentThread().getName() + "] " + str);
			}
		}
		static void info(final String str) {
			System.out.println(getTimeStamp() + " [INFO] " + "[" + Thread.currentThread().getName() + "] " + str);
		}
		static void error(final String str) {
			System.out.println(getTimeStamp() + " [ERROR] " + "[" + Thread.currentThread().getName() + "] " + str);
		}
		static void error(final String str, final Throwable t) {
			System.out.println(getTimeStamp() + " [ERROR] " + "[" + Thread.currentThread().getName() + "] " + str);
			t.printStackTrace(System.out);
		}
	}

}
