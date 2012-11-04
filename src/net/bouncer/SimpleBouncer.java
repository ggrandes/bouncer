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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

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
	public static final double VERSION = 1.0;
	//
	private static final int BUFFER_LEN = 4096; 		// Default 4k page
	private static final int READ_TIMEOUT = 300000;		// Default 5min timeout
	private static final String CONFIG_FILE = "/bouncer.conf";
	// Load Balancing Policies
	private static final int LB_ORDER 	= 0x00000000; 	// Original order, pick next only on error
	private static final int LB_RR 		= 0x00000001;	// Round robin
	private static final int LB_RAND 	= 0x00000002;	// Random pick
	private static final int TUN_SSL	= 0x00000010;	// Client is Plain, Remote is SSL (like stunnel)
	//
	@SuppressWarnings("serial")
	private final static Map<String, Integer> MAP_OPTIONS = Collections.unmodifiableMap(new HashMap<String, Integer>() {
		{
			put("LB=ORDER", LB_ORDER);
			put("LB=RR", LB_RR);
			put("LB=RAND", LB_RAND);
			put("TUN=SSL", TUN_SSL);
		}
	});
	//
	private boolean running = true;

	public static void main(final String[] args) throws Exception {
		final SimpleBouncer bouncer = new SimpleBouncer();
		//
		if (Boolean.getBoolean("DEBUG"))
			Log.enableDebug(); // Enable debugging messages
		Log.info("Starting " + bouncer.getClass() + " version " + VERSION + (Log.isDebug() ? " debug-mode": ""));
		// Read config
		final InputStream isConfig = bouncer.getClass().getResourceAsStream(CONFIG_FILE);
		if (isConfig == null) {
			Log.error("Config not found: " + CONFIG_FILE);
			return;
		}
		final BufferedReader in = new BufferedReader(new InputStreamReader(isConfig));
		String line = null;
		try {
			while ((line = in.readLine()) != null) {
				// Skip comments
				if (line.trim().startsWith("#")) continue; 
				// Expected format (style rinetd):
				// <bind-addr> <bind-port> <remote-addr> <remote-port> [options]
				final String[] toks = line.split("( |\t)+"); 
				// Invalid number of params
				if (toks.length < 4) { 
					Log.error("Invalid config line: " + line);
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
				final int opts = parseOptions(options);
				//
				Log.info("Readed bind-addr=" + bindaddr + " bind-port=" + bindport + " remote-addr=" + remoteaddr + " remote-port=" + remoteport + " options("+opts+")={" + printableOptions(options) + "}");
				InetSocketAddress listen = new InetSocketAddress(bindaddr, bindport); 
				Destination dst = new Destination(remoteaddr, remoteport, opts);
				bouncer.bounce(listen, dst);
			}
		} finally {
			closeSilent(in);
			closeSilent(isConfig);
		}
	}

	/**
	 * Return options in numeric form (bitwise-flags)
	 * @param string to parse
	 * @return int with enabled flags
	 */
	static int parseOptions(final String str) {
		final String[] opts = str.toUpperCase().split(",");
		int ret = 0;
		for (String opt : opts) {
			final Integer i = MAP_OPTIONS.get(opt);
			if (i != null) {
				ret |= i.intValue();
			}
		}
		return ret;
	}

	/**
	 * For humans, return options parsed/validated
	 * @param string to parse
	 * @return human readable string
	 */
	static String printableOptions(final String str) {
		final String[] opts = str.toUpperCase().split(",");
		final StringBuilder sb = new StringBuilder();
		int i = 0;
		for (String opt : opts) {
			if (MAP_OPTIONS.containsKey(opt)) {
				if (i > 0) sb.append(",");
				sb.append(opt);
				i++;
			}
		}
		return sb.toString();
	}

	/**
	 * Start a bouncer
	 * @param bind where to listen
	 * @param dst where to connect
	 */
	void bounce(final InetSocketAddress bind, final Destination dst) {
		try {
			Log.info("Bouncing from " + bind + " to " + dst);
			ServerSocket listen = new ServerSocket();
			setupSocket(listen);
			listen.bind(bind);
			new Thread(new Acceptator(listen, dst)).start();
		} catch (IOException e) {
			Log.error("Error trying to bounce from " + bind + " to " + dst, e);
		}
	}

	static void closeSilent(final Reader ir) {
		try { ir.close(); } catch(Exception ign) {}
	}
	static void closeSilent(final InputStream is) {
		try { is.close(); } catch(Exception ign) {}
	}
	static void closeSilent(final OutputStream os) {
		try { os.flush(); } catch(Exception ign) {}
		try { os.close(); } catch(Exception ign) {}
	}
	static void closeSilent(final Socket sock) {
		try { sock.close(); } catch(Exception ign) {}
	}

	static void setupSocket(final ServerSocket sock) throws SocketException {
		sock.setReuseAddress(true);
	}
	static void setupSocket(final Socket sock) throws SocketException {
		sock.setKeepAlive(true);
		sock.setReuseAddress(true);
		sock.setSoTimeout(READ_TIMEOUT); // SocketTimeoutException 
	}

	/**
	 * Representation of remote destination
	 */
	static class Destination {
		//
		int roundrobin = 0;
		int opts = 0;
		//
		final String host;
		final int port;
		InetAddress[] addrs = null;
		//
		Destination(final String host, final int port, final int opts) {
			this.host = host;
			this.port = port;
			this.opts = opts;
		}
		public String toString() {
			return host + ":" + port;
		}
		String fromArrAddress(final InetAddress[] addrs) {
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < addrs.length; i++) {
				InetAddress addr = addrs[i];
				if (i > 0) sb.append(",");
				sb.append(addr.getHostAddress());
			}
			return sb.toString();
		}
		void resolve() throws UnknownHostException {
			addrs = InetAddress.getAllByName(host);
			Log.info("Resolved host=" + host + " [" + fromArrAddress(addrs) + "]");
		}
		Socket connect() {
			if (addrs == null) {
				return null;
			}
			final boolean isSSL = ((opts & TUN_SSL) != 0);
			Socket remote = null;
			switch (opts & 0x0F) {
			case LB_ORDER:
				for (InetAddress addr : addrs) {
					remote = connect(addr, isSSL);
					if (remote != null) break;
				}
				break;
			case LB_RR:
				final int rrbegin = roundrobin;
				do {
					remote = connect(addrs[roundrobin++], isSSL);
					roundrobin %= addrs.length;
					if (remote != null) break;
				} while (roundrobin != rrbegin);
				break;
			case LB_RAND:
				final Random r = new Random();
				remote = connect(addrs[(r.nextInt(Integer.MAX_VALUE) % addrs.length)], isSSL);
				break;
			}
			return remote;
		}
		Socket connect(final InetAddress addr, final boolean isSSL) {
			Socket sock = null;
			try {
				Log.info("Connecting to " + addr + ":" + port + (isSSL? " (SSL)": ""));
				if (isSSL) {
					SocketFactory factory = SSLSocketFactory.getDefault();
					sock = factory.createSocket(addr.getHostAddress(), port);
				}
				else {
					sock = new Socket(addr, port);
				}
			} catch (IOException e) {
				Log.error("Error connecting to " + addr + ":" + port + (isSSL? " (SSL)": ""), e);
			}
			return sock;
		}
	}

	/**
	 * Listen socket & Accept connections
	 */
	class Acceptator implements Runnable {
		final ServerSocket listen;
		final Destination dst;
		Acceptator(final ServerSocket listen, final Destination dst) {
			this.listen = listen;
			this.dst = dst;
		}
		public void run() {
			try {
				while (running) {
					Socket client = listen.accept();
					setupSocket(client);
					Log.info("New client from=" + client);
					new Thread(new Connector(client, dst)).start();
				}
			}
			catch(Exception e) {
				Log.error("Acceptator: Generic exception", e);
			}
		}
	}

	/**
	 * Connector between Client and Destination
	 */
	class Connector implements Runnable {
		final Socket sock;
		final Destination dst;
		Connector(Socket sock, Destination dst) {
			this.sock = sock;
			this.dst = dst;
		}
		public void run() {
			InputStream client_is = null;
			OutputStream client_os = null;
			Socket remote = null;
			OutputStream remote_os = null;
			InputStream remote_is = null;
			try {
				// Remote
				dst.resolve();
				remote = dst.connect();
				setupSocket(remote);
				remote_os = remote.getOutputStream();
				remote_is = remote.getInputStream();
				// Client
				client_is = sock.getInputStream();
				client_os = sock.getOutputStream();
				// Process
				final SocketTransfer trCliRem = new SocketTransfer(sock, client_is, remote_os);
				final SocketTransfer trRemCli = new SocketTransfer(remote, remote_is, client_os);
				final Thread thCliRem = new Thread(trCliRem);
				final Thread thRemCli = new Thread(trRemCli);
				thCliRem.start();
				thRemCli.start();
				// Wait for ending...
				while (thCliRem.isAlive() && thRemCli.isAlive()) {
					if (Log.isDebug())
						Log.debug("Waiting to... cli->rem=" + thCliRem.isAlive() + " rem->cli=" + thRemCli.isAlive() + " sockcli=" + sock + " sockrem=" + remote);
					Thread.sleep(1000);
				}
				int doWait = 3;
				while (thRemCli.isAlive() && (doWait-- > 0)) {
					if (Log.isDebug())
						Log.debug("Waiting to... cli->rem=" + thCliRem.isAlive() + " rem->cli=" + thRemCli.isAlive() + " sockcli=" + sock + " sockrem=" + remote);
					Thread.sleep(1000);
				}
				// Mark Shutdown
				trCliRem.setShutdown();
				trRemCli.setShutdown();
			}
			catch(UnknownHostException e) {
				Log.error(e.toString());
			}
			catch(Exception e) {
				Log.error("Connector: Generic exception", e);
			}
			finally {
				// Close all
				closeSilent(client_is);
				closeSilent(remote_is);
				closeSilent(client_os);
				closeSilent(remote_os);
				closeSilent(sock);
				closeSilent(remote);
			}
		}
	}

	/**
	 * Transfer data between sockets
	 */
	class SocketTransfer implements Runnable {
		final byte[] buf = new byte[BUFFER_LEN];
		final Socket sockin;
		final InputStream is;
		final OutputStream os;
		volatile boolean shutdown = false;
		SocketTransfer(final Socket sockin, final InputStream is, final OutputStream os) {
			this.sockin = sockin;
			this.is = is;
			this.os = os;
		}
		public void setShutdown() {
			shutdown = true;
		}
		public void run() {
			try {
				while (transfer()) {
					// continue;
				}
			} catch (IOException e) {
				if (!sockin.isClosed() && !shutdown) {
					Log.error("SocketTransfer: " + e.toString() + " " + sockin);
				}
			} finally {
				Log.info("Connection closed " + sockin);
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
				System.out.println(getTimeStamp() + " [DEBUG] " + str);
			}
		}
		static void info(final String str) {
			System.out.println(getTimeStamp() + " [INFO] " + str);
		}
		static void error(final String str) {
			System.err.println(getTimeStamp() + " [ERROR] " + str);

		}
		static void error(final String str, final Throwable t) {
			System.err.println(getTimeStamp() + " [ERROR] " + str);
			t.printStackTrace(System.err);
		}
	}
}
