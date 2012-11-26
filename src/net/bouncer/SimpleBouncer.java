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
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
	public static final String VERSION = "1.3beta1";
	//
	private static final int BUFFER_LEN = 4096; 		// Default 4k page
	private static final int OUTPUT_BUFFERS = 3;
	private static final int CONNECT_TIMEOUT = 30000;	// Default 30seconds timeout
	private static final int READ_TIMEOUT = 300000;		// Default 5min timeout
	private static final long RELOAD_CONFIG = 10000;	// Default 10seconds
	private static final String CONFIG_FILE = "/bouncer.conf";
	// Load Balancing Policies
	private static final int LB_ORDER 	= 0x00000000; 	// Original order, pick next only on error
	private static final int LB_RR 		= 0x00000001;	// Round robin
	private static final int LB_RAND 	= 0x00000002;	// Random pick
	private static final int TUN_SSL	= 0x00000010;	// Client is Plain, Remote is SSL (like stunnel)
	private static final int MUX_OUT	= 0x00000100;	// Multiplexor initiator (outbound)
	private static final int MUX_IN		= 0x00000200;	// Multiplexor terminator (inbound)
	//
	@SuppressWarnings("serial")
	private final static Map<String, Integer> MAP_OPTIONS = Collections.unmodifiableMap(new HashMap<String, Integer>() {
		{
			put("LB=ORDER", LB_ORDER);
			put("LB=RR", LB_RR);
			put("LB=RAND", LB_RAND);
			put("TUN=SSL", TUN_SSL);
			put("MUX=OUT", MUX_OUT);
			put("MUX=IN", MUX_IN);
		}
	});
	// For graceful reload
	private List<Awaiter> reloadables = Collections.synchronizedList(new ArrayList<Awaiter>());
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
					Log.info(this.getClass().getSimpleName() + " New client from=" + client);
					notify(new EventNewSocket(this, client));
				}
			}
			catch(UnknownHostException e) {
				Log.error(this.getClass().getSimpleName() + " " + e.toString());
			}
			catch(Exception e) {
				if (!listen.isClosed()) {
					Log.error(this.getClass().getSimpleName() + " Generic exception", e);
				}
			}
			finally {
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown();
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
			catch(UnknownHostException e) {
				Log.error(this.getClass().getSimpleName() + " " + e.toString());
			}
			catch(Exception e) {
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
				threadPool.submit(connection);
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
					threadPool.submit(new PlainSocketTransfer(client, remote));
					threadPool.submit(new PlainSocketTransfer(remote, client));
				} catch (IOException e) {
					Log.error(this.getClass().getSimpleName() + "::event IOException", e);
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
		PlainSocketTransfer(final Socket sockin, final Socket sockout) throws IOException {
			this.sockin = sockin;
			this.sockout = sockout;
			this.is = sockin.getInputStream();
			this.os = sockout.getOutputStream();
		}
		@Override
		public void setShutdown() {
			shutdown = true;
		}
		@Override
		public void run() {
			try {
				while (transfer()) {
					// continue;
				}
			} catch (IOException e) {
				try {
					if ((sockin instanceof SSLSocket) && (!sockin.isClosed())) {
						Thread.sleep(100);
					}
				} catch(Exception ign) {}
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

	void awaitShutdown() {
		if (shutdownBarrier != null) {
			try {
				shutdownBarrier.await();
			} catch (Exception ign) {}
		}
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
			awaitShutdown();
			Log.info(this.getClass().getSimpleName() + " Shutdown completed");
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
				final int opts = parseOptions(options);
				//
				Log.info(this.getClass().getSimpleName() + " Readed bind-addr=" + bindaddr + " bind-port=" + bindport + " remote-addr=" + remoteaddr + " remote-port=" + remoteport + " options("+opts+")={" + printableOptions(options) + "}");
				start(bindaddr, bindport, remoteaddr, remoteport, opts);
			}
		} finally {
			closeSilent(in);
			closeSilent(isConfig);
		}
	}

	static boolean isOption(final int opt, final int FLAG) {
		return ((opt & FLAG) != 0);
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

	void start(final String leftaddr, final int leftport, final String rightaddr, final int rightport, final int opts) {
		BouncerAddress eleft = null, eright = null;
		try {
			if (isOption(opts, MUX_IN)) {
				InboundAddress left = new InboundAddress(leftaddr, leftport, opts); // MUX
				InboundAddress right = new InboundAddress(rightaddr, rightport, opts); // PLAIN
				eleft = left;
				eright = right;
				new MuxServer(left, right).listenLocal();
			}
			else if (isOption(opts, MUX_OUT)) {
				OutboundAddress left = new OutboundAddress(leftaddr, leftport, opts); // PLAIN
				OutboundAddress right = new OutboundAddress(rightaddr, rightport, opts); // MUX
				eleft = left;
				eright = right;
				new MuxClient(left, right).openRemote();
			}
			else {
				InboundAddress left = new InboundAddress(leftaddr, leftport, opts); // PLAIN
				OutboundAddress right = new OutboundAddress(rightaddr, rightport, opts); // PLAIN
				eleft = left;
				eright = right;
				RinetdStyleAdapterLocal redir = new RinetdStyleAdapterLocal(right);
				GenericAcceptator acceptator = new GenericAcceptator(left, redir);
				reloadables.add(acceptator);
				threadPool.submit(acceptator);
			}
		} catch (Exception e) {
			Log.error(this.getClass().getSimpleName() + " Error trying to bounce from " + eleft + " to " + eright, e);
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
	static void closeSilent(final ServerSocket sock) {
		try { sock.close(); } catch(Exception ign) {}
	}

	static void setupSocket(final ServerSocket sock) throws SocketException {
		sock.setReuseAddress(true);
	}
	static void setupSocket(final Socket sock) throws SocketException {
		sock.setKeepAlive(true);
		sock.setReuseAddress(true);
		sock.setSoTimeout(READ_TIMEOUT); // SocketTimeoutException
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
		int opts = 0;
		//
		final String host;
		final int port;
		InetAddress[] addrs = null;
		//
		InboundAddress(final String host, final int port, final int opts) {
			this.host = host;
			this.port = port;
			this.opts = opts;
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
			ServerSocket listen = new ServerSocket();
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
		int opts = 0;
		//
		final String host;
		final int port;
		InetAddress[] addrs = null;
		//
		OutboundAddress(final String host, final int port, final int opts) {
			this.host = host;
			this.port = port;
			this.opts = opts;
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
			if (remote != null) {
				try {
					setupSocket(remote);
				} catch (SocketException e) {
					Log.error(this.getClass().getSimpleName() + " Error setting parameters to socket: " + remote);
				}
			}
			return remote;
		}
		Socket connect(final InetAddress addr, final boolean isSSL) {
			Socket sock = null;
			try {
				Log.info(this.getClass().getSimpleName() + " Connecting to " + addr + ":" + port + (isSSL? " (SSL)": ""));
				if (isSSL) {
					SocketFactory factory = SSLSocketFactory.getDefault();
					sock = factory.createSocket();
				}
				else {
					sock = new Socket();
				}
				sock.connect(new InetSocketAddress(addr, port), CONNECT_TIMEOUT); 
			} catch(SocketTimeoutException e) {
				Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port + (isSSL? " (SSL) ": " ") + e.toString());
			} catch(ConnectException e) {
				Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port + (isSSL? " (SSL) ": " ") + e.toString());
			} catch (IOException e) {
				Log.error(this.getClass().getSimpleName() + " Error connecting to " + addr + ":" + port + (isSSL? " (SSL)": ""), e);
			}
			if ((sock != null) && sock.isConnected()) {
				Log.info(this.getClass().getSimpleName() + " Connected to " + addr + ":" + port + (isSSL? " (SSL)": ""));
				return sock;
			}
			return null;
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

		void openRemote() throws IOException { // Entry Point
			Log.info(this.getClass().getSimpleName() + "::openRemote " + right);
			remote = new MuxClientRemote(right);
			remote.setRouter(router);
			threadPool.submit(remote);
		}

		void openLocal(int id) throws IOException {
			Log.info(this.getClass().getSimpleName() + "::openLocal id=" + id);
			MuxClientLocal local = new MuxClientLocal(left);
			local.setId(id);
			local.setRouter(router);
			synchronized(mapLocals) {
				mapLocals.put(id, local);
			}
			threadPool.submit(local);
		}
		void closeLocal(int id) {
			// Send FIN
			try {
				MuxPacket mux = new MuxPacket();
				mux.fin(id);
				remote.sendRemote(mux);
			} catch (IOException ign) {
			}
			//
			synchronized(mapLocals) {
				MuxClientLocal local = mapLocals.remove(id);
				if (local != null) {
					local.close();
				}
			}
		}
		void sendACK(RawPacket msg) {
			// Send ACK
			try {
				MuxPacket mux = new MuxPacket();
				mux.ack(msg.getIdChannel(), msg.getBufferLen());
				remote.sendRemote(mux);
			} catch (IOException ign) {
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
					} catch (IOException e) {
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
						local.close();
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
					} catch (IOException e) {
						Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
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
				} catch (IOException e) {
					Log.error(this.getClass().getSimpleName() + "::onReceiveFromLocal " + e.toString(), e);
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
				closeSilent(is);
				closeSilent(os);
				closeSilent(sock);
			}
			public void close() {
				setShutdown();
			}
		}

		class MuxClientRemote extends MuxClientConnection { // Remote is MUX
			public MuxClientRemote(OutboundAddress outboundAddress) throws IOException {
				super(outboundAddress);
			}
			public void sendRemote(MuxPacket msg) throws IOException {
				msg.toWire(os);
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
							closeSilent(is);
							closeSilent(os);
							closeSilent(sock);
							sock = null;
							try { Thread.sleep(5000); } catch(Exception ign) {}
						}
					}
					while (!shutdown) {
						//
						MuxPacket msg = new MuxPacket();
						try {
							msg.fromWire(is);
							router.onReceiveFromRemote(this, msg);
						} catch (SocketTimeoutException e) {
							Log.info(this.getClass().getSimpleName() + " " + e.toString());
							continue;
						} catch (EOFException e) {
							break;
						} catch (IOException e) {
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
							l.close();
						}
						mapLocals.clear();
					}
				}
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown();
				Log.info(this.getClass().getSimpleName() + " end");
			}
		}

		class MuxClientLocal extends MuxClientConnection { // Local is RAW
			int id;
			int isLocked = (BUFFER_LEN * OUTPUT_BUFFERS);
			final ArrayBlockingQueue<RawPacket> queue = new ArrayBlockingQueue<RawPacket>(OUTPUT_BUFFERS<<1);
			//
			public MuxClientLocal(OutboundAddress outboundAddress) throws IOException {
				super(outboundAddress);
				outboundAddress.resolve();
				sock = outboundAddress.connect();
				if (sock == null)
					throw new ConnectException();
				is = sock.getInputStream();
				os = sock.getOutputStream();
				threadPool.submit(new Runnable() {
					@Override
					public void run() {
						while (!shutdown) {
							try {						
								RawPacket msg = queue.take();
								msg.toWire(os);
								sendACK(msg); // Send ACK
							} catch (IOException e) {
								Log.error(this.getClass().getSimpleName() + "::sendLocal " + e.toString(), e);
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
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
				while (!shutdown) {
					RawPacket msg = new RawPacket();
					try {
						//Log.info(this.getClass().getSimpleName() + "::run fromWire: " + sock);
						while (isLocked()) {
							try { Thread.sleep(1); } catch(Exception ign) {}
						}
						msg.fromWire(is);
						msg.setIdChannel(id);
						//Log.info(this.getClass().getSimpleName() + "::run onReceiveFromLocal: " + sock);
						router.onReceiveFromLocal(this, msg);
					} catch (EOFException e) {
						break;
					} catch (IOException e) {
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
			threadPool.submit(localListen);
		}

		void listenRemote() throws IOException {
			remoteListen = new MuxServerListenRemote(right); // Remote is RAW
			reloadables.add(remoteListen);
			threadPool.submit(remoteListen);
		}
		void closeRemote(int id) {
			// Send FIN
			try {
				MuxPacket mux = new MuxPacket();
				mux.fin(id);
				local.sendLocal(mux);
			} catch (IOException ign) {
			}
			//
			synchronized(mapRemotes) {
				MuxServerRemote remote = mapRemotes.remove(id);
				if (remote != null) {
					remote.close();
				}
			}
		}
		void sendACK(RawPacket msg) {
			// Send ACK
			try {
				MuxPacket mux = new MuxPacket();
				mux.ack(msg.getIdChannel(), msg.getBufferLen());
				local.sendLocal(mux);
			} catch (IOException ign) {
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
						remote.close();
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
					} catch (IOException e) {
						Log.error(this.getClass().getSimpleName() + "::onReceiveFromLocal " + e.toString(), e);
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
				} catch (IOException e) {
					Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
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
				inboundAddress.resolve();
				listen = inboundAddress.listen();
			}
			@Override
			public void setShutdown() {
				shutdown = true;
				closeSilent(listen);
			}
			public void close() {
				setShutdown();
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run listen: " + listen);
				while (!shutdown) {
					try {
						Socket socket = listen.accept();
						setupSocket(socket);
						Log.info(this.getClass().getSimpleName() + " new socket: " + socket + " SendBufferSize=" + socket.getSendBufferSize() + " ReceiveBufferSize=" + socket.getReceiveBufferSize());
						attender(socket);
					} catch (IOException e) {
						if (!shutdown)
							Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
						try { Thread.sleep(500); } catch(InterruptedException ign) {}
					}
				}
				close();
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown();
				Log.info(this.getClass().getSimpleName() + " end");
			}
			//
			protected abstract void attender(Socket socket) throws IOException;
		}

		class MuxServerListenLocal extends MuxServerListen { // Local is MUX
			public MuxServerListenLocal(InboundAddress inboundAddress) throws IOException {
				super(inboundAddress);
			}
			@Override
			protected synchronized void attender(Socket socket) throws IOException {
				Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
				if (local == null) {
					local = new MuxServerLocal(socket);
					local.setRouter(router);
					reloadables.add(local);
					listenRemote(); 
					// Solo puede haber un cliente, asi que bloqueamos este thread
					//local.run();
					threadPool.submit(local);
				}
				else {
					// Solo puede haber un cliente, asi que cerramos esa conexion
					closeSilent(socket);
				}
			}
		}

		class MuxServerListenRemote extends MuxServerListen { // Remote is RAW
			public MuxServerListenRemote(InboundAddress inboundAddress) throws IOException {
				super(inboundAddress);
			}
			@Override
			protected synchronized void attender(Socket socket) throws IOException {
				Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
				MuxServerRemote remote = new MuxServerRemote(socket);
				remote.setRouter(router);
				mapRemotes.put(remote.getId(), remote);
				threadPool.submit(remote);
			}
		}

		abstract class MuxServerConnection implements Shutdownable, Awaiter, Runnable { // Local is MUX, Remote is RAW
			Socket sock;
			InputStream is;
			OutputStream os;
			MuxServerMessageRouter router;
			boolean shutdown = false;
			//
			public MuxServerConnection(Socket sock) throws IOException {
				this.sock = sock;
				is = sock.getInputStream();
				os = sock.getOutputStream();
			}
			public void setRouter(MuxServerMessageRouter router) {
				this.router = router;
			}
			@Override
			public void setShutdown() {
				shutdown = true;
				closeSilent(is);
				closeSilent(os);
				closeSilent(sock);
			}
			public void close() {
				setShutdown();
			}
		}

		class MuxServerLocal extends MuxServerConnection { // Local is MUX
			//
			public MuxServerLocal(Socket sock) throws IOException {
				super(sock);
			}
			public void sendLocal(MuxPacket msg) throws IOException {
				msg.toWire(os);
			}
			@Override
			public void run() {
				Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
				while (!shutdown) {
					MuxPacket msg = new MuxPacket();
					try {
						msg.fromWire(is);
						router.onReceiveFromLocal(this, msg);
					} catch (SocketTimeoutException e) {
						Log.info(this.getClass().getSimpleName() + " " + e.toString());
						continue;
					} catch (EOFException e) {
						break;
					} catch (IOException e) {
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
				remoteListen.close();
				synchronized(mapRemotes) { // Remotes are RAW
					for (MuxServerRemote r : mapRemotes.values()) {
						r.close();
					}
					mapRemotes.clear();
				}
				Log.info(this.getClass().getSimpleName() + " await end");
				awaitShutdown();
				Log.info(this.getClass().getSimpleName() + " end");
				local = null;
			}
		}

		class MuxServerRemote extends MuxServerConnection { // Remote is RAW
			int id;
			int isLocked = (BUFFER_LEN * OUTPUT_BUFFERS);
			final ArrayBlockingQueue<RawPacket> queue = new ArrayBlockingQueue<RawPacket>(OUTPUT_BUFFERS<<1);
			//
			public MuxServerRemote(Socket sock) throws IOException {
				super(sock);
				id = sock.getPort();
				threadPool.submit(new Runnable() {
					@Override
					public void run() {
						while (!shutdown) {
							try {
								RawPacket msg = queue.take();
								msg.toWire(os);
								sendACK(msg); // Send ACK
							} catch (IOException e) {
								Log.error(this.getClass().getSimpleName() + "::sendRemote " + e.toString(), e);
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
				} catch (IOException e) {
					Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
				}
				//
				while (!shutdown) {
					RawPacket msg = new RawPacket();
					try {
						while (isLocked()) {
							try { Thread.sleep(1); } catch(Exception ign) {}
						}
						msg.fromWire(is);
						msg.setIdChannel(id);
						router.onReceiveFromRemote(this, msg);
					} catch (EOFException e) {
						break;
					} catch (IOException e) {
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
			this.idChannel = (idChannel & 0x0FFFFFFF);
		}
		@Override
		public int getIdChannel() {
			return (idChannel & 0x0FFFFFFF);
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
			this.idChannel = (idChannel & 0x0FFFFFFF);
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
			catch(IOException e) {
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
		private byte[] header = new byte[8];
		private int idChannel = 0; 			// 4 bytes (SYN/FIN/ACK flags in hi-nibble)
		private int payLoadLength = 0;		// 4 bytes (magic in hi-nibble)
		private byte[] payload = new byte[BUFFER_LEN];
		//
		public MuxPacket() {
			// Nothing
		}
		public MuxPacket(final int idChannel, final int payloadLength, final byte[] payload) {
			this.idChannel = idChannel & 0x0FFFFFFF;
			this.payLoadLength = (payloadLength & 0xFFFF); // Limit to 64KB
			if ((payLoadLength > 0) && (payload != null)) {
				System.arraycopy(payload, 0, this.payload, 0, payloadLength);
			}
		}
		//
		@Override
		public int getIdChannel() {
			return (idChannel & 0x0FFFFFFF);
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
			this.idChannel = ((idChannel & 0x0FFFFFFF) | MUX_SYN);
			this.payLoadLength = 0;
		}
		public void fin(final int idChannel) {
			this.idChannel = ((idChannel & 0x0FFFFFFF) | MUX_FIN);
			this.payLoadLength = 0;
		}
		public void ack(final int idChannel, final int size) {
			this.idChannel = ((idChannel & 0x0FFFFFFF) | MUX_ACK);
			this.payLoadLength = size;
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
		//
		@Override
		public void put(final int idChannel, final int payloadLength, final byte[] payload) {
			this.idChannel = (idChannel & 0x0FFFFFFF);
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
			intToByteArray(idChannel, header, 0);
			intToByteArray((payLoadLength | (payLoadLengthMAGIC & 0xFFFF0000)), header, 4);
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
			len = fullRead(is, header, header.length);
			if (len < 0) {
				clear();
				throw new EOFException("EOF");
			}
			if (len != header.length) {
				final String err = "Invalid HEADER (expected: " + header.length + " readed: " + len + ")";
				clear();
				throw new IOException(err);
			}
			idChannel = intFromByteArray(header, 0);
			payLoadLength = intFromByteArray(header, 4);
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
				len = fullRead(is, payload, payLoadLength);
				if (len != payLoadLength) {
					final String err = "Invalid PAYLOAD (expected: " + payLoadLength + " readed: " + len + ")";
					clear();
					throw new IOException(err);
				}
			}
		}
		private final int fullRead(final InputStream is, final byte[] buf, final int len) throws IOException {
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
		private static final void intToByteArray(int v, byte[] buf, int offset) {
			buf[offset+0] = (byte)((v >> 24) & 0xFF);
			buf[offset+1] = (byte)((v >> 16) & 0xFF);
			buf[offset+2] = (byte)((v >> 8) & 0xFF);
			buf[offset+3] = (byte)((v >> 0) & 0xFF);
		}
		private static final int intFromByteArray(byte[] buf, int offset) {
			int v = 0;
			v |= ((((int)buf[offset+0]) & 0xFF) << 24);
			v |= ((((int)buf[offset+1]) & 0xFF) << 16);
			v |= ((((int)buf[offset+2]) & 0xFF) << 8);
			v |= ((((int)buf[offset+3]) & 0xFF) << 0);
			return v;
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
			} else {
				//if (!ack() && (payLoadLength > 0)) sb.append(new String(payload, 0, payLoadLength));
			}
			return sb.toString();
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
