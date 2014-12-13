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
package org.javastack.bouncer;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;

import javax.management.JMException;

import org.javastack.bouncer.GenericPool.GenericPoolFactory;
import org.javastack.bouncer.TaskManager.AuditableRunner;
import org.javastack.bouncer.jmx.BouncerStatistics;

/**
 * Simple TCP Bouncer
 * 
 * @author Guillermo Grandes / guillermo.grandes[at]gmail.com
 */
public class Bouncer implements ServerContext {
	private static final Timer timer = new Timer("scheduled-task", true);
	private static final GenericPoolFactory<ByteArrayOutputStream> byteArrayOutputStreamFactory = new GenericPoolFactory<ByteArrayOutputStream>() {
		@Override
		public ByteArrayOutputStream newInstance() {
			return new ByteArrayOutputStream(Constants.BUFFER_LEN);
		}
	};

	// For graceful reload
	private final Set<Awaiter> reloadables = Collections.synchronizedSet(new HashSet<Awaiter>());
	private final Set<Shutdownable> orderedShutdown = Collections
			.synchronizedSet(new HashSet<Shutdownable>());
	private CyclicBarrier shutdownBarrier = null;

	private final GenericPool<RawPacket> poolRaw = new GenericPool<RawPacket>(RawPacket.GENERIC_POOL_FACTORY,
			Constants.BUFFER_POOL_SIZE);
	private final GenericPool<MuxPacket> poolMux = new GenericPool<MuxPacket>(MuxPacket.GENERIC_POOL_FACTORY,
			Constants.BUFFER_POOL_SIZE);
	private final GenericPool<ByteArrayOutputStream> poolBAOS = new GenericPool<ByteArrayOutputStream>(
			byteArrayOutputStreamFactory, Constants.BUFFER_POOL_SIZE);
	private final TaskManager taskMgr = new TaskManager();
	private final SocketRegistrator socketRegistry = new SocketRegistrator();
	private CipherSuites cipherSuites = null;

	private final LinkedHashMap<String, MuxServer> muxServers = new LinkedHashMap<String, MuxServer>();
	private final LinkedHashMap<String, MuxClient> muxClients = new LinkedHashMap<String, MuxClient>();
	private final BouncerStatistics stats = new BouncerStatistics();

	// ============================== Global code

	public static void main(final String[] args) throws Exception {
		final Bouncer bouncer = new Bouncer();
		//
		// Init Log System
		if (Boolean.getBoolean("DEBUG")) {
			Log.enableDebug(); // Enable debugging messages
			Log.setMode(Log.LOG_ORIG_STDOUT);
		} else {
			// Redir STDOUT to File
			if (System.getProperty(Constants.PROP_OUT_FILE) != null)
				Log.redirStdOutLog(System.getProperty(Constants.PROP_OUT_FILE));
			// Redir STDERR to File
			if (System.getProperty(Constants.PROP_ERR_FILE) != null)
				Log.redirStdErrLog(System.getProperty(Constants.PROP_ERR_FILE));
			if (Boolean.getBoolean(Constants.PROP_OUT_STDTOO)) {
				Log.setMode(Log.LOG_CURR_STDOUT | Log.LOG_ORIG_STDOUT);
			} else {
				Log.setMode(Log.LOG_CURR_STDOUT);
			}
		}
		Log.info("Starting " + bouncer.getClass() + " version " + getVersion()
				+ (Log.isDebug() ? " debug-mode" : ""));
		// Register BouncyCastleProvider if possible
		try {
			final String bcName = "org.bouncycastle.jce.provider.BouncyCastleProvider";
			Security.addProvider((Provider) Class.forName(bcName).newInstance());
		} catch (Throwable t) {
			Log.warn("Unable to register BouncyCastleProvider: " + t.toString());
		}
		// Read config
		final URL urlConfig = bouncer.getClass().getResource(Constants.CONFIG_FILE);
		if (urlConfig == null) {
			Log.error("Config not found: (classpath)" + Constants.CONFIG_FILE);
			return;
		}
		// Start JMX
		bouncer.initJMX();
		// Schedule Statistics
		timer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				Log.info(bouncer.getStatistics().toString());
			}
		}, 1000, Constants.STATISTICS_PRINT_INTVL);
		long lastReloaded = 0;
		while (true) {
			InputStream isConfig = null;
			try {
				final URLConnection connConfig = urlConfig.openConnection();
				connConfig.setUseCaches(false);
				final long lastModified = connConfig.getLastModified();
				Log.debug("lastReloaded=" + lastReloaded + " getLastModified()="
						+ connConfig.getLastModified() + " currentTimeMillis()=" + System.currentTimeMillis());
				isConfig = connConfig.getInputStream();
				if (lastModified > lastReloaded) {
					if (lastReloaded > 0) {
						Log.info("Reloading config");
					}
					lastReloaded = lastModified;
					bouncer.reload(isConfig);
					Log.info("Reloaded config");
				}
			} catch (Exception e) {
				Log.error("Load config error", e);
			} finally {
				IOHelper.closeSilent(isConfig);
			}
			doSleep(Constants.RELOAD_CONFIG);
		}
	}

	static String getVersion() {
		InputStream is = null;
		try {
			final Properties p = new Properties();
			is = Bouncer.class.getResourceAsStream(Constants.VERSION_FILE);
			p.load(is);
			// Implementation-Vendor-Id: ${project.groupId}
			// Implementation-Title: ${project.name}
			// Implementation-Version: ${project.version}
			return p.getProperty("Bouncer-Version");
		} catch (Exception e) {
			return "UNKNOWN";
		} finally {
			IOHelper.closeSilent(is);
		}
	}

	static void doSleep(final long time) {
		try {
			Thread.sleep(time);
		} catch (InterruptedException ie) {
			Thread.currentThread().interrupt();
		}
	}

	SSLFactory getSSLFactory(final Options opts) throws IOException, GeneralSecurityException {
		if (opts.isOption(Options.MUX_SSL)) {
			String[] sslConfig = new String[] {
				"NULL"
			};
			sslConfig = opts.getString(Options.P_SSL).split(":");
			return new SSLFactory(cipherSuites, sslConfig[0], sslConfig[1], sslConfig[2]);
		}
		return null;
	}

	void initJMX() throws JMException {
		stats.init();
	}

	void destroyJMX() throws JMException {
		stats.destroy();
	}

	void reload(final InputStream isConfig) throws NoSuchAlgorithmException, IOException {
		stats.incReloads();
		if (!reloadables.isEmpty() || !orderedShutdown.isEmpty()) {
			shutdownBarrier = new CyclicBarrier(reloadables.size() + 1);
			for (Shutdownable shut : orderedShutdown) {
				Log.info(this.getClass().getSimpleName() + " Shuting down: "
						+ shut.getClass().getSimpleName());
				shut.setShutdown();
			}
			for (Shutdownable shut : reloadables) {
				Log.info(this.getClass().getSimpleName() + " Shuting down: "
						+ shut.getClass().getSimpleName());
				shut.setShutdown();
			}
			Log.info(this.getClass().getSimpleName() + " Waiting for " + reloadables.size()
					+ " threads to shutdown");
			if (awaitShutdown(null)) {
				Log.info(this.getClass().getSimpleName() + " Shutdown completed");
			} else {
				Log.error(this.getClass().getSimpleName() + " Shutdown Error");
				// Audit Sockets
				Log.warn(this.getClass().getSimpleName() + " Autit Connection Begin");
				for (final Awaiter shut : reloadables) {
					Log.warn("Audit Connection: " + String.valueOf(shut));
				}
				Log.warn(this.getClass().getSimpleName() + " Autit Connection End");
			}
			shutdownBarrier = null;
			reloadables.clear();
			try {
				//
				// Audit Sockets
				Log.warn(this.getClass().getSimpleName() + " Audit Socket Begin");
				for (Socket s : socketRegistry.getClientSockets()) {
					Log.warn("Audit ClientSocket: " + String.valueOf(s));
				}
				for (ServerSocket s : socketRegistry.getServerSockets()) {
					Log.warn("Audit ServerSocket: " + String.valueOf(s));
				}
				// Audit Task
				if (Log.isDebug()) {
					Log.warn(this.getClass().getSimpleName() + " Audit Socket End");
					final Map<Integer, AuditableRunner> localTaskList = new HashMap<Integer, AuditableRunner>(
							taskMgr.getTaskList());
					Log.warn(this.getClass().getSimpleName() + " Audit Task Begin");
					for (Entry<Integer, AuditableRunner> e : localTaskList.entrySet()) {
						Log.debug("Audit Task: " + e.getKey() + " " + e.getValue());
						for (StackTraceElement st : e.getValue().getThread().getStackTrace()) {
							Log.debug("Audit Task: " + e.getKey() + " Stack>>> " + String.valueOf(st));
						}
					}
					Log.warn(this.getClass().getSimpleName() + " Audit Task End");
				}
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " config reload (audit)", e);
			}
		}
		//
		cipherSuites = new CipherSuites();
		//
		final BufferedReader in = new BufferedReader(new InputStreamReader(isConfig));
		String line = null;
		int lineNum = 0;
		try {
			while ((line = in.readLine()) != null) {
				boolean started = false;
				lineNum++;
				try {
					// Skip comments
					if (line.trim().startsWith("#"))
						continue;
					if (line.trim().equals(""))
						continue;
					final String[] toks = line.split("( |\t)+");
					// Invalid number of params
					if (toks.length < 4) {
						Log.error(this.getClass().getSimpleName() + " Invalid config line[num=" + lineNum
								+ "]: " + line);
						continue;
					}
					// Start bouncers
					if (ConnectionType.getTypeFromString(toks[0]) != ConnectionType.UNKNOWN_VALUE) {
						// Expected format (bouncer style):
						// <mux-listen|mux-connect|tun-listen|tun-connect> <mux-name> <address> <port> [opts]
						final ConnectionType connType = ConnectionType.getTypeFromString(toks[0]);
						final String muxName = toks[1];
						//
						final String addr = toks[2];
						final int port = Integer.valueOf(toks[3]);
						//
						final String options = ((toks.length > 4) ? toks[4] : "");
						final Options opts = new Options(options);
						opts.setMuxName(muxName);
						//
						Log.info(this.getClass().getSimpleName() + " Readed type=" + connType + " addr="
								+ addr + " port=" + port + " options{" + opts + "}");
						started = startBouncerStyle(connType, addr, port, opts);
					} else {
						// Expected format (style rinetd):
						// <bind-addr> <bind-port> <remote-addr> <remote-port> [opts]
						final String bindaddr = toks[0];
						final int bindport = Integer.valueOf(toks[1]);
						//
						final String remoteaddr = toks[2];
						final int remoteport = Integer.valueOf(toks[3]);
						//
						final String options = ((toks.length > 4) ? toks[4] : "");
						final Options opts = new Options(options);
						//
						Log.info(this.getClass().getSimpleName() + " Readed bind-addr=" + bindaddr
								+ " bind-port=" + bindport + " remote-addr=" + remoteaddr + " remote-port="
								+ remoteport + " options{" + opts + "}");
						started = startRinetdStyle(bindaddr, bindport, remoteaddr, remoteport, opts);
					}
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + " Invalid config line[num=" + lineNum + "]: "
							+ line + " (" + e.toString() + ")");
					continue;
				}
				if (!started) {
					Log.error(this.getClass().getSimpleName() + " Unable to start line[num=" + lineNum
							+ "]: " + line);
				}
			}
		} finally {
			IOHelper.closeSilent(in);
		}
	}

	boolean startBouncerStyle(final ConnectionType connType, final String addr, final int port,
			final Options opts) throws IOException, GeneralSecurityException {
		final SSLFactory sslFactory = getSSLFactory(opts);
		switch (connType) {
			case MUX_LISTEN: {
				final Options lopts = new Options(opts).unsetOptionsPlain();
				final InboundAddress left = new InboundAddress(this, addr, port, lopts); // MUX
				left.setSSLFactory(sslFactory);
				final MuxServer mux = new MuxServer(this, left, null);
				muxServers.put(lopts.getMuxName(), mux);
				mux.listenLocal();
				break;
			}
			case MUX_CONNECT: {
				final Options ropts = new Options(opts).unsetOptionsPlain();
				final OutboundAddress right = new OutboundAddress(this, addr, port, ropts); // MUX
				right.setSSLFactory(sslFactory);
				final MuxClient mux = new MuxClient(this, null, right);
				muxClients.put(ropts.getMuxName(), mux);
				mux.openRemote();
				break;
			}
			case TUN_LISTEN: {
				final Options ropts = new Options(opts).unsetOptionsMUX();
				final InboundAddress right = new InboundAddress(this, addr, port, ropts); // PLAIN
				final MuxServer mux = muxServers.get(ropts.getMuxName());
				mux.addRight(right);
				break;
			}
			case TUN_CONNECT: {
				final Options lopts = new Options(opts).unsetOptionsMUX();
				final OutboundAddress left = new OutboundAddress(this, addr, port, lopts); // PLAIN
				final MuxClient mux = muxClients.get(lopts.getMuxName());
				mux.addLeft(left);
				break;
			}
			default:
				return false;
		}
		return true;
	}

	boolean startRinetdStyle(final String leftaddr, final int leftport, final String rightaddr,
			final int rightport, final Options opts) throws IOException, GeneralSecurityException {
		final SSLFactory sslFactory = getSSLFactory(opts);
		if (opts.isOption(Options.MUX_IN)) {
			final Options lopts = new Options(opts).unsetOptionsPlain();
			final Options ropts = new Options(opts).unsetOptionsMUX();
			final InboundAddress left = new InboundAddress(this, leftaddr, leftport, lopts); // MUX
			final InboundAddress right = new InboundAddress(this, rightaddr, rightport, ropts); // PLAIN
			left.setSSLFactory(sslFactory);
			new MuxServer(this, left, right).listenLocal();
		} else if (opts.isOption(Options.MUX_OUT)) {
			final Options lopts = new Options(opts).unsetOptionsMUX();
			final Options ropts = new Options(opts).unsetOptionsPlain();
			final OutboundAddress left = new OutboundAddress(this, leftaddr, leftport, lopts); // PLAIN
			final OutboundAddress right = new OutboundAddress(this, rightaddr, rightport, ropts); // MUX
			right.setSSLFactory(sslFactory);
			new MuxClient(this, left, right).openRemote();
		} else {
			final Options lopts = new Options(opts).unsetOptionsMUX();
			final Options ropts = new Options(opts).unsetOptionsMUX();
			final InboundAddress left = new InboundAddress(this, leftaddr, leftport, lopts); // PLAIN
			final OutboundAddress right = new OutboundAddress(this, rightaddr, rightport, ropts); // PLAIN
			new PlainServer(this, left, right).listenLocal();
		}
		return true;
	}

	@Override
	public CipherSuites getCipherSuites() {
		return cipherSuites;
	}

	@Override
	public RawPacket allocateRawPacket() {
		return poolRaw.checkout();
	}

	@Override
	public void releaseRawPacket(final RawPacket packet) {
		packet.clear();
		poolRaw.release(packet);
	}

	@Override
	public MuxPacket allocateMuxPacket() {
		return poolMux.checkout();
	}

	@Override
	public void releaseMuxPacket(final MuxPacket packet) {
		packet.clear();
		poolMux.release(packet);
	}

	@Override
	public ByteArrayOutputStream allocateByteArrayOutputStream() {
		return poolBAOS.checkout();
	}

	@Override
	public void releaseByteArrayOutputStream(final ByteArrayOutputStream baos) {
		baos.reset();
		poolBAOS.release(baos);
	}

	@Override
	public void submitTask(final Runnable task, final String traceName, final int clientId) {
		taskMgr.submitTask(task, traceName, clientId);
	}

	@Override
	public void addReloadableAwaiter(final Awaiter awaiter) {
		reloadables.add(awaiter);
	}

	@Override
	public boolean awaitShutdown(final Awaiter caller) {
		boolean ret = false;
		if (shutdownBarrier != null) {
			try {
				shutdownBarrier.await(Constants.RELOAD_TIMEOUT, TimeUnit.MILLISECONDS);
				ret = true;
			} catch (Exception ign) {
			}
		}
		if (caller != null)
			reloadables.remove(caller);
		return ret;
	}

	@Override
	public void addShutdownable(final Shutdownable shutdownable) {
		orderedShutdown.add(shutdownable);
	}

	public void removeShutdownable(final Shutdownable shutdownable) {
		orderedShutdown.remove(shutdownable);
	}

	@Override
	public void registerSocket(final Socket socket) throws SocketException {
		IOHelper.setupSocket(socket);
		if (socketRegistry.registerSocket(socket)) {
			stats.incActiveConnections();
		}
	}

	@Override
	public void registerSocket(final ServerSocket socket) throws SocketException {
		IOHelper.setupSocket(socket);
		socketRegistry.registerSocket(socket);
	}

	@Override
	public void closeSilent(final Socket sock) {
		IOHelper.closeSilent(sock);
		if (socketRegistry.unregisterSocket(sock)) {
			stats.incAttendedConnections();
			stats.decActiveConnections();
		}
	}

	@Override
	public void closeSilent(final ServerSocket sock) {
		IOHelper.closeSilent(sock);
		socketRegistry.unregisterSocket(sock);
	}

	@Override
	public Statistics getStatistics() {
		return stats;
	}

	static enum ConnectionType {
		MUX_LISTEN, MUX_CONNECT, TUN_LISTEN, TUN_CONNECT, UNKNOWN_VALUE;

		static ConnectionType getTypeFromString(final String value) {
			if (value != null) {
				try {
					return valueOf(value.replace('-', '_').toUpperCase());
				} catch (Exception ign) {
				}
			}
			return UNKNOWN_VALUE;
		}
	}
}
