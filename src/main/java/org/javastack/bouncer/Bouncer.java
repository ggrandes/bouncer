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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
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
	private final GenericPool<ClusterPacket> poolCluster = new GenericPool<ClusterPacket>(
			ClusterPacket.GENERIC_POOL_FACTORY, Constants.BUFFER_POOL_SIZE);
	private final GenericPool<ByteArrayOutputStream> poolBAOS = new GenericPool<ByteArrayOutputStream>(
			byteArrayOutputStreamFactory, Constants.BUFFER_POOL_SIZE);
	private final TaskManager taskMgr = new TaskManager();
	private final SocketRegistrator socketRegistry = new SocketRegistrator();
	private CipherSuites cipherSuites = null;

	private final LinkedHashMap<String, MuxServer> muxServers = new LinkedHashMap<String, MuxServer>();
	private final LinkedHashMap<String, MuxClient> muxClients = new LinkedHashMap<String, MuxClient>();
	private final LinkedHashMap<Long, List<ClusterClient>> clusterClients = new LinkedHashMap<Long, List<ClusterClient>>();
	private final LinkedHashMap<StickyKey, StickyStore<InetAddress, InetAddress>> clusterStickies = new LinkedHashMap<StickyKey, StickyStore<InetAddress, InetAddress>>();
	private final BouncerStatistics stats = new BouncerStatistics();

	// ============================== Global code

	public static void main(final String[] args) throws Exception {
		if (args.length < 1) {
			System.out.println(Bouncer.class.getName() + " <configName|configURL>");
			return;
		}
		final String configFile = args[0];
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
		final URL urlConfig = bouncer.getConfigSource(configFile, args);
		if (urlConfig == null) {
			Log.error("Config not found: " + configFile);
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

	URL getConfigSource(final String configFile, final String[] args) throws MalformedURLException {
		if (configFile.startsWith("http:") || configFile.startsWith("https:")
				|| configFile.startsWith("file:")) {
			return new URL(configFile);
		}
		if (configFile.equals("--")) {
			final Charset ISO = Charset.forName("ISO-8859-1");
			final long mtime = System.currentTimeMillis();
			final StringBuilder sb = new StringBuilder();
			final ByteArrayInputStream baos;
			for (final String a : args) {
				if (a == null || a.isEmpty() || a.equals("--") || a.startsWith("#")) {
					continue;
				}
				sb.append(a).append("\r\n");
			}
			baos = new ByteArrayInputStream(sb.toString().getBytes(ISO));
			return new URL(null, "mem://.", new URLStreamHandler() {
				@Override
				protected URLConnection openConnection(final URL u) throws IOException {
					return new URLConnection(u) {
						@Override
						public void connect() throws IOException {
						}

						@Override
						public InputStream getInputStream() throws IOException {
							baos.reset();
							return baos;
						}

						@Override
						public long getLastModified() {
							return mtime;
						}
					};
				}
			});
		}
		return getClass().getResource("/" + configFile);
	}

	SSLFactory getSSLFactory(final Options opts, final String srcConfig) throws IOException,
			GeneralSecurityException {
		if (opts.isOption(Options.MUX_SSL | Options.TUN_ENDSSL | Options.TUN_SSL)) {
			String p = opts.getString(srcConfig);
			if (p == null) {
				if (opts.isOption(Options.TUN_SSL)) {
					p = ""; // USE_DEFAULT
				} else {
					throw new GeneralSecurityException("Invalid " + srcConfig + " param");
				}
			}
			final String[] sslConfig = p.split(":");
			if (sslConfig.length > 2) {
				return new SSLFactory(cipherSuites, sslConfig[0], sslConfig[1], sslConfig[2]);
			} else if (sslConfig.length > 1) {
				return new SSLFactory(cipherSuites, sslConfig[0], sslConfig[1]);
			}
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
		clusterClients.clear();
		clusterStickies.clear();
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
						// <mux-in|mux-out|tun-listen|tun-connect> <mux-name> <address> <port> [opts]
						final ConnectionType connType = ConnectionType.getTypeFromString(toks[0]);
						switch (connType) {
							case MUX_IN:
							case MUX_LISTEN:
							case MUX_OUT:
							case MUX_CONNECT:
							case TUN_LISTEN:
							case TUN_CONNECT: {
								final String muxName = toks[1];
								//
								final String addr = toks[2];
								final int port = Integer.valueOf(toks[3]);
								//
								final String options = ((toks.length > 4) ? toks[4] : "");
								final Options opts = new Options(options);
								opts.setMuxName(muxName);
								//
								Log.info(this.getClass().getSimpleName() + " Readed type=" + connType
										+ " addr=" + addr + " port=" + port + " options{" + opts + "}");
								started = startBouncerStyle(connType, addr, port, opts);
								break;
							}
							// <cluster-in|cluster-out> <cluster-name> <address> <port> [opts]
							case CLUSTER_IN:
							case CLUSTER_OUT: {
								final long clusterId = IOHelper.longIdFromString(toks[1]);
								//
								final String addr = toks[2];
								final int port = Integer.valueOf(toks[3]);
								//
								final String options = ((toks.length > 4) ? toks[4] : "");
								final Options opts = new Options(options);
								opts.setClusterID(clusterId);
								//
								Log.info(this.getClass().getSimpleName() + " Readed type=" + connType
										+ " addr=" + addr + " port=" + port + " options{" + opts + "}");
								started = startCluster(connType, clusterId, addr, port, opts);
								break;
							}
						}
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
		switch (connType) {
			case MUX_IN:
			case MUX_LISTEN: {
				final SSLFactory sslFactory = getSSLFactory(opts, Options.P_SSL);
				final Options lopts = new Options(opts).unsetOptionsPlain();
				final InboundAddress left = new InboundAddress(this, addr, port, lopts); // MUX
				left.setSSLFactory(sslFactory);
				final MuxServer mux = new MuxServer(this, left, null);
				muxServers.put(lopts.getMuxName(), mux);
				mux.listenLocal();
				break;
			}
			case MUX_OUT:
			case MUX_CONNECT: {
				final SSLFactory sslFactory = getSSLFactory(opts, Options.P_SSL);
				final Options ropts = new Options(opts).unsetOptionsPlain();
				final OutboundAddress right = new OutboundAddress(this, addr, port, ropts); // MUX
				right.setSSLFactory(sslFactory);
				final MuxClient mux = new MuxClient(this, null, right);
				muxClients.put(ropts.getMuxName(), mux);
				mux.openRemote();
				break;
			}
			case TUN_LISTEN: {
				final SSLFactory sslFactory = getSSLFactory(opts, Options.P_ENDSSL);
				final Options ropts = new Options(opts).unsetOptionsMUX();
				final InboundAddress right = new InboundAddress(this, addr, port, ropts); // PLAIN
				right.setSSLFactory(sslFactory);
				final MuxServer mux = muxServers.get(ropts.getMuxName());
				mux.addRight(right);
				break;
			}
			case TUN_CONNECT: {
				final SSLFactory sslFactoryClient = getSSLFactory(opts, Options.P_SSL);
				final Options lopts = new Options(opts).unsetOptionsMUX();
				final OutboundAddress left = new OutboundAddress(this, addr, port, lopts); // PLAIN
				left.setSSLFactory(sslFactoryClient);
				final MuxClient mux = muxClients.get(lopts.getMuxName());
				mux.addLeft(left);
				break;
			}
			default:
				return false;
		}
		return true;
	}

	boolean startCluster(final ConnectionType connType, final long clusterId, final String addr,
			final int port, final Options opts) throws IOException, GeneralSecurityException {
		switch (connType) {
			case CLUSTER_IN: {
				final SSLFactory sslFactory = getSSLFactory(opts, Options.P_SSL);
				final Options lopts = new Options(opts).unsetOptionsPlain().unsetOptionsMUX();
				final InboundAddress left = new InboundAddress(this, addr, port, lopts); // CLUSTER
				left.setSSLFactory(sslFactory);
				final ClusterServer cluster = new ClusterServer(this, left);
				cluster.listenLocal();
				break;
			}
			case CLUSTER_OUT: {
				final SSLFactory sslFactory = getSSLFactory(opts, Options.P_SSL);
				final Options ropts = new Options(opts).unsetOptionsPlain().unsetOptionsMUX();
				final OutboundAddress right = new OutboundAddress(this, addr, port, ropts); // CLUSTER
				right.setSSLFactory(sslFactory);
				final ClusterClient cluster = new ClusterClient(this, right);
				final Long id = Long.valueOf(clusterId);
				List<ClusterClient> list = clusterClients.get(id); // FIXME
				if (list == null) {
					list = new ArrayList<ClusterClient>();
					clusterClients.put(id, list);
				}
				list.add(cluster);
				cluster.openRemote();
				break;
			}
			default:
				return false;
		}
		return true;
	}

	boolean startRinetdStyle(final String leftaddr, final int leftport, final String rightaddr,
			final int rightport, final Options opts) throws IOException, GeneralSecurityException {
		if (opts.isOption(Options.MUX_IN)) {
			final SSLFactory sslFactory = getSSLFactory(opts, Options.P_SSL);
			final Options lopts = new Options(opts).unsetOptionsPlain();
			final Options ropts = new Options(opts).unsetOptionsMUX();
			final InboundAddress left = new InboundAddress(this, leftaddr, leftport, lopts); // MUX
			final InboundAddress right = new InboundAddress(this, rightaddr, rightport, ropts); // PLAIN
			left.setSSLFactory(sslFactory);
			new MuxServer(this, left, right).listenLocal();
		} else if (opts.isOption(Options.MUX_OUT)) {
			final SSLFactory sslFactory = getSSLFactory(opts, Options.P_SSL);
			final Options lopts = new Options(opts).unsetOptionsMUX();
			final Options ropts = new Options(opts).unsetOptionsPlain();
			final OutboundAddress left = new OutboundAddress(this, leftaddr, leftport, lopts); // PLAIN
			final OutboundAddress right = new OutboundAddress(this, rightaddr, rightport, ropts); // MUX
			right.setSSLFactory(sslFactory);
			new MuxClient(this, left, right).openRemote();
		} else {
			final Options lopts = new Options(opts).unsetOptionsMUX().unsetFlags(Options.TUN_SSL);
			final Options ropts = new Options(opts).unsetOptionsMUX().unsetFlags(Options.TUN_ENDSSL);
			final SSLFactory sslFactory = getSSLFactory(lopts, Options.P_ENDSSL);
			final SSLFactory sslFactoryClient = getSSLFactory(ropts, Options.P_SSL);
			final InboundAddress left = new InboundAddress(this, leftaddr, leftport, lopts); // PLAIN
			final OutboundAddress right = new OutboundAddress(this, rightaddr, rightport, ropts); // PLAIN
			left.setSSLFactory(sslFactory);
			right.setSSLFactory(sslFactoryClient);
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
	public ClusterPacket allocateClusterPacket() {
		return poolCluster.checkout();
	}

	@Override
	public void releaseClusterPacket(final ClusterPacket packet) {
		packet.clear();
		poolCluster.release(packet);
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
	public void submitTask(final Runnable task, final String traceName, final long clientId) {
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
	public void stickyRegister(final StickyStore<InetAddress, InetAddress> stickies) {
		final long clusterId = stickies.getConfig().clusterId;
		final long replicationId = stickies.getConfig().replicationId;
		final StickyKey key = StickyKey.valueOf(clusterId, replicationId);
		clusterStickies.put(key, stickies);
	}

	@Override
	public void stickyLocalUpdateNotify(final long clusterId, final long replicationId,
			final InetAddress stickyAddr, final InetAddress mapAddr) {
		// FIXME
		final List<ClusterClient> list = clusterClients.get(clusterId);
		if (list != null) {
			final ClusterPacket packet = allocateClusterPacket();
			packet.put(clusterId, replicationId, stickyAddr, mapAddr);
			for (final ClusterClient cluster : list) {
				try {
					Log.info("stickyLocalUpdateNotify: " + String.valueOf(packet));
					cluster.remote.sendRemote(packet);
				} catch (Exception e) {
					Log.error("stickyLocalUpdateNotify error: " + e.toString(), e);
				}
			}
			releaseClusterPacket(packet);
		}
	}

	@Override
	public void stickyRemoteUpdateNotify(final ClusterPacket packet) {
		final long clusterId = packet.getClusterId();
		final long replicationId = packet.getReplicationId();
		// FIXME
		final StickyKey key = StickyKey.valueOf(clusterId, replicationId);
		final StickyStore<InetAddress, InetAddress> sticky = clusterStickies.get(key);
		if (sticky != null) {
			final InetAddress stickyAddr = packet.getStickyAddr();
			final InetAddress mapAddr = packet.getMapAddr();
			Log.info("stickyRemoteUpdateNotify: " + String.valueOf(packet));
			sticky.put(stickyAddr, mapAddr);
		}
	}

	@Override
	public List<StickyStore<InetAddress, InetAddress>> stickyGetForCluster(final long clusterId) {
		// FIXME
		final Set<Entry<StickyKey, StickyStore<InetAddress, InetAddress>>> s = clusterStickies.entrySet();
		final ArrayList<StickyStore<InetAddress, InetAddress>> l = new ArrayList<StickyStore<InetAddress, InetAddress>>();
		for (final Entry<StickyKey, StickyStore<InetAddress, InetAddress>> e : s) {
			if (clusterId == e.getKey().clusterId) {
				l.add(e.getValue());
			}
		}
		return l;
	}

	@Override
	public Statistics getStatistics() {
		return stats;
	}

	static enum ConnectionType {
		/**
		 * Mux Connection (Server side)
		 */
		MUX_IN,
		/**
		 * Mux Connection (Server side) - legacy tag
		 */
		MUX_LISTEN,
		/**
		 * Mux Connection (Client side)
		 */
		MUX_OUT,
		/**
		 * Mux Connection (Client side) - legacy tag
		 */
		MUX_CONNECT,
		/**
		 * Tunnel Connection (Server side)
		 */
		TUN_LISTEN,
		/**
		 * Tunnel Connection (Client side)
		 */
		TUN_CONNECT,
		/**
		 * Cluster Connection (Server side)
		 */
		CLUSTER_IN,
		/**
		 * Cluster Connection (Client side)
		 */
		CLUSTER_OUT,
		/**
		 * Unknown Parameter
		 */
		UNKNOWN_VALUE;

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

	static class StickyKey {
		final long clusterId;
		final long replicationId;

		StickyKey(final long clusterId, final long replicationId) {
			this.clusterId = clusterId;
			this.replicationId = replicationId;
		}

		static StickyKey valueOf(final long clusterId, final long replicationId) {
			return new StickyKey(clusterId, replicationId);
		}

		@Override
		public boolean equals(final Object obj) {
			if (obj instanceof StickyKey) {
				final StickyKey o = (StickyKey) obj;
				return ((this.clusterId == o.clusterId) && (this.replicationId == o.replicationId));
			}
			return false;
		}

		@Override
		public int hashCode() {
			return (int) (this.clusterId ^ (this.clusterId >>> 32) ^ this.replicationId ^ (this.replicationId >>> 32));
		}
	}
}
