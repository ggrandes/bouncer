package org.javastack.bouncer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

import javax.net.ssl.SSLSocket;

import org.javastack.bouncer.StickyStore.StickyEntry;

// ============================================ Cluster Server

class ClusterServer {
	final ServerContext context;
	final InboundAddress left;

	ClusterServerListen localListen;

	ClusterServer(final ServerContext context, final InboundAddress left) {
		this.context = context;
		this.left = left;
	}

	void listenLocal() throws IOException { // Entry Point
		localListen = new ClusterServerListen(left);
		context.addReloadableAwaiter(localListen);
		context.submitTask(localListen, "ClusterInListenLeft[" + left + "]", ClientId.newId());
	}

	static void doSleep(final long time) {
		try {
			Thread.sleep(time);
		} catch (InterruptedException ie) {
			Thread.currentThread().interrupt();
		}
	}

	class ClusterServerListen implements Awaiter, Runnable {
		final InboundAddress inboundAddress;
		final ServerSocket listen;
		boolean shutdown = false;

		ClusterServerListen(final InboundAddress inboundAddress) throws IOException {
			this.inboundAddress = inboundAddress;
			listen = inboundAddress.listen();
		}

		@Override
		public void setShutdown() {
			shutdown = true;
			close();
		}

		void close() {
			context.closeSilent(listen);
		}

		@Override
		public void run() {
			Log.info(this.getClass().getSimpleName() + "::run listen: " + listen);
			while (!shutdown) {
				try {
					final Socket socket = listen.accept();
					try {
						context.registerSocket(socket);
						final Integer pReadTimeout = inboundAddress.getOpts().getInteger(
								Options.P_READ_TIMEOUT);
						if (pReadTimeout != null) {
							socket.setSoTimeout(pReadTimeout.intValue());
						}
						if (socket instanceof SSLSocket) {
							((SSLSocket) socket).startHandshake();
						}
						Log.info(this.getClass().getSimpleName() + " new socket: " + socket + " "
								+ SSLFactory.getSocketProtocol(socket) + " SendBufferSize="
								+ socket.getSendBufferSize() + " ReceiveBufferSize="
								+ socket.getReceiveBufferSize());
						attender(socket);
					} catch (Exception e) {
						Log.error(this.getClass().getSimpleName() + " Exception: " + e.toString(), e);
						context.closeSilent(socket);
					}
				} catch (SocketTimeoutException e) {
					continue;
				} catch (Exception e) {
					if (!shutdown) {
						Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
					}
					doSleep(1000);
				}
			}
			close();
			Log.info(this.getClass().getSimpleName() + " await end");
			context.awaitShutdown(this);
			Log.info(this.getClass().getSimpleName() + " end");
		}

		protected synchronized void attender(final Socket socket) throws IOException {
			Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
			try {
				socket.setSoTimeout(Constants.CLUSTER_READ_TIMEOUT);
			} catch (Exception ign) {
			}
			ClusterServerLocal local = new ClusterServerLocal(socket, inboundAddress);
			context.addShutdownable(local);
			context.submitTask(local, "ClusterInLeft[" + left + "|" + IOHelper.socketRemoteToString(socket)
					+ "]", ClientId.newId());
		}
	}

	class ClusterServerLocal implements Awaiter, Runnable {
		final Socket sock;
		final InboundAddress inboundAddress;
		final InputStream is;
		final OutputStream os;
		boolean shutdown = false;
		final SealerAES seal;

		ClusterServerLocal(final Socket sock, final InboundAddress inboundAddress) throws IOException {
			this.sock = sock;
			this.inboundAddress = inboundAddress;
			is = new BufferedInputStream(sock.getInputStream(), 256);
			os = new BufferedOutputStream(sock.getOutputStream(), 256);
			if (inboundAddress.getOpts().isOption(Options.CLUSTER_AES)) {
				seal = new SealerAES(inboundAddress.getOpts().getString(Options.P_AES), //
						inboundAddress.getOpts().getString(Options.P_AES_ALG), //
						inboundAddress.getOpts().getInteger(Options.P_AES_BITS, Integer.MIN_VALUE), //
						true);
			} else {
				seal = null;
			}
		}

		@Override
		public void setShutdown() {
			shutdown = true;
			// Graceful Shutdown: don't call close()
		}

		void close() {
			IOHelper.closeSilent(is);
			IOHelper.closeSilent(os);
			context.closeSilent(sock);
		}

		boolean isClosed() {
			return ((sock == null) || sock.isClosed());
		}

		void sendLocal(final ClusterPacket msg) throws IOException, GeneralSecurityException {
			if (os == null)
				return;
			synchronized (os) {
				if (seal != null) {
					// AES encryption
					final ByteArrayOutputStream baos = context.allocateByteArrayOutputStream();
					msg.toWire(baos);
					final byte[] encoded = seal.code(baos.toByteArray(), 0, baos.size());
					baos.reset();
					IOHelper.toWireWithHeader(baos, encoded, encoded.length);
					baos.writeTo(os);
					os.flush();
					context.releaseByteArrayOutputStream(baos);
				} else {
					msg.toWire(os);
				}
			}
		}

		void sendNOP() {
			// Send NOP
			try {
				final ClusterPacket packet = context.allocateClusterPacket();
				packet.nop();
				sendLocal(packet);
				context.releaseClusterPacket(packet);
			} catch (Exception ign) {
			}
		}

		void sendStickyTable(final long clusterId) {
			final ArrayList<ClusterPacket> lcp = new ArrayList<ClusterPacket>();
			if (true) {
				final ClusterPacket packet = context.allocateClusterPacket();
				packet.rawType(ClusterPacket.CLUSTER_MSG_TYPE_SYNC_BEGIN);
				lcp.add(packet);
			}
			for (final StickyStore<InetAddress, InetAddress> e : context.stickyGetForCluster(clusterId)) {
				final StickyConfig cfg = e.getConfig();
				for (final StickyEntry<InetAddress, InetAddress> se : e.getEntries()) {
					final long replicationId = cfg.replicationId;
					final ClusterPacket packet = context.allocateClusterPacket();
					packet.put(clusterId, replicationId, se.key, se.value); // FIXME
					lcp.add(packet);
				}
			}
			if (true) {
				final ClusterPacket packet = context.allocateClusterPacket();
				packet.rawType(ClusterPacket.CLUSTER_MSG_TYPE_SYNC_END);
				lcp.add(packet);
			}
			if (!lcp.isEmpty()) {
				Log.info(this.getClass().getSimpleName() + " SEND: StickyTable size=" + lcp.size());
				context.submitTask(new Runnable() {
					public void run() {
						try {
							Thread.sleep(1000);
						} catch (InterruptedException e) {
						}
						for (final ClusterPacket packet : lcp) {
							try {
								sendLocal(packet);
							} catch (Exception ign) {
							}
						}
					}
				}, "ClusterInLeftSendStickyTable[" + left + "|" + IOHelper.socketRemoteToString(sock) + "]",
						ClientId.getId());
			}
		}

		@Override
		public void run() {
			Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
			final long clusterId = inboundAddress.getOpts().getClusterID().longValue();
			long clusterNopKeepAlive = System.currentTimeMillis();
			while (!shutdown) {
				try {
					final ClusterPacket msg = context.allocateClusterPacket();
					if (seal != null) {
						// AES encryption
						final byte[] encoded = IOHelper.fromWireWithHeader(is);
						final byte[] decoded = seal.decode(encoded, 0, encoded.length);
						final ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
						msg.fromWire(bais);
					} else {
						msg.fromWire(is);
					}
					switch (msg.getMsgType()) {
						case ClusterPacket.CLUSTER_MSG_TYPE_NOP:
							break;
						case ClusterPacket.CLUSTER_MSG_TYPE_HELLO:
							// FIXME: Send current table to client
							Log.info(this.getClass().getSimpleName() + " RECV: HELLO clusterId=" + clusterId);
							sendStickyTable(clusterId);
							break;
						case ClusterPacket.CLUSTER_MSG_TYPE_STICKY_UPDATE:
							context.stickyRemoteUpdateNotify(msg);
							break;
						default:
							Log.error(this.getClass().getSimpleName() + " Unknown Message Type: "
									+ msg.getMsgType());
					}
					context.releaseClusterPacket(msg);
				} catch (SocketTimeoutException e) {
					final long now = System.currentTimeMillis();
					if ((clusterNopKeepAlive + Constants.CLUSTER_KEEP_ALIVE) < now) {
						Log.debug(this.getClass().getSimpleName() + " " + e.toString());
						sendNOP();
						clusterNopKeepAlive = now;
					}
					continue;
				} catch (EOFException e) {
					break;
				} catch (IOException e) {
					if (!sock.isClosed() && !shutdown) {
						Log.error(this.getClass().getSimpleName() + " " + e.toString());
					}
					break;
				} catch (GeneralSecurityException e) {
					Log.error(this.getClass().getSimpleName() + " " + e.toString());
					doSleep(1000);
					break;
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + " Generic exception", e);
					break;
				}
			}
			// Close all
			close();
			Log.info(this.getClass().getSimpleName() + " await end");
			context.awaitShutdown(this);
			Log.info(this.getClass().getSimpleName() + " end");
		}
	}
}
