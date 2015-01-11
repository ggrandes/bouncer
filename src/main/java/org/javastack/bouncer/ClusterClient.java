package org.javastack.bouncer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;

// ============================================ Cluster Client

class ClusterClient {
	final ServerContext context;
	final OutboundAddress right;

	ClusterClientRemote remote;

	ClusterClient(final ServerContext context, final OutboundAddress right) {
		this.context = context;
		this.right = right;
	}

	void openRemote() throws IOException { // Entry Point
		Log.info(this.getClass().getSimpleName() + "::openRemote " + right);
		remote = new ClusterClientRemote(right);
		context.addShutdownable(remote);
		context.submitTask(remote, "ClusterOutRight[" + right + "]", ClientId.newId());
	}

	static void doSleep(final long time) {
		try {
			Thread.sleep(time);
		} catch (InterruptedException ie) {
			Thread.currentThread().interrupt();
		}
	}

	class ClusterClientRemote implements Awaiter, Runnable {
		final OutboundAddress outboundAddress;

		Socket sock;
		InputStream is;
		OutputStream os;
		boolean shutdown = false;

		final SealerAES seal;

		ClusterClientRemote(final OutboundAddress outboundAddress) throws IOException {
			this.outboundAddress = outboundAddress;
			if (outboundAddress.getOpts().isOption(Options.CLUSTER_AES)) {
				seal = new SealerAES(outboundAddress.getOpts().getString(Options.P_AES), //
						outboundAddress.getOpts().getString(Options.P_AES_ALG), //
						outboundAddress.getOpts().getInteger(Options.P_AES_BITS, Integer.MIN_VALUE), //
						false);
			} else {
				seal = null;
			}
		}

		void sendRemote(final ClusterPacket msg) throws IOException, GeneralSecurityException {
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

		void sendHELLO() {
			// Send HELLO
			try {
				final ClusterPacket packet = context.allocateClusterPacket();
				packet.hello();
				sendRemote(packet);
				context.releaseClusterPacket(packet);
			} catch (Exception ign) {
			}
		}

		void sendNOP() {
			// Send NOP
			try {
				final ClusterPacket packet = context.allocateClusterPacket();
				packet.nop();
				sendRemote(packet);
				context.releaseClusterPacket(packet);
			} catch (Exception ign) {
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
			if (sock != null)
				context.closeSilent(sock);
			sock = null;
		}

		@Override
		public void run() {
			long clusterNopKeepAlive = System.currentTimeMillis();
			while (!shutdown) {
				while (!shutdown) {
					try {
						Log.info(this.getClass().getSimpleName() + " Connecting: " + outboundAddress);
						context.getStatistics().incTryingConnections();
						sock = outboundAddress.connect();
						if (sock == null)
							throw new ConnectException("Unable to connect to " + outboundAddress);
						try {
							sock.setSoTimeout(Constants.CLUSTER_READ_TIMEOUT); // Timeout for Cluster
						} catch (Exception ign) {
						}
						is = new BufferedInputStream(sock.getInputStream(), 256);
						os = new BufferedOutputStream(sock.getOutputStream(), 256);
						Log.info(this.getClass().getSimpleName() + " Connected: " + sock + " SendBufferSize="
								+ sock.getSendBufferSize() + " ReceiveBufferSize="
								+ sock.getReceiveBufferSize());
						if (seal != null)
							seal.reset();
						sendHELLO();
						break;
					} catch (Exception e) {
						if (e instanceof IOException) {
							Log.error(this.getClass().getSimpleName() + " " + e.toString());
						} else {
							Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
						}
						close();
						doSleep(5000);
					} finally {
						context.getStatistics().decTryingConnections();
					}
				}
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
							case ClusterPacket.CLUSTER_MSG_TYPE_SYNC_BEGIN:
								Log.info("stickyRemoteUpdateNotify: BEGIN");
								break;
							case ClusterPacket.CLUSTER_MSG_TYPE_SYNC_END:
								Log.info("stickyRemoteUpdateNotify: END");
								break;
							case ClusterPacket.CLUSTER_MSG_TYPE_NOP:
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
						Log.error(this.getClass().getSimpleName() + " " + e.toString());
						doSleep(1000);
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
				Log.info(this.getClass().getSimpleName() + " close all: " + sock);
				close();
			}
			Log.info(this.getClass().getSimpleName() + " await end");
			context.awaitShutdown(this);
			Log.info(this.getClass().getSimpleName() + " end");
		}
	}
}
