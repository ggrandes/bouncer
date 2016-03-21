package org.javastack.bouncer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocket;

// ============================================ Mux Client

// MuxClient (MUX=OUT) Local=RAW, Remote=MUX
class MuxClient {
	final MuxClientMessageRouter router = new MuxClientMessageRouter();
	final HashMap<Integer, MuxClientLocal> mapLocals = new HashMap<Integer, MuxClientLocal>();
	final ServerContext context;
	final Map<Integer, OutboundAddress> left;
	final OutboundAddress right;

	MuxClientRemote remote;

	MuxClient(final ServerContext context, final OutboundAddress left, final OutboundAddress right) {
		this.context = context;
		this.left = (left == null ? new HashMap<Integer, OutboundAddress>() : //
				Collections.singletonMap(Integer.valueOf(0), left));
		this.right = right;
	}

	void addLeft(final OutboundAddress left) {
		this.left.put(left.getOpts().getTunID(), left);
	}

	void openRemote() throws IOException { // Entry Point
		Log.info(this.getClass().getSimpleName() + "::openRemote " + right);
		remote = new MuxClientRemote(right);
		remote.setRouter(router);
		context.addShutdownable(remote);
		context.submitTask(remote, "MuxOutRight[" + right + "]", ClientId.newId());
	}

	void openLocal(final int id, final int idEndPoint, final InetAddress srcAddress) {
		Log.info(this.getClass().getSimpleName() + "::openLocal id=" + id + " srcAddr="
				+ String.valueOf(srcAddress));
		final OutboundAddress left = this.left.get(Integer.valueOf(idEndPoint));
		final MuxClientLocal local = new MuxClientLocal(left);
		local.setId(id);
		local.setSticky(srcAddress);
		local.setRouter(router);
		synchronized (mapLocals) {
			mapLocals.put(id, local);
		}
		context.submitTask(local, "MuxOutLeft-Recv[" + id + "|" + right + "]",
				(((long) id << 48) | ClientId.newId()));
	}

	void closeLocal(final int id) {
		// Send FIN
		try {
			final MuxPacket mux = context.allocateMuxPacket();
			mux.fin(id);
			remote.sendRemote(mux);
			context.releaseMuxPacket(mux);
		} catch (Exception ign) {
		}
		synchronized (mapLocals) {
			final MuxClientLocal local = mapLocals.remove(id);
			if (local != null) {
				local.setShutdown();
			}
		}
	}

	void sendACK(final RawPacket msg) {
		// Send ACK
		try {
			final MuxPacket mux = context.allocateMuxPacket();
			mux.ack(msg.getIdChannel(), msg.getBufferLen());
			remote.sendRemote(mux);
			context.releaseMuxPacket(mux);
		} catch (Exception ign) {
		}
	}

	void sendNOP() {
		// Send NOP
		try {
			final MuxPacket mux = context.allocateMuxPacket();
			mux.nop(0);
			remote.sendRemote(mux);
			context.releaseMuxPacket(mux);
		} catch (Exception ign) {
		}
	}

	MuxClientLocal getLocal(final int id) {
		synchronized (mapLocals) {
			return mapLocals.get(id);
		}
	}

	static void doSleep(final long time) {
		try {
			Thread.sleep(time);
		} catch (InterruptedException ie) {
			Thread.currentThread().interrupt();
		}
	}

	// ============================================

	class MuxClientMessageRouter {
		void onReceiveFromRemote(final MuxClientRemote remote, final MuxPacket msg) { // Remote is MUX
			if (msg.syn()) { // New SubChannel
				Log.info(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				openLocal(msg.getIdChannel(), msg.getIdEndPoint(), msg.getSourceAddress());
			} else if (msg.fin()) { // End SubChannel
				Log.info(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				final MuxClientLocal local = getLocal(msg.getIdChannel());
				if (local != null)
					local.setShutdown();
			} else if (msg.ack()) { // Flow-Control ACK
				Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				final MuxClientLocal local = getLocal(msg.getIdChannel());
				if (local != null)
					local.unlock(msg.ackSize());
			} else if (msg.nop()) { // NOP
				Log.info(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
			} else { // Data
				Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
				try {
					final MuxClientLocal local = getLocal(msg.getIdChannel());
					if (local == null)
						return;
					final RawPacket raw = context.allocateRawPacket();
					raw.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
					local.sendQueueLocal(raw);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
				}
			}
		}

		void onReceiveFromLocal(final MuxClientLocal local, final RawPacket msg) { // Local is RAW
			Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
			try {
				final MuxPacket mux = context.allocateMuxPacket();
				mux.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
				remote.sendRemote(mux);
				context.releaseMuxPacket(mux);
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + "::onReceiveFromLocal " + e.toString(), e);
			}
		}
	}

	abstract class MuxClientConnection implements Shutdownable, Runnable { // Remote is MUX, Local is RAW
		final OutboundAddress outboundAddress;

		Socket sock;
		InputStream is;
		OutputStream os;
		MuxClientMessageRouter router;
		boolean shutdown = false;

		MuxClientConnection(final OutboundAddress outboundAddress) {
			this.outboundAddress = outboundAddress;
		}

		void setRouter(final MuxClientMessageRouter router) {
			this.router = router;
		}

		@Override
		public void setShutdown() {
			shutdown = true;
			// Graceful Shutdown: don't call close()
		}

		synchronized void close() {
			if (((sock == null) || sock.isClosed()))
				return;
			if (sock instanceof SSLSocket) {
				try {
					sock.setSoTimeout(1000);
					is.read();
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + " Closing: " + sock + ": " + e);
				}
			}
			IOHelper.closeSilent(is);
			IOHelper.closeSilent(os);
			if (sock != null)
				context.closeSilent(sock);
			sock = null;
		}
	}

	class MuxClientRemote extends MuxClientConnection implements Awaiter { // Remote is MUX
		final SealerAES seal;

		MuxClientRemote(final OutboundAddress outboundAddress) throws IOException {
			super(outboundAddress);
			if (outboundAddress.getOpts().isOption(Options.MUX_AES)) {
				seal = new SealerAES(outboundAddress.getOpts().getString(Options.P_AES), //
						outboundAddress.getOpts().getString(Options.P_AES_ALG), //
						outboundAddress.getOpts().getInteger(Options.P_AES_BITS, Integer.MIN_VALUE), //
						false);
			} else {
				seal = null;
			}
		}

		void sendRemote(final MuxPacket msg) throws IOException, GeneralSecurityException {
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
			context.getStatistics().incOutMsgs().incOutBytes(msg.getBufferLen());
		}

		@Override
		public void setShutdown() {
			shutdown = true;
			// Graceful Shutdown: don't call close()
		}

		@Override
		public void run() {
			long muxNopKeepAlive = System.currentTimeMillis();
			while (!shutdown) {
				while (!shutdown) {
					try {
						Log.info(this.getClass().getSimpleName() + " Connecting: " + outboundAddress);
						context.getStatistics().incTryingConnections();
						sock = outboundAddress.connect();
						if (sock == null)
							throw new ConnectException("Unable to connect to " + outboundAddress);
						try {
							sock.setSoTimeout(Constants.MUX_READ_TIMEOUT); // Timeout for MUX
						} catch (Exception ign) {
						}
						is = sock.getInputStream();
						os = sock.getOutputStream();
						Log.info(this.getClass().getSimpleName() + " Connected: " + sock + " SendBufferSize="
								+ sock.getSendBufferSize() + " ReceiveBufferSize="
								+ sock.getReceiveBufferSize());
						if (seal != null)
							seal.reset();
						sendNOP();
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
				while (!shutdown || !mapLocals.isEmpty()) {
					try {
						final MuxPacket msg = context.allocateMuxPacket();
						if (seal != null) {
							// AES encryption
							final byte[] encoded = IOHelper.fromWireWithHeader(is);
							final byte[] decoded = seal.decode(encoded, 0, encoded.length);
							final ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
							msg.fromWire(bais);
						} else {
							msg.fromWire(is);
						}
						context.getStatistics().incInMsgs().incInBytes(msg.getBufferLen());
						router.onReceiveFromRemote(this, msg);
						context.releaseMuxPacket(msg);
					} catch (SocketTimeoutException e) {
						final long now = System.currentTimeMillis();
						if ((muxNopKeepAlive + Constants.MUX_KEEP_ALIVE) < now) {
							Log.debug(this.getClass().getSimpleName() + " " + e.toString());
							sendNOP();
							muxNopKeepAlive = now;
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
				synchronized (mapLocals) { // Locals are RAW
					for (MuxClientLocal l : mapLocals.values()) {
						l.setShutdown();
					}
					mapLocals.clear();
				}
			}
			Log.info(this.getClass().getSimpleName() + " await end");
			context.awaitShutdown(this);
			Log.info(this.getClass().getSimpleName() + " end");
		}
	}

	class MuxClientLocal extends MuxClientConnection { // Local is RAW
		final Semaphore isLocked = new Semaphore(Constants.BUFFER_LEN * Constants.IO_BUFFERS);
		final ArrayBlockingQueue<RawPacket> queue = new ArrayBlockingQueue<RawPacket>(
				Constants.IO_BUFFERS << 1);
		int id;
		InetAddress stickyAddress = null;
		long keepalive = System.currentTimeMillis();

		MuxClientLocal(final OutboundAddress outboundAddress) {
			super(outboundAddress);
		}

		public void setSticky(final InetAddress stickyAddress) {
			this.stickyAddress = stickyAddress;
		}

		void unlock(final int size) {
			isLocked.release(size);
		}

		boolean lock(final int size) throws InterruptedException {
			return isLocked.tryAcquire(size, 3000, TimeUnit.MILLISECONDS);
		}

		void setId(final int id) {
			this.id = id;
		}

		void sendQueueLocal(final RawPacket msg) throws IOException {
			try {
				while (!queue.offer(msg, 1000, TimeUnit.MILLISECONDS)) {
					if (shutdown)
						break;
				}
				keepalive = System.currentTimeMillis();
			} catch (InterruptedException e) {
				Log.error(this.getClass().getSimpleName() + "::sendLocal " + e.toString(), e);
			}
		}

		@Override
		public void run() {
			Log.info(this.getClass().getSimpleName() + "::run " + outboundAddress);
			//
			try {
				try {
					context.getStatistics().incTryingConnections();
					sock = outboundAddress.connectFrom(stickyAddress);
				} finally {
					context.getStatistics().decTryingConnections();
				}
				if (sock == null)
					throw new ConnectException("Unable to connect to " + outboundAddress);
				is = sock.getInputStream();
				os = sock.getOutputStream();
				// Send SYN/ACK
				try {
					final MuxPacket mux = context.allocateMuxPacket();
					mux.syn(id);
					remote.sendRemote(mux);
					context.releaseMuxPacket(mux);
				} catch (Exception ign) {
				}
			} catch (Exception e) {
				if (e instanceof IOException) {
					Log.error(this.getClass().getSimpleName() + " " + e.toString());
				} else {
					Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
				}
				setShutdown();
				close();
			}
			//
			if (!shutdown) {
				context.submitTask(new Runnable() {
					@Override
					public void run() {
						Log.info(this.getClass().getName() + "::run " + sock);
						while (!shutdown || !queue.isEmpty()) {
							try {
								final RawPacket msg = queue.poll(1000, TimeUnit.MILLISECONDS);
								if (msg == null)
									continue;
								msg.toWire(os);
								context.getStatistics().incOutMsgs().incOutBytes(msg.getBufferLen());
								sendACK(msg); // Send ACK
								context.releaseRawPacket(msg);
							} catch (IOException e) {
								if (!sock.isClosed() && !shutdown) {
									Log.error(this.getClass().getName() + "::sendLocal " + e.toString());
								}
							} catch (Exception e) {
								Log.error(this.getClass().getName() + " Generic exception", e);
							}
						}
						close();
					}
				}, "MuxOutLeft-Send[" + id + "|" + right + "]", ClientId.getId());
			}
			//
			int pkt = 0;
			OUTTER: while (!shutdown) {
				try {
					// Log.info(this.getClass().getSimpleName() + "::run fromWire: " + sock);
					final RawPacket msg = context.allocateRawPacket();
					msg.fromWire(is);
					msg.setIdChannel(id);
					pkt++;
					while (!lock(msg.getBufferLen())) {
						if (shutdown)
							break OUTTER;
						Log.info(this.getClass().getSimpleName() + " Timeout Locking(" + pkt + "): " + sock);
					}
					// Log.info(this.getClass().getSimpleName() + "::run onReceiveFromLocal: " + sock);
					context.getStatistics().incInMsgs().incInBytes(msg.getBufferLen());
					router.onReceiveFromLocal(this, msg);
					context.releaseRawPacket(msg);
				} catch (SocketTimeoutException e) {
					Log.info(this.getClass().getSimpleName() + " " + e.toString());
					try {
						// Idle Timeout
						final long now = System.currentTimeMillis();
						if ((sock.getSoTimeout() + keepalive) < now) {
							break;
						}
					} catch (Exception brk) {
						break;
					}
				} catch (EOFException e) {
					break;
				} catch (IOException e) {
					if (!sock.isClosed() && !shutdown) {
						Log.error(this.getClass().getSimpleName() + " " + e.toString());
					}
					break;
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + " Generic exception", e);
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
