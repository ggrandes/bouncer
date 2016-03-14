package org.javastack.bouncer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocket;

// ============================================ Mux Server

// MuxServer (MUX=IN) Local=MUX, Remote=RAW
class MuxServer {
	final MuxServerMessageRouter router = new MuxServerMessageRouter();
	final HashMap<Integer, MuxServerRemote> mapRemotes = new HashMap<Integer, MuxServerRemote>();
	final ServerContext context;

	MuxServerListenLocal localListen;
	ArrayList<MuxServerListenRemote> remoteListen = new ArrayList<MuxServerListenRemote>(1);
	MuxServerLocal local = null;

	final InboundAddress left;
	final Map<Integer, InboundAddress> right;

	MuxServer(final ServerContext context, final InboundAddress left, final InboundAddress right) {
		this.context = context;
		this.left = left;
		this.right = (right == null ? new HashMap<Integer, InboundAddress>() : //
				Collections.singletonMap(Integer.valueOf(0), right));
	}

	void addRight(final InboundAddress right) {
		this.right.put(right.getOpts().getTunID(), right);
	}

	void listenLocal() throws IOException { // Entry Point
		localListen = new MuxServerListenLocal(left); // Local is MUX
		context.addReloadableAwaiter(localListen);
		context.submitTask(localListen, "MuxInListenLeft[" + left + "]", ClientId.newId());
	}

	void listenRemote() throws IOException {
		for (InboundAddress right : this.right.values()) {
			try {
				final MuxServerListenRemote remoteListen = new MuxServerListenRemote(right); // Remote is RAW
				this.remoteListen.add(remoteListen);
				context.addReloadableAwaiter(remoteListen);
				context.submitTask(remoteListen, "MuxInListenRight[" + left + "|" + right + "]",
						ClientId.newId());
			} catch (IOException e) {
				Log.error(this.getClass().getSimpleName() + "::listenRemote " + e.toString(), e);
			}
		}
	}

	void closeRemote() {
		for (final MuxServerListenRemote remoteListen : this.remoteListen) {
			remoteListen.setShutdown();
		}
	}

	void closeRemote(final int id) {
		// Send FIN
		try {
			final MuxPacket mux = context.allocateMuxPacket();
			mux.fin(id);
			local.sendLocal(mux);
			context.releaseMuxPacket(mux);
		} catch (Exception ign) {
		}
		//
		synchronized (mapRemotes) {
			final MuxServerRemote remote = mapRemotes.remove(id);
			if (remote != null) {
				remote.setShutdown();
			}
		}
	}

	void sendACK(final RawPacket msg) {
		// Send ACK
		try {
			final MuxPacket mux = context.allocateMuxPacket();
			mux.ack(msg.getIdChannel(), msg.getBufferLen());
			local.sendLocal(mux);
			context.releaseMuxPacket(mux);
		} catch (Exception ign) {
		}
	}

	void sendNOP() {
		// Send NOP
		try {
			final MuxPacket mux = context.allocateMuxPacket();
			mux.nop(0);
			local.sendLocal(mux);
			context.releaseMuxPacket(mux);
		} catch (Exception ign) {
		}
	}

	MuxServerRemote getRemote(final int id) {
		synchronized (mapRemotes) {
			return mapRemotes.get(id);
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

	class MuxServerMessageRouter {
		void onReceiveFromLocal(final MuxServerLocal local, final MuxPacket msg) { // Local is MUX
			// Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
			if (msg.syn()) { // This is SYN/ACK
				final MuxServerRemote remote = getRemote(msg.getIdChannel());
				if (remote != null)
					remote.unlock(Constants.BUFFER_LEN * Constants.IO_BUFFERS);
			} else if (msg.fin()) { // End SubChannel
				Log.info(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
				final MuxServerRemote remote = getRemote(msg.getIdChannel());
				if (remote != null)
					remote.setShutdown();
			} else if (msg.ack()) { // Flow-Control ACK
				Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
				final MuxServerRemote remote = getRemote(msg.getIdChannel());
				if (remote != null)
					remote.unlock(msg.ackSize());
			} else if (msg.nop()) { // NOP
				Log.info(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
			} else { // Data
				Log.debug(this.getClass().getSimpleName() + "::onReceiveFromLocal " + msg);
				try {
					final MuxServerRemote remote = getRemote(msg.getIdChannel());
					if (remote == null)
						return;
					final RawPacket raw = context.allocateRawPacket();
					raw.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
					remote.sendQueueRemote(raw);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + "::onReceiveFromLocal " + e.toString(), e);
				}
			}
		}

		void onReceiveFromRemote(final MuxServerRemote remote, final RawPacket msg) { // Remote is RAW
			Log.debug(this.getClass().getSimpleName() + "::onReceiveFromRemote " + msg);
			try {
				final MuxPacket mux = context.allocateMuxPacket();
				mux.put(msg.getIdChannel(), msg.getBufferLen(), msg.getBuffer());
				local.sendLocal(mux);
				context.releaseMuxPacket(mux);
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + "::onReceiveFromRemote " + e.toString(), e);
			}
		}
	}

	abstract class MuxServerListen implements Awaiter, Runnable { // Local is MUX, Remote is RAW
		final InboundAddress inboundAddress;
		final ServerSocket listen;
		boolean shutdown = false;

		MuxServerListen(final InboundAddress inboundAddress) throws IOException {
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

		//
		protected abstract void attender(Socket socket) throws IOException;
	}

	class MuxServerListenLocal extends MuxServerListen { // Local is MUX
		MuxServerListenLocal(final InboundAddress inboundAddress) throws IOException {
			super(inboundAddress);
		}

		@Override
		protected synchronized void attender(final Socket socket) throws IOException {
			Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
			if ((local == null) || local.isClosed()) {
				try {
					socket.setSoTimeout(Constants.MUX_READ_TIMEOUT);
				} catch (Exception ign) {
				}
				local = new MuxServerLocal(socket, inboundAddress);
				local.setRouter(router);
				context.addShutdownable(local);
				listenRemote();
				context.submitTask(local, "MuxInLeft[" + left + "|" + IOHelper.socketRemoteToString(socket)
						+ "]", ClientId.newId());
			} else {
				// Only one concurrent client, close the new connection
				Log.error(this.getClass().getSimpleName()
						+ " This listener already connected, closing socket: " + socket);
				sendNOP(); // FIXME: Try to check
				doSleep(1000);
				context.closeSilent(socket);
			}
		}
	}

	class MuxServerListenRemote extends MuxServerListen { // Remote is RAW
		MuxServerListenRemote(final InboundAddress inboundAddress) throws IOException {
			super(inboundAddress);
		}

		@Override
		protected synchronized void attender(final Socket socket) throws IOException {
			Log.info(this.getClass().getSimpleName() + " attending socket: " + socket);
			final MuxServerRemote remote = new MuxServerRemote(socket, inboundAddress);
			remote.setRouter(router);
			mapRemotes.put(remote.getId(), remote);
			context.submitTask(remote, "MuxInRight-Recv[" + socket.getPort() + "|" + left + "|" + right + "|"
					+ IOHelper.socketRemoteToString(socket) + "]",
					(((long) socket.getPort() << 48) | ClientId.newId()));
		}
	}

	abstract class MuxServerConnection implements Shutdownable, Runnable { // Local is MUX, Remote is RAW
		final Socket sock;
		final InboundAddress inboundAddress;
		final InputStream is;
		final OutputStream os;
		MuxServerMessageRouter router;
		boolean shutdown = false;

		//
		MuxServerConnection(final Socket sock, final InboundAddress inboundAddress) throws IOException {
			this.sock = sock;
			this.inboundAddress = inboundAddress;
			is = sock.getInputStream();
			os = sock.getOutputStream();
		}

		void setRouter(final MuxServerMessageRouter router) {
			this.router = router;
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
	}

	class MuxServerLocal extends MuxServerConnection implements Awaiter { // Local is MUX
		final SealerAES seal;

		MuxServerLocal(final Socket sock, final InboundAddress inboundAddress) throws IOException {
			super(sock, inboundAddress);
			if (inboundAddress.getOpts().isOption(Options.MUX_AES)) {
				seal = new SealerAES(inboundAddress.getOpts().getString(Options.P_AES), //
						inboundAddress.getOpts().getString(Options.P_AES_ALG), //
						inboundAddress.getOpts().getInteger(Options.P_AES_BITS, Integer.MIN_VALUE), //
						true);
			} else {
				seal = null;
			}
		}

		void sendLocal(final MuxPacket msg) throws IOException, GeneralSecurityException {
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
		public void run() {
			Log.info(this.getClass().getSimpleName() + "::run socket: " + sock);
			long muxNopKeepAlive = System.currentTimeMillis();
			while (!shutdown || !mapRemotes.isEmpty()) {
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
					router.onReceiveFromLocal(this, msg);
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
			closeRemote();
			synchronized (mapRemotes) { // Remotes are RAW
				for (MuxServerRemote r : mapRemotes.values()) {
					r.setShutdown();
				}
				mapRemotes.clear();
			}
			Log.info(this.getClass().getSimpleName() + " await end");
			context.awaitShutdown(this);
			Log.info(this.getClass().getSimpleName() + " end");
			local = null;
		}
	}

	class MuxServerRemote extends MuxServerConnection { // Remote is RAW
		final Semaphore isLocked = new Semaphore(0); // Begin Locked
		final ArrayBlockingQueue<RawPacket> queue = new ArrayBlockingQueue<RawPacket>(
				Constants.IO_BUFFERS << 1);
		final int id;
		long keepalive = System.currentTimeMillis();

		MuxServerRemote(final Socket sock, final InboundAddress inboundAddress) throws IOException {
			super(sock, inboundAddress);
			id = sock.getPort();
		}

		void unlock(final int size) {
			isLocked.release(size);
		}

		boolean lock(final int size) throws InterruptedException {
			return isLocked.tryAcquire(size, 3000, TimeUnit.MILLISECONDS);
		}

		int getId() {
			return id;
		}

		void sendQueueRemote(final RawPacket msg) throws IOException {
			try {
				while (!queue.offer(msg, 1000, TimeUnit.MILLISECONDS)) {
					if (shutdown)
						break;
				}
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
				final MuxPacket mux = context.allocateMuxPacket();
				final int idEndpoint = inboundAddress.getOpts().getTunID();
				mux.syn(id, idEndpoint, sock.getInetAddress());
				local.sendLocal(mux);
				while (!lock(1)) {
					if (shutdown) {
						close();
						break;
					}
				}
				unlock(1);
				context.releaseMuxPacket(mux);
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + "::syn-send " + e.toString(), e);
			}
			// Send Headers
			if (inboundAddress.getOpts().isOption(Options.PROXY_SEND)) {
				try {
					final MuxPacket mux = context.allocateMuxPacket();
					final byte[] header = ProxyProtocol.getInstance().formatV1(sock).getBytes();
					mux.put(id, header.length, header);
					local.sendLocal(mux);
					while (!lock(header.length)) {
						if (shutdown) {
							close();
							break;
						}
					}
					unlock(header.length);
					context.releaseMuxPacket(mux);
				} catch (Exception e) {
					Log.error(this.getClass().getSimpleName() + "::proxy-send " + e.toString(), e);
				}
			}
			//
			if (!shutdown) {
				context.submitTask(new Runnable() {
					@Override
					public void run() {
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
									Log.error(this.getClass().getName() + "::sendRemote " + e.toString());
								}
							} catch (Exception e) {
								Log.error(this.getClass().getName() + " Generic exception", e);
							}
						}
						close();
					}
				}, "MuxInRight-Send[" + id + "|" + inboundAddress + "|" + IOHelper.socketRemoteToString(sock)
						+ "]", ClientId.getId());
			}
			//
			int pkt = 0;
			OUTTER: while (!shutdown) {
				try {
					final RawPacket msg = context.allocateRawPacket();
					msg.fromWire(is);
					msg.setIdChannel(id);
					pkt++;
					while (!lock(msg.getBufferLen())) {
						if (shutdown)
							break OUTTER;
						Log.info(this.getClass().getSimpleName() + " Timeout Locking(" + pkt + "): " + sock);
					}
					context.getStatistics().incInMsgs().incInBytes(msg.getBufferLen());
					router.onReceiveFromRemote(this, msg);
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
			closeRemote(id);
			close();
			Log.info(this.getClass().getSimpleName() + " end");
		}
	}
}
