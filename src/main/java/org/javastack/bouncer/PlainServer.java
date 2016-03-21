package org.javastack.bouncer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import javax.net.ssl.SSLSocket;

/**
 * Forward Plain Connections
 */
class PlainServer {
	final ServerContext context;
	final InboundAddress inboundAddress;
	final OutboundAddress outboundAddress;

	PlainServer(final ServerContext context, final InboundAddress inboundAddress,
			final OutboundAddress outboundAddress) {
		this.context = context;
		this.inboundAddress = inboundAddress;
		this.outboundAddress = outboundAddress;
	}

	void listenLocal() { // Entry Point
		final PlainListen acceptator = new PlainListen();
		context.addReloadableAwaiter(acceptator);
		context.submitTask(acceptator, "ForwardListen[" + inboundAddress + "]", ClientId.newId());
	}

	class PlainListen implements Awaiter, Runnable {
		ServerSocket listen;
		volatile boolean shutdown = false;

		@Override
		public void setShutdown() {
			shutdown = true;
			context.closeSilent(listen);
		}

		@Override
		public void run() {
			try {
				listen = inboundAddress.listen();
				Log.info(this.getClass().getSimpleName() + " started: " + inboundAddress);
				while (!shutdown) {
					try {
						final Socket client = listen.accept();
						try {
							context.registerSocket(client);
							final Integer pReadTimeout = inboundAddress.getOpts().getInteger(
									Options.P_READ_TIMEOUT);
							if (pReadTimeout != null) {
								client.setSoTimeout(pReadTimeout);
							}
							if (client instanceof SSLSocket) {
								((SSLSocket) client).startHandshake();
							}
							Log.info(this.getClass().getSimpleName() + " New client from=" + client + " "
									+ SSLFactory.getSocketProtocol(client));
							context.submitTask(
									new PlainConnector(client, inboundAddress.getOpts()),
									"ForwardConnect[" + inboundAddress + "|"
											+ IOHelper.socketRemoteToString(client) + "]",
									(((long) client.getPort() << 48) | ClientId.newId()));
						} catch (Exception e) {
							Log.error(this.getClass().getSimpleName() + " Exception: " + e.toString(), e);
							context.closeSilent(client);
						}
					} catch (SocketTimeoutException e) {
						continue;
					} catch (Exception e) {
						if (!listen.isClosed()) {
							Log.error(this.getClass().getSimpleName() + " " + e.toString(), e);
						}
					}
				}
			} catch (IOException e) {
				Log.error(this.getClass().getSimpleName() + " " + e.toString());
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " Generic exception", e);
			} finally {
				Log.info(this.getClass().getSimpleName() + " await end");
				context.awaitShutdown(this);
				Log.info(this.getClass().getSimpleName() + " end");
			}
		}
	}

	class PlainConnector implements Shutdownable, Runnable {
		final Socket client;
		final Options options;
		Socket remote = null;
		volatile boolean shutdown = false;

		PlainConnector(final Socket client, final Options options) {
			this.client = client;
			this.options = options;
		}

		@Override
		public void setShutdown() {
			shutdown = true;
			close();
		}

		void close() {
			// FIXME: java.lang.NullPointerException: SocketRegistrator.unregisterSocket(Socket==null)
			if (client != null)
				context.closeSilent(client);
			if (remote != null)
				context.closeSilent(remote);
		}

		@Override
		public void run() {
			Log.info(this.getClass().getSimpleName() + " started: " + outboundAddress);
			try {
				try {
					context.getStatistics().incTryingConnections();
					remote = outboundAddress.connectFrom(client.getInetAddress());
				} finally {
					context.getStatistics().decTryingConnections();
				}
				if (remote == null)
					throw new ConnectException("Unable to connect to " + outboundAddress);
				Log.info(this.getClass().getSimpleName() + " Bouncer from " + client + " to " + remote);
				final PlainSocketTransfer st1 = new PlainSocketTransfer(client, remote);
				final PlainSocketTransfer st2 = new PlainSocketTransfer(remote, client);
				if (options.isOption(Options.PROXY_SEND)) {
					st1.setHeadersBuffer(ProxyProtocol.getInstance().formatV1(client).getBytes());
				}
				st1.setBrother(st2);
				st2.setBrother(st1);
				context.submitTask(
						st1,
						"ForwardTransfer-CliRem[" + inboundAddress + "|"
								+ IOHelper.socketRemoteToString(client) + "|"
								+ IOHelper.socketRemoteToString(remote) + "]", ClientId.getId());
				context.submitTask(
						st2,
						"ForwardTransfer-RemCli[" + inboundAddress + "|"
								+ IOHelper.socketRemoteToString(remote) + "|"
								+ IOHelper.socketRemoteToString(client) + "]", ClientId.getId());
			} catch (IOException e) {
				Log.error(this.getClass().getSimpleName() + " " + e.toString());
				close();
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " Generic exception", e);
				close();
			} finally {
				Log.info(this.getClass().getSimpleName() + " ended: " + outboundAddress);
			}
		}
	}

	/**
	 * Transfer data between sockets
	 */
	class PlainSocketTransfer implements Shutdownable, Runnable {
		final byte[] buf = new byte[Constants.BUFFER_LEN];
		final Socket sockin;
		final Socket sockout;
		final InputStream is;
		final OutputStream os;
		volatile boolean shutdown = false;
		byte[] headers = null;

		long keepalive = System.currentTimeMillis();
		PlainSocketTransfer brother = null;

		PlainSocketTransfer(final Socket sockin, final Socket sockout) throws IOException {
			this.sockin = sockin;
			this.sockout = sockout;
			this.is = sockin.getInputStream();
			this.os = sockout.getOutputStream();
		}

		void setBrother(final PlainSocketTransfer brother) {
			this.brother = brother;
		}

		void setHeadersBuffer(final byte[] headers) {
			this.headers = headers;
		}

		@Override
		public void setShutdown() {
			shutdown = true;
		}

		@Override
		public void run() {
			try {
				if (headers != null) {
					context.getStatistics().incOutMsgs().incOutBytes(headers.length);
					os.write(headers, 0, headers.length);
					os.flush();
					headers = null;
				}
				final int TIMEOUT = sockin.getSoTimeout();
				sockin.setSoTimeout(250);
				while (!shutdown) {
					try {
						if (!shutdown && transfer()) {
							keepalive = System.currentTimeMillis();
							continue;
						}
					} catch (SocketTimeoutException e) {
						// Idle Timeout
						if (TIMEOUT > 0) {
							final long now = System.currentTimeMillis();
							if (((now - keepalive) > TIMEOUT) || ((now - brother.keepalive) > TIMEOUT)) {
								Log.info(this.getClass().getSimpleName() + " " + e.toString());
								setShutdown();
							}
						}
					}
				}
			} catch (IOException e) {
				if (!sockin.isClosed() && !shutdown) {
					Log.error(this.getClass().getSimpleName() + " " + e.toString() + " " + sockin);
				}
			} catch (Exception e) {
				Log.error(this.getClass().getSimpleName() + " Generic exception", e);
			} finally {
				context.closeSilent(sockin);
				if (brother != null) {
					brother.setShutdown();
				}
				Log.info(this.getClass().getSimpleName() + " Connection closed " + sockin);
			}
		}

		boolean transfer() throws IOException {
			final int len = is.read(buf, 0, buf.length);
			if (len < 0) {
				context.closeSilent(sockin);
				throw new EOFException("EOF");
			}
			context.getStatistics().incInMsgs().incInBytes(len);
			os.write(buf, 0, len);
			os.flush();
			context.getStatistics().incOutMsgs().incOutBytes(len);
			return true;
		}
	}
}
