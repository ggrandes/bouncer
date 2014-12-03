package org.javastack.bouncer.benchmark;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Generate random text [0-9a-zA-Z] and consume InputStream
 */
public class BenchmarkThroughput {
	private static final int CHARGEN_TCP = 19;
	private static final char[] chars = "0123456789abcdefefghijklmnopqrstuvwxyzABCDEFEFGHIJKLMNOPQRSTUVWXYZ"
			.toCharArray();
	private static final ExecutorService threadPool = Executors.newCachedThreadPool();
	private static final int THROUGHTPUT_BYTES = 512 * 1024 * 1024; // 512MB

	public static void main(final String[] args) throws Exception {
		final boolean client = Boolean.getBoolean("client");
		if (client) {
			Socket sock = args.length < 2 ? new Socket("127.0.0.1", CHARGEN_TCP) : //
					new Socket(args[0], Integer.parseInt(args[1]));
			System.out.println("Connected to: " + sock);
			new SocketSync(sock).run();
			threadPool.shutdown();
		} else {
			ServerSocket listen = new ServerSocket(args.length < 1 ? CHARGEN_TCP : Integer.parseInt(args[0]));
			System.out.println("Listen in: " + listen);
			while (true) {
				final Socket sock = listen.accept();
				threadPool.submit(new SocketSync(sock));
			}
		}
	}

	static class SocketSync implements Runnable {
		Socket sock = null;

		public SocketSync(final Socket sock) {
			this.sock = sock;
		}

		@Override
		public void run() {
			final CountDownLatch cdl = new CountDownLatch(2);
			final SocketReader rdr = new SocketReader(sock, cdl);
			final SocketWriter wtr = new SocketWriter(sock, cdl);
			try {
				sock.setSendBufferSize(0xFFFF);
				sock.setReceiveBufferSize(0xFFFF);
				sock.setTcpNoDelay(true);
				System.out.println("Connection begin: " + sock);
				// Read
				threadPool.submit(rdr);
				// Write
				threadPool.submit(wtr);
				// Wait end
				cdl.await();
			} catch (Exception e) {
				e.printStackTrace(System.out);
			} finally {
				System.out.println("Connection end: " + sock);
				close();
			}
		}

		public void close() {
			try {
				sock.shutdownInput();
				sock.shutdownOutput();
				sock.close();
			} catch (Exception ign) {
			}
		}
	}

	static class SocketReader implements Runnable {
		Socket sock = null;
		InputStream is = null;
		CountDownLatch cdl = null;

		public SocketReader(final Socket sock, final CountDownLatch cdl) {
			this.sock = sock;
			this.cdl = cdl;
		}

		@Override
		public void run() {
			int count = 0;
			try {
				is = sock.getInputStream();
				byte[] buf = new byte[1024];
				final long ts = System.currentTimeMillis();
				while (count < THROUGHTPUT_BYTES) {
					final int n = is.read(buf);
					if (n < 0)
						break;
					count += n;
				}
				final long diff = System.currentTimeMillis() - ts;
				final int speed = (int) (count / Math.max(1, diff / 1000) / 1024 / 1024);
				System.out.println("Throughput (rdr):\tdata=" + (count / 1024 / 1024) + "MB\ttime="
						+ (diff / 1000) + "s\tspeed=" + speed + "MB/s\tspeed=" + (speed * 8) + "MBits");
			} catch (IOException e) {
				System.out.println(e.toString() + " " + sock);
			} catch (Throwable t) {
				t.printStackTrace();
			} finally {
				cdl.countDown();
			}
		}
	}

	static class SocketWriter implements Runnable {
		Socket sock = null;
		OutputStream os = null;
		CountDownLatch cdl = null;

		public SocketWriter(final Socket sock, final CountDownLatch cdl) {
			this.sock = sock;
			this.cdl = cdl;
		}

		@Override
		public void run() {
			int count = 0;
			try {
				os = sock.getOutputStream();
				final long ts = System.currentTimeMillis();
				final byte[] buf = new byte[1024];
				for (int i = 0; i < buf.length; i++) {
					buf[i] = (byte) (chars[i % chars.length]);
				}
				while (count < THROUGHTPUT_BYTES) {
					os.write(buf);
					os.flush();
					count += buf.length;
				}
				final long diff = System.currentTimeMillis() - ts;
				final int speed = (int) (count / Math.max(1, diff / 1000) / 1024 / 1024);
				System.out.println("Throughput (wtr):\tdata=" + (count / 1024 / 1024) + "MB\ttime="
						+ (diff / 1000) + "s\tspeed=" + speed + "MB/s\tspeed=" + (speed * 8) + "MBits");
			} catch (IOException e) {
				System.out.println(e.toString() + " " + sock);
			} catch (Throwable t) {
				t.printStackTrace();
			} finally {
				cdl.countDown();
			}
		}
	}
}
