package org.javastack.bouncer.benchmark;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Client for EchoServer that measures latency.
 * 
 * <a href="https://github.com/ggrandes/sandbox/blob/master/src/EchoServer.java">EchoServer on GitHub</a>
 */
public class BenchmarkLatency {
	private static final int LATENCY_ITERATIONS = 100000; // 100K packets
	private static final char[] chars = "0123456789abcdefefghijklmnopqrstuvwxyzABCDEFEFGHIJKLMNOPQRSTUVWXYZ"
			.toCharArray();

	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			System.out.println(BenchmarkLatency.class.getName() + " <host> <port>");
			return;
		}
		final Socket sock = new Socket(args[0], Integer.parseInt(args[1]));
		System.out.println("Connected to: " + sock);
		sock.setSendBufferSize(0xFFFF);
		sock.setReceiveBufferSize(0xFFFF);
		sock.setTcpNoDelay(true);
		OutputStream os = null;
		InputStream is = null;
		try {
			os = sock.getOutputStream();
			is = sock.getInputStream();
			byte[] buf = new byte[1];
			int c = 0;
			long min = Long.MAX_VALUE, max = Long.MIN_VALUE, avg = 0;
			os.write(' ');
			is.read(buf);
			// Latency
			while (c < LATENCY_ITERATIONS) {
				final long ts = System.nanoTime();
				os.write(chars[++c % chars.length]);
				final int n = is.read(buf);
				if (n < 0)
					break;
				final long t = System.nanoTime() - ts;
				if (t < min) {
					min = t;
				} else if (t > max) {
					max = t;
				}
				avg += t;
			}
			System.out.println("Latency:\tpackets=" + c + "\tmin=" + min / 1000 + "\u00B5s\tmax=" + max
					/ 1000 + "\u00B5s\tavg=" + (avg / c / 1000) + "\u00B5s");
		} catch (IOException e) {
			System.out.println(e.toString() + " " + sock);
		} catch (Throwable t) {
			t.printStackTrace();
		}
		try {
			is.close();
		} catch (Exception ign) {
		}
		try {
			os.close();
		} catch (Exception ign) {
		}
		try {
			sock.close();
		} catch (Exception ign) {
		}
	}
}
