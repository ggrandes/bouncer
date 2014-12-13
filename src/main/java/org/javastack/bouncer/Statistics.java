package org.javastack.bouncer;

import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.javastack.bouncer.jmx.BouncerStatisticsMBean;

public class Statistics implements BouncerStatisticsMBean {
	// Concurrents
	private final AtomicInteger tryingConnections = new AtomicInteger();
	private final AtomicInteger activeConnections = new AtomicInteger();

	// Counters
	private final AtomicInteger reloads = new AtomicInteger();
	private final AtomicLong attendedConnections = new AtomicLong();
	private final AtomicLong failedConnections = new AtomicLong();
	private final AtomicLong inMsgs = new AtomicLong();
	private final AtomicLong outMsgs = new AtomicLong();
	private final AtomicLong inBytes = new AtomicLong();
	private final AtomicLong outBytes = new AtomicLong();

	// Concurrents

	public void incTryingConnections() {
		tryingConnections.incrementAndGet();
	}

	public void decTryingConnections() {
		tryingConnections.decrementAndGet();
	}

	@Override
	public int getTryingConnections() {
		return tryingConnections.get();
	}

	public void incActiveConnections() {
		activeConnections.incrementAndGet();
	}

	public void decActiveConnections() {
		activeConnections.decrementAndGet();
	}

	@Override
	public int getActiveConnections() {
		return activeConnections.get();
	}

	// Counters

	public void incReloads() {
		reloads.incrementAndGet();
	}

	@Override
	public int getReloads() {
		return reloads.get();
	}

	public void incAttendedConnections() {
		attendedConnections.incrementAndGet();
	}

	@Override
	public long getAttendedConnections() {
		return attendedConnections.get();
	}

	public void incFailedConnections() {
		failedConnections.incrementAndGet();
	}

	@Override
	public long getFailedConnections() {
		return failedConnections.get();
	}

	public Statistics incInMsgs() {
		inMsgs.incrementAndGet();
		return this;
	}

	@Override
	public long getInMsgs() {
		return inMsgs.get();
	}

	public Statistics incOutMsgs() {
		outMsgs.incrementAndGet();
		return this;
	}

	@Override
	public long getOutMsgs() {
		return outMsgs.get();
	}

	public Statistics incInBytes(final int bytes) {
		inBytes.addAndGet(bytes);
		return this;
	}

	@Override
	public long getInBytes() {
		return inBytes.get();
	}

	public Statistics incOutBytes(final int bytes) {
		outBytes.addAndGet(bytes);
		return this;
	}

	@Override
	public long getOutBytes() {
		return outBytes.get();
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		sb.append("[ ");
		sb.append("connections: { ");
		sb.append("trying: ").append(tryingConnections.get()).append(", ");
		sb.append("active: ").append(activeConnections.get()).append(", ");
		sb.append("attended: ").append(attendedConnections.get()).append(", ");
		sb.append("failed: ").append(failedConnections.get());
		sb.append(" }, ");
		sb.append("msgs: { ");
		sb.append("in: ").append(inMsgs.get()).append(", ");
		sb.append("out: ").append(outMsgs.get());
		sb.append(" }, ");
		sb.append("bytes: { ");
		sb.append("in: ").append(toHumanReadable(inBytes.get())).append(", ");
		sb.append("out: ").append(toHumanReadable(outBytes.get()));
		sb.append(" }, ");
		sb.append("reloads: ").append(reloads.get());
		sb.append(" ]");
		return sb.toString();
	}

	private static final String toHumanReadable(final long bytes) {
		double d = bytes;
		int f = 0;
		while ((d >= 1024) && (f < 60)) {
			d /= 1024;
			f += 10;
		}
		final DecimalFormat df = new DecimalFormat("#.##");
		final DecimalFormatSymbols dfs = DecimalFormatSymbols.getInstance(Locale.US);
		df.setDecimalFormatSymbols(dfs);
		df.setRoundingMode(RoundingMode.CEILING);
		final String b = df.format(d);
		// http://es.wikipedia.org/wiki/Byte#M.C3.BAltiplos_utilizando_los_prefijos_ISO.2FIEC_80000-13
		switch (f) {
			case 0:
				return b + "B";
			case 10:
				return b + "KiB";
			case 20:
				return b + "MiB";
			case 30:
				return b + "GiB";
			case 40:
				return b + "TiB";
			case 50:
				return b + "PiB";
			case 60:
				return b + "EiB";
		}
		return bytes + "???";
	}

	public static void main(String[] args) {
		System.out.println(toHumanReadable(1024L));
		System.out.println(toHumanReadable(1911640064L));
	}
}
