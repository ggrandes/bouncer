package org.javastack.bouncer;

import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Simple logging wrapper (you want log4j/logback/slfj? easy to do!)
 */
public class Log {
	public static final int LOG_NULL = 0x00;
	public static final int LOG_CURR_STDOUT = 0x01;
	public static final int LOG_ORIG_STDOUT = 0x02;

	private static final SimpleDateFormat ISO8601DATEFORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	private static boolean isDebugEnabled = false;
	private static int outMode = LOG_CURR_STDOUT;
	private static PrintStream stdOut = System.out;
	private static PrintStream stdErr = System.err;

	static void setMode(final int newMode) {
		outMode = newMode;
	}

	static boolean isModeOrigEnabled() {
		return ((outMode & LOG_ORIG_STDOUT) != 0);
	}

	static boolean isModeCurrEnabled() {
		return ((outMode & LOG_CURR_STDOUT) != 0);
	}

	static void redirStdOutLog(final String stdFile) {
		System.setOut(new PrintStream(new AutoRotateFileOutputStream(stdFile)));
	}

	static void restoreStdOutLog() {
		System.setOut(stdOut);
	}

	static void redirStdErrLog(final String errFile) {
		System.setErr(new PrintStream(new AutoRotateFileOutputStream(errFile)));
	}

	static void restoreStdErrLog() {
		System.setErr(stdErr);
	}

	static void enableDebug() {
		isDebugEnabled = true;
	}

	static boolean isDebug() {
		return isDebugEnabled;
	}

	static String getTimeStamp() {
		synchronized (ISO8601DATEFORMAT) {
			return ISO8601DATEFORMAT.format(new Date());
		}
	}

	static void debug(final String str) {
		if (isDebugEnabled) {
			final String msg = getTimeStamp() + " [" + getId() + "]" + " [DEBUG] " + "[" + getName() + "] "
					+ str;
			if (isModeOrigEnabled())
				stdOut.println(msg);
			if (isModeCurrEnabled())
				System.out.println(msg);
		}
	}

	static void info(final String str) {
		final String msg = getTimeStamp() + " [" + getId() + "]" + "[INFO]" + "[" + getName() + "] " + str;
		if (isModeOrigEnabled())
			stdOut.println(msg);
		if (isModeCurrEnabled())
			System.out.println(msg);
	}

	static void warn(final String str) {
		final String msg = getTimeStamp() + " [" + getId() + "]" + "[WARN]" + "[" + getName() + "] " + str;
		if (isModeOrigEnabled())
			stdOut.println(msg);
		if (isModeCurrEnabled())
			System.out.println(msg);
	}

	static void error(final String str) {
		final String msg = getTimeStamp() + " [" + getId() + "]" + "[ERROR]" + "[" + getName() + "] " + str;
		if (isModeOrigEnabled())
			stdOut.println(msg);
		if (isModeCurrEnabled())
			System.out.println(msg);
	}

	static void error(final String str, final Throwable t) {
		final String msg = getTimeStamp() + " [" + getId() + "]" + "[ERROR]" + "[" + getName() + "] " + str;
		if (isModeOrigEnabled()) {
			synchronized (stdOut) {
				stdOut.println(msg);
				t.printStackTrace(stdOut);
			}
		}
		if (isModeCurrEnabled()) {
			synchronized (System.out) {
				System.out.println(msg);
				t.printStackTrace(System.out);
			}
		}
	}

	private static final String getName() {
		return Thread.currentThread().getName();
	}

	private static final String getId() {
		return "id" + SimpleHex.longAsHex(ClientId.getId());
	}
}
