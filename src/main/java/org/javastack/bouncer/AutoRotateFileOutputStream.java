package org.javastack.bouncer;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

public class AutoRotateFileOutputStream extends OutputStream {
	private final String filename;
	private final SimpleDateFormat sdf;
	private final LinkedHashMap<Integer, String> cache = new LinkedHashMap<Integer, String>(8) {
		private static final long serialVersionUID = 1L;

		@Override
		protected boolean removeEldestEntry(Map.Entry<Integer, String> eldest) {
			return (size() > 3);
		}
	};
	private String currentStamp = null;
	private FileOutputStream os = null;

	/**
	 * Creates a file output stream with default daily pattern (yyyy-MM-dd) rotation
	 * 
	 * @param filename
	 */
	public AutoRotateFileOutputStream(final String filename) {
		this(filename, "yyyy-MM-dd");
	}

	/**
	 * Creates a file output stream with specified pattern rotation
	 * 
	 * @param filename
	 * @param pattern
	 *            like SimpleDateFormat: yyyy-MM-dd.HHmmss
	 */
	public AutoRotateFileOutputStream(final String filename, final String pattern) {
		this.filename = filename;
		this.sdf = new SimpleDateFormat(pattern);
	}

	private final String getTimeStamp() {
		final Integer now = Integer.valueOf((int) (System.currentTimeMillis() / 1000));
		String nowString = cache.get(now);
		if (nowString == null) {
			nowString = sdf.format(new Date(now.longValue() * 1000));
			cache.put(now, nowString);
		}
		return nowString;
	}

	private final void open() throws IOException {
		final String newStamp = getTimeStamp();
		if (newStamp != currentStamp) {
			if (newStamp.equals(currentStamp)) {
				currentStamp = newStamp;
			} else {
				close();
			}
		}
		if (os == null) {
			final String out = filename + "." + newStamp;
			os = new FileOutputStream(out, true);
			currentStamp = newStamp;
		}
	}

	@Override
	public synchronized void close() throws IOException {
		if (os != null) {
			os.flush();
			os.close();
			os = null;
		}
	}

	@Override
	public synchronized void flush() throws IOException {
		if (os != null)
			os.flush();
	}

	@Override
	public void write(final byte[] b) throws IOException {
		write(b, 0, b.length);
	}

	@Override
	public final synchronized void write(final byte[] b, final int off, final int len) throws IOException {
		if ((os != null) && ((b[off] == '\n') || (b[off] == '\r'))) {
			os.write(b, off, len);
		} else {
			open();
			os.write(b, off, len);
		}
	}

	@Override
	public final synchronized void write(final int b) throws IOException {
		if ((os != null) && ((b == '\n') || (b == '\r'))) {
			os.write(b);
		} else {
			open();
			os.write(b);
		}
	}
}
