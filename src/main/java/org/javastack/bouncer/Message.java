package org.javastack.bouncer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public 	interface Message {
	public int getIdChannel();

	public int getBufferLen();

	public byte[] getBuffer();

	public void put(int idChannel, int bufferLen, byte[] buffer);

	public void clear();

	public void fromWire(InputStream is) throws IOException;

	public void toWire(OutputStream os) throws IOException;
}
