package org.javastack.bouncer;

import java.io.ByteArrayOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

public interface ServerContext {
	public CipherSuites getCipherSuites();

	public RawPacket allocateRawPacket();

	public void releaseRawPacket(final RawPacket packet);

	public MuxPacket allocateMuxPacket();

	public ByteArrayOutputStream allocateByteArrayOutputStream();

	public void releaseByteArrayOutputStream(final ByteArrayOutputStream baos);

	public void releaseMuxPacket(final MuxPacket packet);

	public void submitTask(final Runnable task, final String traceName, final int clientId);

	public void addShutdownable(final Shutdownable shutdownable);

	public void removeShutdownable(final Shutdownable shutdownable);

	public void addReloadableAwaiter(final Awaiter awaiter);

	public boolean awaitShutdown(final Awaiter caller);

	public void registerSocket(final Socket socket) throws SocketException;

	public void registerSocket(final ServerSocket socket) throws SocketException;

	public void closeSilent(final ServerSocket socket);

	public void closeSilent(final Socket socket);

	public Statistics getStatistics();
}
