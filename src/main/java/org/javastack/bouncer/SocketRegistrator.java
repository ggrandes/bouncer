package org.javastack.bouncer;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Socket Auditing
 */
class SocketRegistrator {
	private final Set<Socket> cliSockets = Collections.synchronizedSet(new HashSet<Socket>());
	private final Set<ServerSocket> srvSockets = Collections.synchronizedSet(new HashSet<ServerSocket>());

	void registerSocket(final ServerSocket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.registerSocket(ServerSocket==null)")
					.printStackTrace(System.out);
		srvSockets.add(sock);
	}

	void unregisterSocket(final ServerSocket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.unregisterSocket(ServerSocket==null)")
					.printStackTrace(System.out);
		srvSockets.remove(sock);
	}

	void registerSocket(final Socket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.registerSocket(Socket==null)")
					.printStackTrace(System.out);
		cliSockets.add(sock);
	}

	void unregisterSocket(final Socket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.unregisterSocket(Socket==null)")
					.printStackTrace(System.out);
		cliSockets.remove(sock);
	}

	Set<Socket> getClientSockets() {
		return Collections.unmodifiableSet(cliSockets);
	}

	Set<ServerSocket> getServerSockets() {
		return Collections.unmodifiableSet(srvSockets);
	}
}
