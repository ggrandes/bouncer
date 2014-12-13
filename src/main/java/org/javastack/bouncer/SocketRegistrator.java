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

	boolean registerSocket(final ServerSocket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.registerSocket(ServerSocket==null)")
					.printStackTrace(System.out);
		return srvSockets.add(sock);
	}

	boolean unregisterSocket(final ServerSocket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.unregisterSocket(ServerSocket==null)")
					.printStackTrace(System.out);
		return srvSockets.remove(sock);
	}

	boolean registerSocket(final Socket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.registerSocket(Socket==null)")
					.printStackTrace(System.out);
		return cliSockets.add(sock);
	}

	boolean unregisterSocket(final Socket sock) {
		if (sock == null)
			new NullPointerException("SocketRegistrator.unregisterSocket(Socket==null)")
					.printStackTrace(System.out);
		return cliSockets.remove(sock);
	}

	Set<Socket> getClientSockets() {
		return Collections.unmodifiableSet(cliSockets);
	}

	Set<ServerSocket> getServerSockets() {
		return Collections.unmodifiableSet(srvSockets);
	}
}
