package org.javastack.bouncer;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.List;

import org.javastack.bouncer.jmx.BouncerStatistics;

public class ClusterTest implements ServerContext {
	private final TaskManager taskMgr = new TaskManager();
	private final BouncerStatistics stats = new BouncerStatistics();

	/**
	 * Simple Test
	 */
	public static void main(final String[] args) throws Throwable {
		new ClusterTest().start();
	}

	public void start() throws Throwable {
		String opts = ""; // "CLUSTER=AES,AES=fake";
		InboundAddress left = new InboundAddress(this, "0.0.0.0", 1234, new Options(opts));
		ClusterServer server = new ClusterServer(this, left);
		server.listenLocal();
		OutboundAddress right = new OutboundAddress(this, "127.0.0.1", 1234, new Options(opts));
		ClusterClient client = new ClusterClient(this, right);
		client.openRemote();
		Thread.sleep(1000);
		int lastvalue = 0, cx = 0;
		while (true) {
			// Thread.sleep(1000);
			final int value = (int) (System.currentTimeMillis() / 1000);
			if (lastvalue == value) {
				cx++;
			} else {
				System.out.println("REQ/s=" + cx);
				lastvalue = value;
				cx = 0;
			}
			ClusterPacket msg = allocateClusterPacket();
			msg.put(cx >> 2, cx, InetAddress.getByName("127.0.0.1"), InetAddress.getByName("127.0.0.2"));
			client.remote.sendRemote(msg);
		}
	}

	@Override
	public ClusterPacket allocateClusterPacket() {
		return ClusterPacket.GENERIC_POOL_FACTORY.newInstance();
	}

	@Override
	public void releaseClusterPacket(ClusterPacket packet) {
	}

	@Override
	public ByteArrayOutputStream allocateByteArrayOutputStream() {
		return new ByteArrayOutputStream(Constants.BUFFER_LEN);
	}

	@Override
	public void releaseByteArrayOutputStream(ByteArrayOutputStream baos) {
	}

	@Override
	public void submitTask(Runnable task, String traceName, long clientId) {
		taskMgr.submitTask(task, traceName, clientId);
	}

	@Override
	public void addShutdownable(Shutdownable shutdownable) {
	}

	@Override
	public void removeShutdownable(Shutdownable shutdownable) {
	}

	@Override
	public void addReloadableAwaiter(Awaiter awaiter) {
	}

	@Override
	public boolean awaitShutdown(Awaiter caller) {
		return false;
	}

	@Override
	public void registerSocket(Socket socket) throws SocketException {
	}

	@Override
	public void registerSocket(ServerSocket socket) throws SocketException {
	}

	@Override
	public void closeSilent(ServerSocket socket) {
		IOHelper.closeSilent(socket);
	}

	@Override
	public void closeSilent(Socket socket) {
		IOHelper.closeSilent(socket);
	}

	@Override
	public CipherSuites getCipherSuites() {
		return null;
	}

	@Override
	public RawPacket allocateRawPacket() {
		return null;
	}

	@Override
	public void releaseRawPacket(RawPacket packet) {
	}

	@Override
	public MuxPacket allocateMuxPacket() {
		return null;
	}

	@Override
	public void releaseMuxPacket(MuxPacket packet) {
	}

	@Override
	public void stickyRegister(final StickyStore<InetAddress, InetAddress> stickies) {
	}

	@Override
	public void stickyLocalUpdateNotify(final long clusterId, final long replicationId,
			final InetAddress stickyAddr, final InetAddress addr) {
	}

	@Override
	public void stickyRemoteUpdateNotify(final ClusterPacket packet) {
	}

	@Override
	public Statistics getStatistics() {
		return stats;
	}

	@Override
	public List<StickyStore<InetAddress, InetAddress>> stickyGetForCluster(long clusterId) {
		return null;
	}
}
