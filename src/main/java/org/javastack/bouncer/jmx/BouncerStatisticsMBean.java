package org.javastack.bouncer.jmx;


public interface BouncerStatisticsMBean {

	@Description(value="Current Connections in Trying State")
	public int getTryingConnections();

	@Description(value="Current Established Connections")
	public int getActiveConnections();

	@Description(value="Total config reloads")
	public int getReloads();

	@Description(value="Total Attended Connections")
	public long getAttendedConnections();

	@Description(value="Total Failed Connections")
	public long getFailedConnections();

	@Description(value="Total Input Messages")
	public long getInMsgs();

	@Description(value="Total Output Messages")
	public long getOutMsgs();

	@Description(value="Total Input Bytes")
	public long getInBytes();

	@Description(value="Total Output Bytes")
	public long getOutBytes();
}
