package org.javastack.bouncer.jmx;

import java.lang.management.ManagementFactory;

import javax.management.JMException;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.javastack.bouncer.Statistics;

/**
 * JMX Management
 */
public class BouncerStatistics extends Statistics implements BouncerStatisticsMBean {
	public static final String MY_NAME = BouncerStatistics.class.getPackage().getName() + ":type="
			+ BouncerStatistics.class.getSimpleName();

	public void init() throws JMException {
		final MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		mbs.registerMBean(new AnnotatedStandardMBean(this, BouncerStatisticsMBean.class), new ObjectName(
				MY_NAME));
	}

	public void destroy() throws JMException {
		final MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		mbs.unregisterMBean(new ObjectName(MY_NAME));
	}
}
