package org.javastack.bouncer;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

class TaskManager {
	private final ExecutorService threadPool = Executors.newCachedThreadPool(new AuditableThreadFactory());
	private final AtomicInteger taskCounter = new AtomicInteger(0);
	// Thread Auditing
	private final Map<Integer, AuditableRunner> taskList = Collections
			.synchronizedMap(new HashMap<Integer, AuditableRunner>());

	void submitTask(final Runnable task, final String traceName, final long clientId) {
		final int taskNum = taskCounter.incrementAndGet();
		Log.info("Task: [" + taskNum + "] New: " + task);
		threadPool.submit(new AuditableRunner() {
			@Override
			public void run() {
				setClientId(clientId);
				setThread(Thread.currentThread());
				thread.setName("task" + taskNum + ":th" + Thread.currentThread().getId() + ":" + traceName);
				try {
					taskList.put(taskNum, this);
					Log.info("Task [" + taskNum + "] Start: " + task);
					task.run();
				} finally {
					Log.info("Task [" + taskNum + "] End: " + task);
					taskList.remove(taskNum);
					setThread(null);
					destroyClientId();
				}
			}

			@Override
			public String toString() {
				return task.toString();
			}
		});
	}

	Map<Integer, AuditableRunner> getTaskList() {
		return Collections.unmodifiableMap(taskList);
	}

	abstract static class AuditableRunner implements Runnable {
		Thread thread;

		void setThread(final Thread thread) {
			this.thread = thread;
		}

		Thread getThread() {
			return thread;
		}

		long getClientId() {
			return ClientId.getId();
		}

		void setClientId(final long clientId) {
			ClientId.setId(clientId);
		}

		void destroyClientId() {
			ClientId.destroy();
		}
	}

	static class AuditableThreadFactory implements ThreadFactory {
		final ThreadFactory defThreadFactory = Executors.defaultThreadFactory();

		@Override
		public Thread newThread(final Runnable r) {
			final Thread t = defThreadFactory.newThread(r);
			Log.info("new thread created: " + t.getName());
			return t;
		}
	}
}
