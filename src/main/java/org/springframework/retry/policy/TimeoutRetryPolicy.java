/*
 * Copyright 2006-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.retry.policy;

import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryPolicy;
import org.springframework.retry.context.RetryContextSupport;

/**
 * A {@link RetryPolicy} that allows a retry only if it hasn't timed out. The clock is
 * started on a call to {@link #open(RetryContext)}.
 *
 * @author Dave Syer
 *
 */
@SuppressWarnings("serial")
public class TimeoutRetryPolicy implements RetryPolicy {

	/**
	 * Default value for timeout (milliseconds).
	 */
	public static final long DEFAULT_TIMEOUT = 1000;

	private long timeout;

	/**
	 * Create a new instance with the timeout set to {@link #DEFAULT_TIMEOUT}.
	 */
	public TimeoutRetryPolicy() {
		this(DEFAULT_TIMEOUT);
	}

	/**
	 * Create a new instance with a configurable timeout.
	 * @param timeout timeout in milliseconds
	 * @since 2.0.2
	 */
	public TimeoutRetryPolicy(long timeout) {
		this.timeout = timeout;
	}

	/**
	 * Setter for timeout in milliseconds. Default is {@link #DEFAULT_TIMEOUT}.
	 * @param timeout how long to wait until a timeout
	 */
	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}

	/**
	 * The value of the timeout.
	 * @return the timeout in milliseconds
	 */
	public long getTimeout() {
		return timeout;
	}

	/**
	 * Only permits a retry if the timeout has not expired. Does not check the exception
	 * at all.
	 *
	 * @see org.springframework.retry.RetryPolicy#canRetry(org.springframework.retry.RetryContext)
	 */
	public boolean canRetry(RetryContext context) {
		return ((TimeoutRetryContext) context).isAlive();
	}

	public void close(RetryContext context) {
	}

	public RetryContext open(RetryContext parent) {
		return new TimeoutRetryContext(parent, timeout);
	}

	public void registerThrowable(RetryContext context, Throwable throwable) {
		((RetryContextSupport) context).registerThrowable(throwable);
		// otherwise no-op - we only time out, otherwise retry everything...
	}

	private static class TimeoutRetryContext extends RetryContextSupport {

		private final long timeout;

		private final long start;

		public TimeoutRetryContext(RetryContext parent, long timeout) {
			super(parent);
			this.start = System.currentTimeMillis();
			this.timeout = timeout;
		}

		public boolean isAlive() {
			return (System.currentTimeMillis() - start) <= timeout;
		}

	}

}
