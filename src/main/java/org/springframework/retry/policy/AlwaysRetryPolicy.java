/*
 * Copyright 2006-2007 the original author or authors.
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

/**
 * A {@link RetryPolicy} that always permits a retry. Can also be used as a base class for
 * other policies, e.g. for test purposes as a stub.
 *
 * @author Dave Syer
 *
 */
@SuppressWarnings("serial")
public class AlwaysRetryPolicy extends NeverRetryPolicy {

	/**
	 * Always returns true.
	 *
	 * @see org.springframework.retry.RetryPolicy#canRetry(org.springframework.retry.RetryContext)
	 */
	public boolean canRetry(RetryContext context) {
		return true;
	}

}
