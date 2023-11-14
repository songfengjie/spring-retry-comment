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

package org.springframework.retry;

/**
 * Callback interface for an operation that can be retried using a
 * {@link RetryOperations}.
 *
 * @param <T> the type of object returned by the callback
 * @param <E> the type of exception it declares may be thrown
 * @author Rob Harrop
 * @author Dave Syer
 */
public interface RetryCallback<T, E extends Throwable> {

	/**
	 * Execute an operation with retry semantics. Operations should generally be
	 * idempotent, but implementations may choose to implement compensation semantics when
	 * an operation is retried.
	 * @param context the current retry context.
	 * @return the result of the successful operation.
	 * @throws E of type E if processing fails
	 */
	T doWithRetry(RetryContext context) throws E;

}
