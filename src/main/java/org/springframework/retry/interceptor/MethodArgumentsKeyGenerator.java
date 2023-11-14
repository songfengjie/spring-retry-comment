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
package org.springframework.retry.interceptor;

/**
 * Interface that allows method parameters to be identified and tagged by a unique key.
 *
 * @author Dave Syer
 *
 */
public interface MethodArgumentsKeyGenerator {

	/**
	 * Get a unique identifier for the item that can be used to cache it between calls if
	 * necessary, and then identify it later.
	 * @param item the current method arguments (may be null if there are none).
	 * @return a unique identifier.
	 */
	Object getKey(Object[] item);

}
