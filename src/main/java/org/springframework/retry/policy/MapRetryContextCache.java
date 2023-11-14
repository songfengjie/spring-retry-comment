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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.retry.RetryContext;

/**
 * Map-based implementation of {@link RetryContextCache}. The map backing the cache of
 * contexts is synchronized.
 *
 * @author Dave Syer
 */
public class MapRetryContextCache implements RetryContextCache {

	/**
	 * Default value for maximum capacity of the cache. This is set to a reasonably low
	 * value (4096) to avoid users inadvertently filling the cache with item keys that are
	 * inconsistent.
	 */
	public static final int DEFAULT_CAPACITY = 4096;

	private final Map<Object, RetryContext> map = Collections.synchronizedMap(new HashMap<>());

	private int capacity;

	/**
	 * Create a {@link MapRetryContextCache} with default capacity.
	 */
	public MapRetryContextCache() {
		this(DEFAULT_CAPACITY);
	}

	/**
	 * @param defaultCapacity the default capacity
	 */
	public MapRetryContextCache(int defaultCapacity) {
		super();
		this.capacity = defaultCapacity;
	}

	/**
	 * Public setter for the capacity. Prevents the cache from growing unboundedly if
	 * items that fail are misidentified and two references to an identical item actually
	 * do not have the same key. This can happen when users implement equals and hashCode
	 * based on mutable fields, for instance.
	 * @param capacity the capacity to set
	 */
	public void setCapacity(int capacity) {
		this.capacity = capacity;
	}

	public boolean containsKey(Object key) {
		return map.containsKey(key);
	}

	public RetryContext get(Object key) {
		return map.get(key);
	}

	public void put(Object key, RetryContext context) {
		if (map.size() >= capacity) {
			throw new RetryCacheCapacityExceededException("Retry cache capacity limit breached. "
					+ "Do you need to re-consider the implementation of the key generator, "
					+ "or the equals and hashCode of the items that failed?");
		}
		map.put(key, context);
	}

	public void remove(Object key) {
		map.remove(key);
	}

}
