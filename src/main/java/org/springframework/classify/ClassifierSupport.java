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

package org.springframework.classify;

/**
 * Base class for {@link Classifier} implementations. Provides default behaviour and some
 * convenience members, like constants.
 *
 * @author Dave Syer
 * @param <C> the type of the thing to classify
 * @param <T> the output of the classifier
 */
@SuppressWarnings("serial")
public class ClassifierSupport<C, T> implements Classifier<C, T> {

	final private T defaultValue;

	/**
	 * @param defaultValue the default value
	 */
	public ClassifierSupport(T defaultValue) {
		super();
		this.defaultValue = defaultValue;
	}

	/**
	 * Always returns the default value. This is the main extension point for subclasses,
	 * so it must be able to classify null.
	 *
	 * @see org.springframework.classify.Classifier#classify(Object)
	 */
	@Override
	public T classify(C throwable) {
		return this.defaultValue;
	}

}
