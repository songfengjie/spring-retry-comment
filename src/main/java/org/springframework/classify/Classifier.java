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

import java.io.Serializable;

/**
 * Interface for a classifier. At its simplest a {@link Classifier} is just a map from
 * objects of one type to objects of another type.
 *
 * Note that implementations can only be serializable if the parameter types are
 * themselves serializable.
 *
 * @author Dave Syer
 * @param <C> the type of the thing to classify
 * @param <T> the output of the classifier
 *
 */
public interface Classifier<C, T> extends Serializable {

	/**
	 * Classify the given object and return an object of a different type, possibly an
	 * enumerated type.
	 * @param classifiable the input object. Can be null.
	 * @return an object. Can be null, but implementations should declare if this is the
	 * case.
	 */
	T classify(C classifiable);

}
