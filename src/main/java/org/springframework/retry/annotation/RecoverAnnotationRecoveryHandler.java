/*
 * Copyright 2006-2023 the original author or authors.
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

package org.springframework.retry.annotation;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

import org.springframework.classify.SubclassClassifier;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.retry.ExhaustedRetryException;
import org.springframework.retry.RetryContext;
import org.springframework.retry.interceptor.MethodInvocationRecoverer;
import org.springframework.retry.support.RetrySynchronizationManager;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

/**
 * A recoverer for method invocations based on the <code>@Recover</code> annotation. A
 * suitable recovery method is one with a Throwable type as the first parameter and the
 * same return type and arguments as the method that failed. The Throwable first argument
 * is optional and if omitted the method is treated as a default (called when there are no
 * other matches). Generally the best matching method is chosen based on the type of the
 * first parameter and the type of the exception being handled. The closest match in the
 * class hierarchy is chosen, so for instance if an IllegalArgumentException is being
 * handled and there is a method whose first argument is RuntimeException, then it will be
 * preferred over a method whose first argument is Throwable.
 *
 * @param <T> the type of the return value from the recovery
 * @author Dave Syer
 * @author Josh Long
 * @author Aldo Sinanaj
 * @author Randell Callahan
 * @author Nathanaël Roberts
 * @author Maksim Kita
 * @author Gary Russell
 * @author Artem Bilan
 * @author Gianluca Medici
 * @author Lijinliang
 * @author Yanming Zhou
 */
public class RecoverAnnotationRecoveryHandler<T> implements MethodInvocationRecoverer<T> {

	private final SubclassClassifier<Throwable, Method> classifier = new SubclassClassifier<>();

	private final Map<Method, SimpleMetadata> methods = new HashMap<>();

	private final Object target;

	private String recoverMethodName;

	public RecoverAnnotationRecoveryHandler(Object target, Method method) {
		this.target = target;
		// 在构造器中，初始化目标对象的recover方法
		init(target, method);
	}

	/**
	 * 这里是执行@recover注解的方法
	 * @param args the arguments for the method invocation that failed.
	 * @param cause the cause of the failure that led to this recovery.
	 * @return
	 */
	@Override
	public T recover(Object[] args, Throwable cause) {
		Method method = findClosestMatch(args, cause.getClass());
		if (method == null) {
			throw new ExhaustedRetryException("Cannot locate recovery method", cause);
		}
		SimpleMetadata meta = this.methods.get(method);
		Object[] argsToUse = meta.getArgs(cause, args);
		ReflectionUtils.makeAccessible(method);
		RetryContext context = RetrySynchronizationManager.getContext();
		Object proxy = null;
		if (context != null) {
			proxy = context.getAttribute("___proxy___");
			if (proxy != null) {
				// 通过代理对象获取代理方法
				Method proxyMethod = findMethodOnProxy(method, proxy);
				// 获取不到代理方法，那代理对象应为空
				if (proxyMethod == null) {
					proxy = null;
				}
				else {
					method = proxyMethod;
				}
			}
		}
		// 没有代理对象，对象取原目标对象
		if (proxy == null) {
			proxy = this.target;
		}
		// 通过反射执行
		@SuppressWarnings("unchecked")
		T result = (T) ReflectionUtils.invokeMethod(method, proxy, argsToUse);
		return result;
	}

	/**
	 * 在代理对象上查找对应代理方法
	 *
	 * @param method 原方法（target的方法）
	 * @param proxy 代理对象
	 * @return 代理对象的方法（proxy的方法）
	 */
	private Method findMethodOnProxy(Method method, Object proxy) {
		try {
			return proxy.getClass().getMethod(method.getName(), method.getParameterTypes());
		}
		catch (NoSuchMethodException | SecurityException e) {
			return null;
		}
	}

	/**
	 * 因为目标对象中，被recover标注的方法，可能存在多个，所以推断一个最符合的方法
	 * 根据当前retryable方法的参数和异常参数，去methods的缓存容器中，取一个完全匹配的方法
	 *
	 * @param args 参数集合
	 * @param cause 异常原因
	 * @return 目标方法
	 */
	private Method findClosestMatch(Object[] args, Class<? extends Throwable> cause) {
		Method result = null;
		// 如果retryable注解没有指定recover方法，那么需要推断
		if (!StringUtils.hasText(this.recoverMethodName)) {
			int min = Integer.MAX_VALUE;
			for (Map.Entry<Method, SimpleMetadata> entry : this.methods.entrySet()) {
				Method method = entry.getKey();
				SimpleMetadata meta = entry.getValue();
				Class<? extends Throwable> type = meta.getType();
				if (type == null) {
					type = Throwable.class;
				}
				if (type.isAssignableFrom(cause)) {
					// 如果根据异常匹配，那么可能这个异常不能完全匹配，是子类或者子类的子类等等
					// 需要根据距离的远近来判断到底选择哪一个方法
					int distance = calculateDistance(cause, type);
					if (distance < min) {
						min = distance;
						result = method;
					}
					else if (distance == min) {
						boolean parametersMatch = compareParameters(args, meta.getArgCount(),
								method.getParameterTypes(), false);
						if (parametersMatch) {
							result = method;
						}
					}
				}
			}
		}
		else {
			// 如果recover被指定，那么直接从methods里面找到被指定的那个方法
			for (Map.Entry<Method, SimpleMetadata> entry : this.methods.entrySet()) {
				Method method = entry.getKey();
				if (method.getName().equals(this.recoverMethodName)) {
					SimpleMetadata meta = entry.getValue();
					if ((meta.type == null || meta.type.isAssignableFrom(cause))
							&& compareParameters(args, meta.getArgCount(), method.getParameterTypes(), true)) {
						result = method;
						break;
					}
				}
			}
		}
		return result;
	}

	/**
	 * 计算recover方法的异常和当前发生的异常的距离
	 * 距离：距离在这里的含义是，throwable和exception为1，因为exception是throwable的子类
	 * 		每继承一层，距离+1
	 * @param cause 当前发生的异常
	 * @param type recover标注的异常参数
	 * @return 当前异常与方法异常参数标识的异常的距离
	 */
	private int calculateDistance(Class<? extends Throwable> cause, Class<? extends Throwable> type) {
		int result = 0;
		Class<?> current = cause;
		while (current != type && current != Throwable.class) {
			result++;
			current = current.getSuperclass();
		}
		return result;
	}

	/**
	 * 参数匹配，根据参数的index进行挨个匹配参数类型
	 * @param args 当前参数
	 * @param argCount 参数数量
	 * @param parameterTypes 参数类型
	 * @param withRecoverMethodName 是否是被retryable中指定的recover方法名
	 * @return 是否匹配
	 */
	private boolean compareParameters(Object[] args, int argCount, Class<?>[] parameterTypes,
			boolean withRecoverMethodName) {
		if ((withRecoverMethodName && argCount == args.length) || argCount == (args.length + 1)) {
			int startingIndex = 0;
			if (parameterTypes.length > 0 && Throwable.class.isAssignableFrom(parameterTypes[0])) {
				startingIndex = 1;
			}
			for (int i = startingIndex; i < parameterTypes.length; i++) {
				final Object argument = i - startingIndex < args.length ? args[i - startingIndex] : null;
				if (argument == null) {
					continue;
				}
				Class<?> parameterType = parameterTypes[i];
				parameterType = ClassUtils.resolvePrimitiveIfNecessary(parameterType);
				if (!parameterType.isAssignableFrom(argument.getClass())) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * 初始化目标对中，所有符合的目标方法
	 * @param target 目标对象
	 * @param method 目标方法
	 */
	private void init(final Object target, Method method) {
		final Map<Class<? extends Throwable>, Method> types = new HashMap<>();
		final Method failingMethod = method;
		// retryable注解也可以指定recover的方法
		Retryable retryable = AnnotatedElementUtils.findMergedAnnotation(method, Retryable.class);
		if (retryable != null) {
			this.recoverMethodName = retryable.recover();
		}
		// 将目标对象中返回类型与目标方法返回类型匹配的方法，收集起来
		ReflectionUtils.doWithMethods(target.getClass(), candidate -> {
			Recover recover = AnnotatedElementUtils.findMergedAnnotation(candidate, Recover.class);
			if (recover == null) {
				recover = findAnnotationOnTarget(target, candidate);
			}
			if (recover != null && failingMethod.getGenericReturnType() instanceof ParameterizedType
					&& candidate.getGenericReturnType() instanceof ParameterizedType) {
				if (isParameterizedTypeAssignable((ParameterizedType) candidate.getGenericReturnType(),
						(ParameterizedType) failingMethod.getGenericReturnType())) {
					putToMethodsMap(candidate, types);
				}
			}
			else if (recover != null && candidate.getReturnType().isAssignableFrom(failingMethod.getReturnType())) {
				putToMethodsMap(candidate, types);
			}
		});
		// 收集方法
		this.classifier.setTypeMap(types);
		// 将putToMethodsMap方法放入到methods中的返回类型不符合的方法过滤掉
		optionallyFilterMethodsBy(failingMethod.getReturnType());
	}

	/**
	 * Returns {@code true} if the input methodReturnType is a direct match of the
	 * failingMethodReturnType. Takes nested generics into consideration as well, while
	 * deciding a match.
	 * @param methodReturnType the method return type
	 * @param failingMethodReturnType the failing method return type
	 * @return true if the parameterized return types match.
	 * @since 1.3.2
	 */
	private static boolean isParameterizedTypeAssignable(ParameterizedType methodReturnType,
			ParameterizedType failingMethodReturnType) {

		Type[] methodActualArgs = methodReturnType.getActualTypeArguments();
		Type[] failingMethodActualArgs = failingMethodReturnType.getActualTypeArguments();
		if (methodActualArgs.length != failingMethodActualArgs.length) {
			return false;
		}
		int startingIndex = 0;
		for (int i = startingIndex; i < methodActualArgs.length; i++) {
			Type methodArgType = methodActualArgs[i];
			Type failingMethodArgType = failingMethodActualArgs[i];
			if (methodArgType instanceof ParameterizedType && failingMethodArgType instanceof ParameterizedType) {
				if (!isParameterizedTypeAssignable((ParameterizedType) methodArgType,
						(ParameterizedType) failingMethodArgType)) {

					return false;
				}
			}
			else if (methodArgType instanceof Class && failingMethodArgType instanceof Class) {
				if (!failingMethodArgType.equals(methodArgType)) {
					return false;
				}
			}
			else if (!methodArgType.equals(failingMethodArgType)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 对目标方法进行分类
	 * 如果存在异常类型的参数，那么将异常-方法作为健值对存储
	 * 如果不存在异常类型的参数，那么保存classifier容器对象
	 * <p>
	 * 且同时放入methods容器对象， <method, simpleMetadata>
	 * <p>
	 * simpleMetadata为元数据，详见:SimpleMetadata
	 * @param method recover代理的目标方法
	 * @param types 存放异常和方法关系的容器对象
	 */
	private void putToMethodsMap(Method method, Map<Class<? extends Throwable>, Method> types) {
		Class<?>[] parameterTypes = method.getParameterTypes();
		// 如果该方法存在参数，且第一个参数类型是jdk中Throwable的子类，将类型-方法，放入到types容器对象中
		if (parameterTypes.length > 0 && Throwable.class.isAssignableFrom(parameterTypes[0])) {
			@SuppressWarnings("unchecked")
			Class<? extends Throwable> type = (Class<? extends Throwable>) parameterTypes[0];
			types.put(type, method);
			RecoverAnnotationRecoveryHandler.this.methods.put(method, new SimpleMetadata(parameterTypes.length, type));
		}
		else {
			// recover标注的是无参方法
			RecoverAnnotationRecoveryHandler.this.classifier.setDefaultValue(method);
			RecoverAnnotationRecoveryHandler.this.methods.put(method, new SimpleMetadata(parameterTypes.length, null));
		}
	}

	/**
	 * 从目标对象的目标方法上获取recover注解
	 * @param target 目标对象
	 * @param method 代理方法
	 * @return Recover注解
	 */
	private Recover findAnnotationOnTarget(Object target, Method method) {
		try {
			Method targetMethod = target.getClass().getMethod(method.getName(), method.getParameterTypes());
			return AnnotatedElementUtils.findMergedAnnotation(targetMethod, Recover.class);
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * 可以过滤的方法
	 * 支持方法过滤
	 * @param returnClass 代理方法返回的类型
	 */
	private void optionallyFilterMethodsBy(Class<?> returnClass) {
		Map<Method, SimpleMetadata> filteredMethods = new HashMap<>();
		for (Method method : this.methods.keySet()) {
			if (method.getReturnType() == returnClass) {
				filteredMethods.put(method, this.methods.get(method));
			}
		}
		if (filteredMethods.size() > 0) {
			this.methods.clear();
			;
			this.methods.putAll(filteredMethods);
		}
	}

	private static class SimpleMetadata {

		private final int argCount;

		private final Class<? extends Throwable> type;

		public SimpleMetadata(int argCount, Class<? extends Throwable> type) {
			super();
			this.argCount = argCount;
			this.type = type;
		}

		public int getArgCount() {
			return this.argCount;
		}

		public Class<? extends Throwable> getType() {
			return this.type;
		}

		/**
		 * 将所有的参数放入容器对象中
		 *
		 * @param t 异常（即recover注解标注的方法的第一个参数）
		 * @param args 其他参数
		 * @return 数组容器对象：Object[]
		 */
		public Object[] getArgs(Throwable t, Object[] args) {
			Object[] result = new Object[getArgCount()];
			int startArgs = 0;
			if (this.type != null) {
				result[0] = t;
				startArgs = 1;
			}
			int length = Math.min(result.length - startArgs, args.length);
			if (length == 0) {
				return result;
			}
			System.arraycopy(args, 0, result, startArgs, length);
			return result;
		}

	}

}
