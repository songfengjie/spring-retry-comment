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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.naming.OperationNotSupportedException;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.IntroductionInterceptor;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.Expression;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;
import org.springframework.retry.RetryPolicy;
import org.springframework.retry.backoff.BackOffPolicy;
import org.springframework.retry.backoff.BackOffPolicyBuilder;
import org.springframework.retry.backoff.NoBackOffPolicy;
import org.springframework.retry.backoff.Sleeper;
import org.springframework.retry.interceptor.FixedKeyGenerator;
import org.springframework.retry.interceptor.MethodArgumentsKeyGenerator;
import org.springframework.retry.interceptor.MethodInvocationRecoverer;
import org.springframework.retry.interceptor.NewMethodArgumentsIdentifier;
import org.springframework.retry.interceptor.RetryInterceptorBuilder;
import org.springframework.retry.policy.CircuitBreakerRetryPolicy;
import org.springframework.retry.policy.ExpressionRetryPolicy;
import org.springframework.retry.policy.MapRetryContextCache;
import org.springframework.retry.policy.RetryContextCache;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.Args;
import org.springframework.retry.support.RetrySynchronizationManager;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.util.ConcurrentReferenceHashMap;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

/**
 * Interceptor that parses the retry metadata on the method it is invoking and delegates
 * to an appropriate RetryOperationsInterceptor.
 *
 * @author Dave Syer
 * @author Artem Bilan
 * @author Gary Russell
 * @since 1.1
 */
public class AnnotationAwareRetryOperationsInterceptor implements IntroductionInterceptor, BeanFactoryAware {

	private static final TemplateParserContext PARSER_CONTEXT = new TemplateParserContext();

	private static final SpelExpressionParser PARSER = new SpelExpressionParser();

	/**
	 * 拦截器对象的默认实现
	 * 1、用户未指定且
	 * 2、根据注解信息无法构建对应的拦截器对象时
	 * 3、或者构建拦截器对象的过程异常
	 * 当1&&(2||3)=true时，构建默认的拦截器对象，抛出异常
	 */
	private static final MethodInterceptor NULL_INTERCEPTOR = methodInvocation -> {
		throw new OperationNotSupportedException("Not supported");
	};

	/**
	 * beanFactory解析器
	 */
	private final StandardEvaluationContext evaluationContext = new StandardEvaluationContext();

	/**
	 * 装载拦截器对象的容器（缓存）
	 */
	private final ConcurrentReferenceHashMap<Object, ConcurrentMap<Method, MethodInterceptor>> delegates = new ConcurrentReferenceHashMap<>();

	/**
	 * 有状态场景时，重试上下文的缓存对象
	 * 有状态即Retryable#stateful()为true
	 */
	private RetryContextCache retryContextCache = new MapRetryContextCache();

	private MethodArgumentsKeyGenerator methodArgumentsKeyGenerator;

	private NewMethodArgumentsIdentifier newMethodArgumentsIdentifier;

	/**
	 * 睡眠者
	 * @BackOff
	 * 退避策略里面设置的重试时间间隔，由睡眠者执行时间间隔
	 */
	private Sleeper sleeper;

	/**
	 * 实现BeanFactoryAware，注入的bean工厂
	 */
	private BeanFactory beanFactory;

	private RetryListener[] globalListeners;

	/**
	 * @param sleeper the sleeper to set
	 */
	public void setSleeper(Sleeper sleeper) {
		this.sleeper = sleeper;
	}

	/**
	 * Public setter for the {@link RetryContextCache}.
	 * @param retryContextCache the {@link RetryContextCache} to set.
	 */
	public void setRetryContextCache(RetryContextCache retryContextCache) {
		this.retryContextCache = retryContextCache;
	}

	/**
	 * @param methodArgumentsKeyGenerator the {@link MethodArgumentsKeyGenerator}
	 */
	public void setKeyGenerator(MethodArgumentsKeyGenerator methodArgumentsKeyGenerator) {
		this.methodArgumentsKeyGenerator = methodArgumentsKeyGenerator;
	}

	/**
	 * @param newMethodArgumentsIdentifier the {@link NewMethodArgumentsIdentifier}
	 */
	public void setNewItemIdentifier(NewMethodArgumentsIdentifier newMethodArgumentsIdentifier) {
		this.newMethodArgumentsIdentifier = newMethodArgumentsIdentifier;
	}

	/**
	 * Default retry listeners to apply to all operations.
	 * @param globalListeners the default listeners
	 */
	public void setListeners(Collection<RetryListener> globalListeners) {
		ArrayList<RetryListener> retryListeners = new ArrayList<>(globalListeners);
		AnnotationAwareOrderComparator.sort(retryListeners);
		this.globalListeners = retryListeners.toArray(new RetryListener[0]);
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = beanFactory;
		this.evaluationContext.setBeanResolver(new BeanFactoryResolver(beanFactory));
	}

	@Override
	public boolean implementsInterface(Class<?> intf) {
		return org.springframework.retry.interceptor.Retryable.class.isAssignableFrom(intf);
	}

	/**
	 * 拦截器 --@Retryable
	 *
	 * @param invocation
	 * @return
	 * @throws Throwable
	 */
	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		// 获取当前方法拦截器
		MethodInterceptor delegate = getDelegate(invocation.getThis(), invocation.getMethod());
		if (delegate != null) {
			/*
			 * 调用被拦截的方法，aop增强方法
			 * 这里的delegate实际上是RetryOperationsInterceptor的对象
			 */
			return delegate.invoke(invocation);
		}
		else {
			// 没有获取到增强代理对象，直接执行
			return invocation.proceed();
		}
	}

	private MethodInterceptor getDelegate(Object target, Method method) {
		// 当retryable标注的方法初次加载时，缓存中是没有改方法的，因此需要new，最终放入缓存中，等触发retry的时候，可以直接从缓存读取重试的方法信息
		ConcurrentMap<Method, MethodInterceptor> cachedMethods = this.delegates.get(target);
		if (cachedMethods == null) {
			cachedMethods = new ConcurrentHashMap<>();
		}
		MethodInterceptor delegate = cachedMethods.get(method);
		if (delegate == null) {
			MethodInterceptor interceptor = NULL_INTERCEPTOR;
			// 从代理方法上获取retryable注解信息
			Retryable retryable = AnnotatedElementUtils.findMergedAnnotation(method, Retryable.class);
			if (retryable == null) {
				retryable = classLevelAnnotation(method, Retryable.class);
			}
			if (retryable == null) {
				retryable = findAnnotationOnTarget(target, method, Retryable.class);
			}
			// 根据retryable注解信息装配增强拦截器
			if (retryable != null) {
				// 如果retryable注解被用户指定了拦截器，那么取用户指定的
				if (StringUtils.hasText(retryable.interceptor())) {
					// 这里我们通过beanFactory拿到用户指定的拦截器对象，
					// 当前对象还是一个object，尚未完成springbean的过程，因为这里我们需要代理这个object
					interceptor = this.beanFactory.getBean(retryable.interceptor(), MethodInterceptor.class);
				}
				// 重试是否有状态，默认是false
				else if (retryable.stateful()) {
					interceptor = getStatefulInterceptor(target, method, retryable);
				}
				// 无状态的重试，默认的策略
				else {
					interceptor = getStatelessInterceptor(target, method, retryable);
				}
			}
			cachedMethods.putIfAbsent(method, interceptor);
			delegate = cachedMethods.get(method);
		}
		// 放入缓存中，便于后续重试的时候，直接获取拦截器对象
		this.delegates.putIfAbsent(target, cachedMethods);
		return delegate == NULL_INTERCEPTOR ? null : delegate;
	}

	/**
	 * 找目标对象和方法上的注解信息
	 *
	 * @param target
	 * @param method
	 * @param annotation
	 * @return
	 * @param <A>
	 */
	private <A extends Annotation> A findAnnotationOnTarget(Object target, Method method, Class<A> annotation) {

		try {
			Method targetMethod = target.getClass().getMethod(method.getName(), method.getParameterTypes());
			// 从方法上获取retryable注解
			A retryable = AnnotatedElementUtils.findMergedAnnotation(targetMethod, annotation);
			if (retryable == null) {
				// 从类上获取retryable注解
				retryable = classLevelAnnotation(targetMethod, annotation);
			}

			return retryable;
		}
		catch (Exception e) {
			return null;
		}
	}

	/*
	 * With a class level annotation, exclude @Recover methods.
	 */
	private <A extends Annotation> A classLevelAnnotation(Method method, Class<A> annotation) {
		A ann = AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), annotation);
		if (ann != null && AnnotatedElementUtils.findMergedAnnotation(method, Recover.class) != null) {
			ann = null;
		}
		return ann;
	}

	/**
	 * 缺省值
	 * 基于retryable参数，默认场景构建的拦截器对象
	 *
	 * @param target 被拦截的目标对象
	 * @param method 目标方法
	 * @param retryable @Retryable
	 * @return 拦截器对象
	 */
	private MethodInterceptor getStatelessInterceptor(Object target, Method method, Retryable retryable) {
		// RetryTemplate是实现@Retryable功能的核心代码所在，在这里我们根据retryable提供的参数构建RetryTemplate的对象
		RetryTemplate template = createTemplate(retryable.listeners());
		// 设置重试策略
		template.setRetryPolicy(getRetryPolicy(retryable, true));
		// 设置退避策略，退避策略构建逻辑，由@Backoff注解中设置的参数来决定
		template.setBackOffPolicy(getBackoffPolicy(retryable.backoff(), true));
		// 将template对象创建好后，封装进拦截器对象中，由拦截器对象触发调用核心逻辑
		return RetryInterceptorBuilder.stateless()
			.retryOperations(template)
			.label(retryable.label())
			.recoverer(getRecoverer(target, method))
			.build();
	}

	private MethodInterceptor getStatefulInterceptor(Object target, Method method, Retryable retryable) {
		RetryTemplate template = createTemplate(retryable.listeners());
		template.setRetryContextCache(this.retryContextCache);

		/*
		 * CircuitBreaker的功能基本已经被Retryable替代，我认为是个即将过期的注解，可以不用了解，也不建议使用这个注解了
		 */
		CircuitBreaker circuit = AnnotatedElementUtils.findMergedAnnotation(method, CircuitBreaker.class);
		if (circuit == null) {
			circuit = findAnnotationOnTarget(target, method, CircuitBreaker.class);
		}
		if (circuit != null) {
			RetryPolicy policy = getRetryPolicy(circuit, false);
			CircuitBreakerRetryPolicy breaker = new CircuitBreakerRetryPolicy(policy);
			openTimeout(breaker, circuit);
			resetTimeout(breaker, circuit);
			template.setRetryPolicy(breaker);
			template.setBackOffPolicy(new NoBackOffPolicy());
			String label = circuit.label();
			if (!StringUtils.hasText(label)) {
				label = method.toGenericString();
			}
			return RetryInterceptorBuilder.circuitBreaker()
				.keyGenerator(new FixedKeyGenerator("circuit"))
				.retryOperations(template)
				.recoverer(getRecoverer(target, method))
				.label(label)
				.build();
		}
		// 根据retryable构建重试策略
		RetryPolicy policy = getRetryPolicy(retryable, false);
		template.setRetryPolicy(policy);
		// 根据retryable内的Backoff构建退避策略
		template.setBackOffPolicy(getBackoffPolicy(retryable.backoff(), false));
		String label = retryable.label();
		// 将template对象创建好后，封装进拦截器对象中，由拦截器对象触发调用核心逻辑
		return RetryInterceptorBuilder.stateful()
			.keyGenerator(this.methodArgumentsKeyGenerator)
			.newMethodArgumentsIdentifier(this.newMethodArgumentsIdentifier)
			.retryOperations(template)
			.label(label)
			.recoverer(getRecoverer(target, method))
			.build();
	}

	/**
	 * 根据注解circuit设置对应的退避策略的openTimeout
	 * 目前应该不再使用了
	 *
	 * @param breaker
	 * @param circuit
	 */
	private void openTimeout(CircuitBreakerRetryPolicy breaker, CircuitBreaker circuit) {
		String expression = circuit.openTimeoutExpression();
		if (StringUtils.hasText(expression)) {
			Expression parsed = parse(expression);
			if (isTemplate(expression)) {
				Long value = parsed.getValue(this.evaluationContext, Long.class);
				if (value != null) {
					breaker.setOpenTimeout(value);
					return;
				}
			}
			else {
				breaker.openTimeoutSupplier(() -> evaluate(parsed, Long.class, false));
				return;
			}
		}
		breaker.setOpenTimeout(circuit.openTimeout());
	}

	/**
	 * 根据注解circuit设置退避策略的resetTimeout
	 * @param breaker
	 * @param circuit
	 */
	private void resetTimeout(CircuitBreakerRetryPolicy breaker, CircuitBreaker circuit) {
		String expression = circuit.resetTimeoutExpression();
		if (StringUtils.hasText(expression)) {
			Expression parsed = parse(expression);
			if (isTemplate(expression)) {
				Long value = parsed.getValue(this.evaluationContext, Long.class);
				if (value != null) {
					breaker.setResetTimeout(value);
					return;
				}
			}
			else {
				breaker.resetTimeoutSupplier(() -> evaluate(parsed, Long.class, false));
			}
		}
		breaker.setResetTimeout(circuit.resetTimeout());
	}

	/**
	 * 创建RetryTemplate对象
	 * @param listenersBeanNames retryable注解中指定的listener
	 * @return template
	 */
	private RetryTemplate createTemplate(String[] listenersBeanNames) {
		RetryTemplate template = new RetryTemplate();
		if (listenersBeanNames.length > 0) {
			template.setListeners(getListenersBeans(listenersBeanNames));
		}
		else if (this.globalListeners != null) {
			template.setListeners(this.globalListeners);
		}
		return template;
	}

	/**
	 * 根据listenerName获取listener的object
	 * @param listenersBeanNames 监听器的名称
	 * @return 监听器对象
	 */
	private RetryListener[] getListenersBeans(String[] listenersBeanNames) {
		RetryListener[] listeners = new RetryListener[listenersBeanNames.length];
		for (int i = 0; i < listeners.length; i++) {
			listeners[i] = this.beanFactory.getBean(listenersBeanNames[i], RetryListener.class);
		}
		return listeners;
	}

	/**
	 * 构建recover注解标注的方法的抽象
	 * @param target
	 * @param method
	 * @return
	 */
	private MethodInvocationRecoverer<?> getRecoverer(Object target, Method method) {
		if (target instanceof MethodInvocationRecoverer) {
			return (MethodInvocationRecoverer<?>) target;
		}
		final AtomicBoolean foundRecoverable = new AtomicBoolean(false);
		ReflectionUtils.doWithMethods(target.getClass(), candidate -> {
			if (AnnotatedElementUtils.findMergedAnnotation(candidate, Recover.class) != null) {
				foundRecoverable.set(true);
			}
		});

		if (!foundRecoverable.get()) {
			return null;
		}
		return new RecoverAnnotationRecoveryHandler<>(target, method);
	}

	/**
	 * 构建重试策略
	 *
	 * @param retryable
	 * @param stateless
	 * @return
	 */
	private RetryPolicy getRetryPolicy(Annotation retryable, boolean stateless) {
		Map<String, Object> attrs = AnnotationUtils.getAnnotationAttributes(retryable);
		/*
			根据注解中填入的相关信息，构建对应的重试的策略
		 */
		@SuppressWarnings("unchecked")
		Class<? extends Throwable>[] includes = (Class<? extends Throwable>[]) attrs.get("value");
		String exceptionExpression = (String) attrs.get("exceptionExpression");
		boolean hasExceptionExpression = StringUtils.hasText(exceptionExpression);
		if (includes.length == 0) {
			@SuppressWarnings("unchecked")
			Class<? extends Throwable>[] value = (Class<? extends Throwable>[]) attrs.get("retryFor");
			includes = value;
		}
		@SuppressWarnings("unchecked")
		Class<? extends Throwable>[] excludes = (Class<? extends Throwable>[]) attrs.get("noRetryFor");
		Integer maxAttempts = (Integer) attrs.get("maxAttempts");
		String maxAttemptsExpression = (String) attrs.get("maxAttemptsExpression");
		Expression parsedExpression = null;
		if (StringUtils.hasText(maxAttemptsExpression)) {
			parsedExpression = parse(maxAttemptsExpression);
			if (isTemplate(maxAttemptsExpression)) {
				maxAttempts = parsedExpression.getValue(this.evaluationContext, Integer.class);
				parsedExpression = null;
			}
		}
		final Expression maxAttExpression = parsedExpression;
		SimpleRetryPolicy simple = null;
		/*
			当注解中没有设置value和noRetryFor，构建一个SimpleRetryPolicy或者ExpressionRetryPolicy
			到底构建哪一个策略取决于exceptionExpression参数
		 */
		if (includes.length == 0 && excludes.length == 0) {
			simple = hasExceptionExpression
					? new ExpressionRetryPolicy(resolve(exceptionExpression)).withBeanFactory(this.beanFactory)
					: new SimpleRetryPolicy();
			if (maxAttExpression != null) {
				simple.maxAttemptsSupplier(() -> evaluate(maxAttExpression, Integer.class, stateless));
			}
			else {
				simple.setMaxAttempts(maxAttempts);
			}
		}
		Map<Class<? extends Throwable>, Boolean> policyMap = new HashMap<>();
		for (Class<? extends Throwable> type : includes) {
			policyMap.put(type, true);
		}
		for (Class<? extends Throwable> type : excludes) {
			policyMap.put(type, false);
		}
		boolean retryNotExcluded = includes.length == 0;
		/*
			上面的构建条件不满足的话，这里需要接着构建重试策略，逻辑基本一致，不过多了几个参数
		 */
		if (simple == null) {
			if (hasExceptionExpression) {
				simple = new ExpressionRetryPolicy(maxAttempts, policyMap, true, resolve(exceptionExpression),
						retryNotExcluded)
					.withBeanFactory(this.beanFactory);
			}
			else {
				simple = new SimpleRetryPolicy(maxAttempts, policyMap, true, retryNotExcluded);
			}
			if (maxAttExpression != null) {
				simple.maxAttemptsSupplier(() -> evaluate(maxAttExpression, Integer.class, stateless));
			}
		}
		/*
			在根据条件，是否需要构建一个notRecoverable的参数，取决于参数notRecoverable
		 */
		@SuppressWarnings("unchecked")
		Class<? extends Throwable>[] noRecovery = (Class<? extends Throwable>[]) attrs.get("notRecoverable");
		if (noRecovery != null && noRecovery.length > 0) {
			simple.setNotRecoverable(noRecovery);
		}
		return simple;
	}

	/**
	 * 构建退避策略
	 *
	 * @param backoff 退避注解
	 * @param stateless 状态
	 * @return 退避策略
	 */
	private BackOffPolicy getBackoffPolicy(Backoff backoff, boolean stateless) {
		Map<String, Object> attrs = AnnotationUtils.getAnnotationAttributes(backoff);
		long min = backoff.delay() == 0 ? backoff.value() : backoff.delay();
		String delayExpression = (String) attrs.get("delayExpression");
		Expression parsedMinExp = null;
		if (StringUtils.hasText(delayExpression)) {
			parsedMinExp = parse(delayExpression);
			if (isTemplate(delayExpression)) {
				min = parsedMinExp.getValue(this.evaluationContext, Long.class);
				parsedMinExp = null;
			}
		}
		long max = backoff.maxDelay();
		String maxDelayExpression = (String) attrs.get("maxDelayExpression");
		Expression parsedMaxExp = null;
		if (StringUtils.hasText(maxDelayExpression)) {
			parsedMaxExp = parse(maxDelayExpression);
			if (isTemplate(maxDelayExpression)) {
				max = parsedMaxExp.getValue(this.evaluationContext, Long.class);
				parsedMaxExp = null;
			}
		}
		double multiplier = backoff.multiplier();
		String multiplierExpression = (String) attrs.get("multiplierExpression");
		Expression parsedMultExp = null;
		if (StringUtils.hasText(multiplierExpression)) {
			parsedMultExp = parse(multiplierExpression);
			if (isTemplate(multiplierExpression)) {
				multiplier = parsedMultExp.getValue(this.evaluationContext, Double.class);
				parsedMultExp = null;
			}
		}
		boolean isRandom = false;
		String randomExpression = (String) attrs.get("randomExpression");
		Expression parsedRandomExp = null;
		if (multiplier > 0) {
			isRandom = backoff.random();
			if (StringUtils.hasText(randomExpression)) {
				parsedRandomExp = parse(randomExpression);
				if (isTemplate(randomExpression)) {
					isRandom = parsedRandomExp.getValue(this.evaluationContext, Boolean.class);
					parsedRandomExp = null;
				}
			}
		}
		return buildBackOff(min, parsedMinExp, max, parsedMaxExp, multiplier, parsedMultExp, isRandom, parsedRandomExp,
				stateless);
	}

	/**
	 * 根据参数，构建退避策略对象
	 * @param min 最小延迟
	 * @param minExp 最小延迟表达式
	 * @param max 最大延迟
	 * @param maxExp 最大延迟表达式
	 * @param multiplier 每次调度间隔的乘数或者调度次数
	 * @param multExp 乘数表达式
	 * @param isRandom 是否随机
	 * @param randomExp 随机表达式
	 * @param stateless 状态
	 * @return 退避策略
	 */
	private BackOffPolicy buildBackOff(long min, Expression minExp, long max, Expression maxExp, double multiplier,
			Expression multExp, boolean isRandom, Expression randomExp, boolean stateless) {

		BackOffPolicyBuilder builder = BackOffPolicyBuilder.newBuilder();
		if (minExp != null) {
			builder.delaySupplier(() -> evaluate(minExp, Long.class, stateless));
		}
		else {
			builder.delay(min);
		}
		if (maxExp != null) {
			builder.maxDelaySupplier(() -> evaluate(maxExp, Long.class, stateless));
		}
		else {
			builder.maxDelay(max);
		}
		if (multExp != null) {
			builder.multiplierSupplier(() -> evaluate(multExp, Double.class, stateless));
		}
		else {
			builder.multiplier(multiplier);
		}
		if (randomExp != null) {
			builder.randomSupplier(() -> evaluate(randomExp, Boolean.class, stateless));
		}
		else {
			builder.random(isRandom);
		}
		builder.sleeper(this.sleeper);
		return builder.build();
	}

	/**
	 * 解析表达式
	 * @param expression 表达式
	 * @return 解析后的表达式
	 */
	private Expression parse(String expression) {
		if (isTemplate(expression)) {
			return PARSER.parseExpression(resolve(expression), PARSER_CONTEXT);
		}
		else {
			return PARSER.parseExpression(resolve(expression));
		}
	}

	/**
	 * 判断表达式是否符合模板
	 * @param expression 表达式
	 * @return
	 */
	private boolean isTemplate(String expression) {
		return expression.contains(PARSER_CONTEXT.getExpressionPrefix())
				&& expression.contains(PARSER_CONTEXT.getExpressionSuffix());
	}

	/**
	 * 不是模板的情况下，用spring支持的表达式来解析
	 * @param expression
	 * @param type
	 * @param stateless
	 * @return
	 * @param <T>
	 */
	private <T> T evaluate(Expression expression, Class<T> type, boolean stateless) {
		Args args = null;
		if (stateless) {
			RetryContext context = RetrySynchronizationManager.getContext();
			if (context != null) {
				args = (Args) context.getAttribute("ARGS");
			}
			if (args == null) {
				args = Args.NO_ARGS;
			}
		}
		return expression.getValue(this.evaluationContext, args, type);
	}

	/**
	 * Resolve the specified value if possible.
	 *
	 * @see ConfigurableBeanFactory#resolveEmbeddedValue
	 */
	private String resolve(String value) {
		if (this.beanFactory != null && this.beanFactory instanceof ConfigurableBeanFactory) {
			return ((ConfigurableBeanFactory) this.beanFactory).resolveEmbeddedValue(value);
		}
		return value;
	}

}
