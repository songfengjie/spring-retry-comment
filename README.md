# spring-retry-comment
spring-retry源码注释

spring帮助装配资源的入口：
--org.springframework.retry.annotation.RetryConfiguration

拦截器入口：实现功能代码的入口
--org.springframework.retry.annotation.AnnotationAwareRetryOperationsInterceptor.invoke

整体流程逻辑大纲：
--org.springframework.retry.interceptor.RetryOperationsInterceptor.invoke

逻辑的具体实现
--org.springframework.retry.support.RetryTemplate.execute(org.springframework.retry.RetryCallback<T,E>, org.springframework.retry.RecoveryCallback<T>)
