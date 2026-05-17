package com.crosscert.passkey.audit.service;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Dedicated executor for ceremony-path audit writes. Kept small and bounded so a Postgres slowdown
 * cannot exhaust the application's thread pool; the calling thread runs the audit append itself
 * (CallerRunsPolicy) if the queue fills, which preserves audit durability over throughput.
 */
@Configuration
@EnableAsync
public class AuditAsyncConfig {

  public static final String EXECUTOR_BEAN = "auditExecutor";

  @Bean(name = EXECUTOR_BEAN)
  public Executor auditExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(2);
    executor.setMaxPoolSize(4);
    executor.setQueueCapacity(1000);
    executor.setThreadNamePrefix("audit-");
    executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
    executor.setWaitForTasksToCompleteOnShutdown(true);
    executor.setAwaitTerminationSeconds(30);
    executor.initialize();
    return executor;
  }
}
