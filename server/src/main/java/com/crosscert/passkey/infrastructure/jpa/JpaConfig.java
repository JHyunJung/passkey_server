package com.crosscert.passkey.infrastructure.jpa;

import org.springframework.context.annotation.Configuration;

/**
 * JPA wiring placeholder. Auditing is performed directly in {@link BaseEntity} via
 * {@code @PrePersist}/{@code @PreUpdate} so no global auditing infrastructure is needed.
 */
@Configuration
public class JpaConfig {}
