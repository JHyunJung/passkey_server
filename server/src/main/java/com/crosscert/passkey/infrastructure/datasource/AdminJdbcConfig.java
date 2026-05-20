package com.crosscert.passkey.infrastructure.datasource;

import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Activates the {@code adminDataSource} ({@code APP_ADMIN} role, BYPASSRLS) for the few writes that
 * the {@code APP_RUNTIME} role is not granted.
 *
 * <p>The platform's JPA layer runs entirely on the {@code @Primary} {@code runtimeDataSource}; its
 * {@code APP_RUNTIME} role has every privilege RP traffic needs. Two operations are the exception —
 * the {@code api_key} table grants {@code INSERT}/{@code DELETE} only to {@code APP_ADMIN}. Rather
 * than build a second {@code EntityManagerFactory} (which would force splitting the cross-cutting
 * entity packages and double-binding shared repositories), those writes go through a dedicated
 * {@link NamedParameterJdbcTemplate} on this data source. The JPA multi-tenancy infrastructure is
 * left completely untouched, so VPD isolation reasoning is unaffected.
 *
 * <p>All beans here are conditional on {@code passkey.admin.enabled=true}, so RP-only deployments
 * (and the test profile) never instantiate the admin data source.
 */
@Configuration
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class AdminJdbcConfig {

  /**
   * JDBC template bound to {@code APP_ADMIN}. Used only for privilege-elevated writes to {@code
   * api_key}. {@code APP_ADMIN} holds {@code EXEMPT ACCESS POLICY}, so no VPD predicate applies and
   * {@code set_tenant} is neither needed nor invoked on this path.
   */
  @Bean
  public NamedParameterJdbcTemplate adminJdbcTemplate(
      @Qualifier("adminDataSource") DataSource adminDataSource) {
    return new NamedParameterJdbcTemplate(adminDataSource);
  }

  /**
   * Re-declares the JPA transaction manager as {@code @Primary}.
   *
   * <p>Once a second {@link PlatformTransactionManager} bean exists ({@link
   * #adminTransactionManager}), Spring can no longer pick a default for the ~56 unqualified
   * {@code @Transactional} methods across the codebase. Marking the JPA manager primary restores
   * that default; only the admin writers opt out via an explicit qualifier. The auto-configured
   * {@link EntityManagerFactory} (which carries the VPD multi-tenancy customizer) is reused as-is.
   */
  @Bean
  @Primary
  public PlatformTransactionManager transactionManager(EntityManagerFactory emf) {
    return new JpaTransactionManager(emf);
  }

  /**
   * Transaction manager for the admin data source. Admin writers reference it explicitly via
   * {@code @Transactional("adminTransactionManager")}; nothing else uses it.
   */
  @Bean
  public PlatformTransactionManager adminTransactionManager(
      @Qualifier("adminDataSource") DataSource adminDataSource) {
    return new DataSourceTransactionManager(adminDataSource);
  }
}
