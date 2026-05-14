package com.crosscert.passkey.infrastructure.datasource;

import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Two DataSources:
 *
 * <ul>
 *   <li>{@code runtimeDataSource} (@Primary) — uses the {@code app_runtime} role (NOBYPASSRLS).
 *       Handles RP API and RP admin traffic.
 *   <li>{@code adminDataSource} — uses the {@code app_admin} role (BYPASSRLS). Conditional on
 *       {@code passkey.admin.enabled=true}. M4 activation.
 * </ul>
 *
 * <p>{@link DataSourceProperties} is used (rather than {@code DataSourceBuilder.create().build()})
 * so Spring Boot's standard environment binding runs — including {@code @DynamicPropertySource}
 * overrides applied by integration tests.
 */
@Configuration
public class DataSourceConfig {

  @Primary
  @Bean(name = "runtimeDataSourceProperties")
  @ConfigurationProperties("spring.datasource")
  public DataSourceProperties runtimeDataSourceProperties() {
    return new DataSourceProperties();
  }

  @Primary
  @Bean(name = "runtimeDataSource")
  @ConfigurationProperties("spring.datasource.hikari")
  public DataSource runtimeDataSource(DataSourceProperties properties) {
    return properties.initializeDataSourceBuilder().build();
  }

  @Bean(name = "adminDataSourceProperties")
  @ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
  @ConfigurationProperties("passkey.admin.datasource")
  public DataSourceProperties adminDataSourceProperties() {
    return new DataSourceProperties();
  }

  @Bean(name = "adminDataSource")
  @ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
  @ConfigurationProperties("passkey.admin.datasource.hikari")
  public DataSource adminDataSource(
      @org.springframework.beans.factory.annotation.Qualifier("adminDataSourceProperties")
          DataSourceProperties properties) {
    return properties.initializeDataSourceBuilder().build();
  }
}
