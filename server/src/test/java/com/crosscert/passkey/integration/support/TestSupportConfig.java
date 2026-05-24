package com.crosscert.passkey.integration.support;

import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@TestConfiguration
public class TestSupportConfig {

  @Bean
  public TransactionTemplate transactionTemplate(PlatformTransactionManager tm) {
    return new TransactionTemplate(tm);
  }

  @Bean
  public TenantSeed tenantSeed(
      TenantRepository tenantRepository,
      TenantUserRepository tenantUserRepository,
      TransactionTemplate txTemplate) {
    return new TenantSeed(tenantRepository, tenantUserRepository, txTemplate);
  }

  @Bean
  public CredentialSeed credentialSeed(
      CredentialRepository credentialRepository,
      TenantSeed tenantSeed,
      TransactionTemplate txTemplate) {
    return new CredentialSeed(credentialRepository, tenantSeed, txTemplate);
  }

  @Bean
  public RefreshTokenSeed refreshTokenSeed(
      @Qualifier("adminJdbcTemplate") NamedParameterJdbcTemplate adminJdbcTemplate) {
    return new RefreshTokenSeed(adminJdbcTemplate);
  }
}
