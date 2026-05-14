package com.crosscert.passkey.infrastructure.jpa.multitenancy;

import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class HibernateMultiTenancyConfig implements HibernatePropertiesCustomizer {

  private final TenantConnectionProvider provider;
  private final CurrentTenantIdentifierResolverImpl resolver;

  @Override
  public void customize(Map<String, Object> hibernateProperties) {
    hibernateProperties.put("hibernate.multi_tenant_connection_provider", provider);
    hibernateProperties.put("hibernate.tenant_identifier_resolver", resolver);
  }
}
