package com.crosscert.passkey.integration.datasource;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;

class AdminDataSourceConditionTest extends IntegrationTestBase {

  @Autowired ApplicationContext ctx;

  @Autowired
  @Qualifier("runtimeDataSource")
  DataSource runtimeDataSource;

  @Test
  void runtime_data_source_is_registered() {
    assertThat(runtimeDataSource).isNotNull();
  }

  @Test
  void admin_data_source_is_absent_when_admin_disabled() {
    assertThat(ctx.containsBean("adminDataSource")).isFalse();
    assertThat(ctx.containsBean("adminDataSourceProperties")).isFalse();
  }
}
