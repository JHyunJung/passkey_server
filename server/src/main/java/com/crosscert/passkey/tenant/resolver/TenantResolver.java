package com.crosscert.passkey.tenant.resolver;

import com.crosscert.passkey.tenant.context.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

public interface TenantResolver {

  Optional<TenantContext> resolve(HttpServletRequest request);
}
