package com.crosscert.passkey.tenant.context;

import java.util.UUID;

public record TenantContext(UUID tenantId, String tenantSlug) {}
