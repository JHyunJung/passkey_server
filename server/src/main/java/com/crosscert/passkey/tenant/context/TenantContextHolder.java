package com.crosscert.passkey.tenant.context;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import java.util.Objects;
import java.util.Optional;

/**
 * Static {@link ThreadLocal} holder for the active tenant context. {@code InheritableThreadLocal}
 * is intentionally avoided to prevent stale context from leaking across thread-pool tasks. Async
 * paths must propagate via a {@code TaskDecorator}.
 */
public final class TenantContextHolder {

  private static final ThreadLocal<TenantContext> HOLDER = new ThreadLocal<>();

  private TenantContextHolder() {}

  public static void set(TenantContext ctx) {
    HOLDER.set(Objects.requireNonNull(ctx, "TenantContext must not be null"));
  }

  public static Optional<TenantContext> optional() {
    return Optional.ofNullable(HOLDER.get());
  }

  public static TenantContext required() {
    TenantContext c = HOLDER.get();
    if (c == null) {
      throw new BusinessException(ErrorCode.TENANT_CONTEXT_MISSING);
    }
    return c;
  }

  public static void clear() {
    HOLDER.remove();
  }
}
