package com.crosscert.passkey.rp.starter.security;

import com.crosscert.passkey.rp.error.PasskeyAuthenticationException;
import com.crosscert.passkey.rp.jwt.JwtVerifier;
import com.crosscert.passkey.rp.jwt.VerifiedToken;
import com.crosscert.passkey.rp.starter.PasskeyProperties;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Reads {@code Authorization: Bearer <jwt>}, verifies via {@link JwtVerifier}, asserts the token's
 * {@code tid} claim matches the resolver's tenant, and populates the security context. Skips when
 * no Authorization header is present so non-passkey endpoints (the RP's own public paths) continue
 * unimpeded.
 */
public class PasskeyJwtAuthenticationFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PasskeyJwtAuthenticationFilter.class);

  private final JwtVerifier verifier;
  private final ApiKeyResolver resolver;
  private final String headerName;
  private final PasskeyProperties props;

  public PasskeyJwtAuthenticationFilter(
      JwtVerifier verifier, ApiKeyResolver resolver, PasskeyProperties props) {
    this.verifier = verifier;
    this.resolver = resolver;
    this.headerName = props.getAuth().getJwt().getHeaderName();
    this.props = props;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String header = request.getHeader(headerName);
    if (header == null || !header.startsWith("Bearer ")) {
      chain.doFilter(request, response);
      return;
    }
    String token = header.substring("Bearer ".length()).trim();
    try {
      VerifiedToken verified = verifier.verifyAccess(token);
      if (props.getMultiTenant().isEnabled() || props.getTenantId() != null) {
        UUID expected = resolver.resolve(request).tenantId();
        if (expected != null && !expected.equals(verified.tenantId())) {
          log.warn(
              "passkey.security.tid_mismatch expected={} actual={} path={}",
              expected,
              verified.tenantId(),
              request.getRequestURI());
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return;
        }
      }
      PasskeyPrincipal principal = PasskeyPrincipal.from(verified);
      SecurityContextHolder.getContext().setAuthentication(new PasskeyAuthentication(principal));
    } catch (PasskeyAuthenticationException ex) {
      log.debug("passkey.jwt.verify.failed reason={}", ex.getMessage());
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      if (ex.errorCode() == com.crosscert.passkey.rp.error.ErrorCode.EXPIRED_TOKEN) {
        response.setHeader("WWW-Authenticate", "Bearer error=\"token_expired\"");
      } else {
        response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
      }
      return;
    }
    chain.doFilter(request, response);
  }

  static final class PasskeyAuthentication extends AbstractAuthenticationToken {
    private final PasskeyPrincipal principal;

    PasskeyAuthentication(PasskeyPrincipal principal) {
      super(List.of(new SimpleGrantedAuthority("ROLE_USER")));
      this.principal = principal;
      setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
      return "";
    }

    @Override
    public Object getPrincipal() {
      return principal;
    }
  }
}
