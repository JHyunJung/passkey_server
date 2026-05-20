package com.crosscert.passkey.demo.user;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Minimal user store — the one piece of state the passkey SDK does not manage. A real RP would back
 * this with its existing user database; the demo keeps it in memory so there is nothing to
 * provision. State is lost on restart, which is fine for a reference example.
 */
@Component
public class InMemoryUserStore {

  private final ConcurrentHashMap<String, DemoUser> byExternalId = new ConcurrentHashMap<>();

  /** Creates a user and issues a fresh externalUserId. */
  public DemoUser create(String displayName) {
    String externalUserId = UUID.randomUUID().toString();
    DemoUser user = new DemoUser(externalUserId, displayName);
    byExternalId.put(externalUserId, user);
    return user;
  }

  public Optional<DemoUser> findByExternalUserId(String externalUserId) {
    return Optional.ofNullable(byExternalId.get(externalUserId));
  }
}
