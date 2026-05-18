package com.crosscert.passkey.infrastructure.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import lombok.Getter;

/**
 * Common columns: {@code id} (uuid), {@code created_at}, {@code updated_at}. Timestamps are
 * application-driven via {@link PrePersist}/{@link PreUpdate} so the DB rows always reflect the
 * application's notion of "now" — JPA Auditing is intentionally avoided since it does not bridge
 * {@code LocalDateTime} → {@code OffsetDateTime} cleanly.
 */
@Getter
@MappedSuperclass
public abstract class BaseEntity {

  @Id
  // Oracle stores UUIDs as RAW(16). The dialect maps java.util.UUID ↔ RAW automatically once the
  // explicit "uuid" columnDefinition (Postgres-only) is removed, so ddl-auto=validate is happy
  // with the V1__oracle_baseline.sql DDL.
  @Column(name = "id", updatable = false, nullable = false)
  private UUID id;

  @Column(name = "created_at", nullable = false, updatable = false)
  private OffsetDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private OffsetDateTime updatedAt;

  protected BaseEntity() {}

  protected BaseEntity(UUID id) {
    this.id = id;
  }

  @PrePersist
  void onCreate() {
    if (this.id == null) {
      this.id = UUID.randomUUID();
    }
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    if (this.createdAt == null) {
      this.createdAt = now;
    }
    if (this.updatedAt == null) {
      this.updatedAt = now;
    }
  }

  @PreUpdate
  void onUpdate() {
    this.updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }
}
