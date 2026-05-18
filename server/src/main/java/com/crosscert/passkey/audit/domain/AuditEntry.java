package com.crosscert.passkey.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Append-only audit row. Composite PK (id, createdAt) — required by Oracle interval partitioning on
 * created_at (the partitioning key must be part of the primary key for local indexes).
 */
@Getter
@Entity
@Table(name = "audit_log")
@IdClass(AuditEntry.Pk.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditEntry {

  @Id
  @Column(name = "id", updatable = false, nullable = false)
  private UUID id;

  @Id
  @Column(name = "created_at", nullable = false, updatable = false)
  private OffsetDateTime createdAt;

  @Column(name = "tenant_id", nullable = false, updatable = false)
  private UUID tenantId;

  @Enumerated(EnumType.STRING)
  @Column(name = "event_type", nullable = false, updatable = false)
  private AuditEventType eventType;

  @Enumerated(EnumType.STRING)
  @Column(name = "actor_type", nullable = false, updatable = false)
  private ActorType actorType;

  @Column(name = "actor_id", updatable = false)
  private String actorId;

  @Column(name = "subject_type", updatable = false)
  private String subjectType;

  @Column(name = "subject_id", updatable = false)
  private String subjectId;

  // Oracle 19c has no native JSON type. Stored as CLOB with a DDL-level `CHECK (payload IS JSON)`
  // constraint (see V1__oracle_baseline.sql) that gates malformed JSON at insert time. The CLOB
  // round-trips as String via ojdbc11's CLOB-as-string mode (auto-enabled by Hibernate when the
  // field type is String).
  @Lob
  @Column(name = "payload", updatable = false, columnDefinition = "CLOB")
  private String payload;

  @Column(name = "prev_hash", updatable = false)
  private String prevHash;

  @Column(name = "row_hash", nullable = false, updatable = false)
  private String rowHash;

  @SuppressWarnings("checkstyle:ParameterNumber")
  public AuditEntry(
      UUID id,
      OffsetDateTime createdAt,
      UUID tenantId,
      AuditEventType eventType,
      ActorType actorType,
      String actorId,
      String subjectType,
      String subjectId,
      String payload,
      String prevHash,
      String rowHash) {
    this.id = id;
    this.createdAt = createdAt;
    this.tenantId = tenantId;
    this.eventType = eventType;
    this.actorType = actorType;
    this.actorId = actorId;
    this.subjectType = subjectType;
    this.subjectId = subjectId;
    this.payload = payload;
    this.prevHash = prevHash;
    this.rowHash = rowHash;
  }

  @Getter
  @NoArgsConstructor
  public static class Pk implements Serializable {
    private UUID id;
    private OffsetDateTime createdAt;

    public Pk(UUID id, OffsetDateTime createdAt) {
      this.id = id;
      this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof Pk that)) return false;
      return Objects.equals(id, that.id) && Objects.equals(createdAt, that.createdAt);
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, createdAt);
    }
  }
}
