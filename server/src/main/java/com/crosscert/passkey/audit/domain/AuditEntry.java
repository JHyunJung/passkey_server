package com.crosscert.passkey.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Append-only audit row. Composite PK (id, createdAt) — required by Postgres partitioning by
 * created_at.
 */
@Getter
@Entity
@Table(name = "audit_log", schema = "passkey")
@IdClass(AuditEntry.Pk.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditEntry {

  @Id
  @Column(name = "id", columnDefinition = "uuid", updatable = false, nullable = false)
  private UUID id;

  @Id
  @Column(name = "created_at", nullable = false, updatable = false)
  private OffsetDateTime createdAt;

  @Column(name = "tenant_id", nullable = false, updatable = false, columnDefinition = "uuid")
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

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "payload", updatable = false, columnDefinition = "jsonb")
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
