package com.crosscert.passkey.audit.domain;

/**
 * 운영자 UI 필터 칩이 audit 이벤트를 묶기 위해 사용하는 의미적 카테고리. {@link AuditEventType}이 각자 한 값을 가리킨다. 서버가 응답에 미리 채워서
 * 보내므로 클라이언트는 매핑 로직을 갖지 않는다 — single source of truth.
 *
 * <p>세 값의 정의:
 *
 * <ul>
 *   <li>{@link #CEREMONY} — 정상 WebAuthn 등록/인증 경로 + backup-state 전환 같은 부산물 이벤트.
 *   <li>{@link #ADMIN_ACTION} — 운영자(관리자)가 명시적으로 트리거한 변경. RP API 키 발급, tenant 상태 변경, WebAuthn config
 *       갱신 등.
 *   <li>{@link #SECURITY_FAIL} — 보안 이상 신호. signature counter 회귀, attestation 신뢰 실패, rate-limit 위반,
 *       MDS 무효화로 인한 자동 정지/회수.
 * </ul>
 */
public enum AuditCategory {
  CEREMONY,
  ADMIN_ACTION,
  SECURITY_FAIL
}
