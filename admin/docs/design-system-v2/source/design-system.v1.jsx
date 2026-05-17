/* global React, Icons */
// Design system specimen — documents tokens + components used in the prototype.

const { useState: useStateDS, useEffect: useEffectDS } = React;

// ─────── Foundations ───────

const COLOR_GROUPS = [
  {
    title: "Surfaces & Text",
    sub: "Slate-based neutral scale. Light/dark는 같은 토큰을 다른 값으로 매핑.",
    tokens: [
      { name: "--bg", role: "페이지 배경" },
      { name: "--surface", role: "카드 · 시트 · 패널" },
      { name: "--surface-2", role: "subtle 카드 hover · 헤더 영역" },
      { name: "--surface-3", role: "input 그룹 · code block" },
      { name: "--border", role: "기본 1px 라인" },
      { name: "--border-strong", role: "강조 라인 · toggle off" },
      { name: "--text", role: "본문 텍스트" },
      { name: "--text-soft", role: "부제목 · 보조 텍스트" },
      { name: "--text-mute", role: "라벨 · 메타 정보" },
      { name: "--text-faint", role: "placeholder · disabled" },
    ],
  },
  {
    title: "Accent (테마 컬러)",
    sub: "Tweaks에서 4가지 중 선택. accent-soft는 자동 파생.",
    tokens: [
      { name: "--accent", role: "primary 버튼 · 활성 탭 · 링크" },
      { name: "--accent-hover", role: "primary 버튼 hover" },
      { name: "--accent-soft", role: "활성 nav · 선택된 chip 배경" },
      { name: "--accent-soft-2", role: "차트 보조 fill" },
    ],
  },
  {
    title: "Semantic",
    sub: "상태/감정 표현. badge, toast, alert 카드 등에서 ${color} + ${color}-soft 페어로 사용.",
    tokens: [
      { name: "--success", role: "ACTIVE · INTACT · 성공" },
      { name: "--warning", role: "변경 사항 · PENDING · 주의" },
      { name: "--danger", role: "REVOKED · TAMPERED · 위험" },
      { name: "--info", role: "RP_ADMIN · 정보 안내" },
      { name: "--violet", role: "PLATFORM_OPERATOR · 운영 액션" },
      { name: "--teal", role: "보조 — 보안 그린 톤" },
    ],
  },
];

function ColorsSection() {
  return (
    <div className="stack-6">
      {COLOR_GROUPS.map((g) => (
        <section key={g.title}>
          <SectionHead title={g.title} sub={g.sub} />
          <div className="grid-2" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))" }}>
            {g.tokens.map((t) => <ColorChip key={t.name} {...t} />)}
          </div>
        </section>
      ))}
    </div>
  );
}

function ColorChip({ name, role }) {
  const [actual, setActual] = useStateDS("");
  useEffectDS(() => {
    const r = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    setActual(r);
  }, [name]);
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden", background: "var(--surface)" }}>
      <div style={{ height: 64, background: `var(${name})`, borderBottom: "1px solid var(--border)" }} />
      <div style={{ padding: "10px 12px" }}>
        <code style={{ fontSize: 12, fontFamily: "var(--mono)", color: "var(--text)" }}>{name}</code>
        <div style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 2 }}>{role}</div>
        {actual && <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--text-faint)", marginTop: 4 }}>{actual}</div>}
      </div>
    </div>
  );
}

// ─────── Typography ───────

const TYPE_SAMPLES = [
  { size: 38, weight: 600, role: "Display · 로그인 hero · 마케팅", sample: "패스키 인증을 운영하는 콘솔." },
  { size: 28, weight: 600, role: "Metric value · KPI 카드", sample: "449,071" },
  { size: 22, weight: 600, role: "Page title · 페이지 헤더", sample: "Tenants" },
  { size: 16, weight: 600, role: "Dialog title", sample: "운영자 추가" },
  { size: 14, weight: 600, role: "Card title · 강조 항목", sample: "WebAuthn 요약" },
  { size: 13, weight: 500, role: "Body · 본문 / 메뉴", sample: "이 작업은 되돌릴 수 없습니다. RP 서비스에 새 키가 배포되어 있는지 확인하세요." },
  { size: 12, weight: 500, role: "Label · 보조 캡션", sample: "마지막 검증 · 2분 전 · 1,284,920 행" },
  { size: 11, weight: 600, role: "Metric label · 칼럼 헤더", sample: "검증된 AUDIT ROW" },
];

function TypeSection() {
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Font stack" sub="한국어 본문은 Pretendard, code/mono는 JetBrains Mono. 두 family 모두 self-host (CDN fallback)." />
        <div className="grid-2">
          <div className="card"><div className="card__body">
            <div style={{ fontSize: 12, color: "var(--text-mute)" }}>--font</div>
            <div style={{ fontSize: 28, marginTop: 8, letterSpacing: "-0.01em" }}>Pretendard</div>
            <div style={{ fontSize: 13, color: "var(--text-soft)", marginTop: 8, lineHeight: 1.6 }}>
              한국어 가독성 · 영문은 system-ui fallback. weight 400/500/600 사용.<br/>
              <code style={{ fontSize: 11, background: "var(--surface-3)", padding: "1px 6px", borderRadius: 3 }}>--font: "Pretendard", -apple-system, ...</code>
            </div>
          </div></div>
          <div className="card"><div className="card__body">
            <div style={{ fontSize: 12, color: "var(--text-mute)" }}>--mono</div>
            <div style={{ fontSize: 28, marginTop: 8, fontFamily: "var(--mono)", letterSpacing: "-0.02em" }}>JetBrains Mono</div>
            <div style={{ fontSize: 13, color: "var(--text-soft)", marginTop: 8, lineHeight: 1.6 }}>
              ID · timestamp · API key · audit hash 모두 mono로. weight 400/500/600.<br/>
              <code className="mono" style={{ fontSize: 11, background: "var(--surface-3)", padding: "1px 6px", borderRadius: 3 }}>pk_aB3xY7Q9.•••••</code>
            </div>
          </div></div>
        </div>
      </section>

      <section>
        <SectionHead title="Type scale" sub="명목 사이즈 + 사용 위치. compact density에서 row 글자는 13px, comfortable에서는 14px." />
        <div className="card"><div style={{ padding: 0 }}>
          {TYPE_SAMPLES.map((t, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "100px 1fr 280px", alignItems: "center", padding: "16px 20px", borderBottom: i === TYPE_SAMPLES.length - 1 ? 0 : "1px solid var(--border)", gap: 16 }}>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)" }}>{t.size}px / {t.weight}</div>
              <div style={{ fontSize: t.size, fontWeight: t.weight, letterSpacing: t.size >= 22 ? "-0.01em" : "0" }}>{t.sample}</div>
              <div style={{ fontSize: 12, color: "var(--text-mute)" }}>{t.role}</div>
            </div>
          ))}
        </div></div>
      </section>
    </div>
  );
}

// ─────── Spacing / Radii / Shadows ───────

function SpacingSection() {
  const spaces = [4, 6, 8, 10, 12, 14, 16, 20, 24];
  const radii = [
    { name: "--radius-sm", v: "4px", role: "kbd · 작은 코드 인라인" },
    { name: "--radius", v: "6px", role: "버튼 · 입력 · chip" },
    { name: "--radius-lg", v: "10px", role: "card · sidebar block" },
    { name: "--radius-xl", v: "14px", role: "dialog · scrim 모달" },
  ];
  const shadows = [
    { name: "--shadow-sm", role: "card 기본 깊이" },
    { name: "--shadow-md", role: "toast · dropdown" },
    { name: "--shadow-lg", role: "dialog · focus overlay" },
  ];
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Spacing" sub="8px 베이스 + 4px 보조. stack-1/3/4/6 유틸리티는 4/12/16/24px gap." />
        <div className="card"><div className="card__body" style={{ display: "flex", alignItems: "flex-end", gap: 24, flexWrap: "wrap" }}>
          {spaces.map((s) => (
            <div key={s} style={{ textAlign: "center" }}>
              <div style={{ width: s, height: s, background: "var(--accent)", borderRadius: 2, margin: "0 auto" }} />
              <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 8 }}>{s}px</div>
            </div>
          ))}
        </div></div>
      </section>

      <section>
        <SectionHead title="Border radius" sub="네 단계만 사용. 카드는 항상 lg, 모달은 항상 xl." />
        <div className="grid-4">
          {radii.map((r) => (
            <div key={r.name} className="card">
              <div style={{ height: 80, background: "var(--accent-soft)", borderRadius: `var(${r.name})`, margin: 14, border: "1px solid color-mix(in oklab, var(--accent) 30%, transparent)" }} />
              <div style={{ padding: "0 16px 14px" }}>
                <code className="mono" style={{ fontSize: 11 }}>{r.name}</code>
                <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 2 }}>{r.v}</div>
                <div style={{ fontSize: 11, color: "var(--text-soft)", marginTop: 6 }}>{r.role}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionHead title="Shadow" sub="화면 깊이를 3단계로만. light/dark 두 테마 모두에서 잘 보이도록 alpha 조정." />
        <div className="grid-3">
          {shadows.map((s) => (
            <div key={s.name} className="card" style={{ boxShadow: `var(${s.name})` }}>
              <div className="card__body">
                <code className="mono" style={{ fontSize: 12 }}>{s.name}</code>
                <div style={{ fontSize: 12, color: "var(--text-mute)", marginTop: 6 }}>{s.role}</div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

// ─────── Buttons ───────

function ButtonsSection() {
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Variants" sub="primary는 한 화면에 1~2개만. ghost는 close/cancel 같은 secondary action." />
        <div className="card"><div className="card__body" style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}>
          <button className="btn btn--primary">primary</button>
          <button className="btn">default</button>
          <button className="btn btn--ghost">ghost</button>
          <button className="btn btn--danger">danger</button>
          <button className="btn" disabled>disabled</button>
          <button className="btn btn--primary"><Icons.Plus size={13} /> with icon</button>
          <button className="btn"><Icons.Refresh size={12} /> Refresh</button>
        </div></div>
      </section>

      <section>
        <SectionHead title="Sizes" sub="기본 · sm · xs. compact 테이블의 row action은 xs." />
        <div className="card"><div className="card__body" style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <button className="btn btn--primary">기본 (6/12)</button>
          <button className="btn btn--primary btn--sm">sm (4/8)</button>
          <button className="btn btn--primary btn--xs">xs (2/6)</button>
        </div></div>
      </section>
    </div>
  );
}

// ─────── Inputs / Form ───────

function InputsSection() {
  const [v, setV] = useStateDS("acme-corp");
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Text input" sub="모든 input은 .input 클래스. focus 시 accent border + 3px outer ring." />
        <div className="card"><div className="card__body stack-3" style={{ maxWidth: 420 }}>
          <Field label="이메일" hint="로그인 ID로 사용됩니다.">
            <input className="input" placeholder="user@example.com" />
          </Field>
          <Field label="Slug" hint="URL-safe ID. 한 번 생성되면 변경 불가.">
            <input className="input mono" value={v} onChange={(e) => setV(e.target.value)} />
          </Field>
          <Field label="비밀번호 (disabled)">
            <input className="input" type="password" placeholder="••••••••••" disabled />
          </Field>
        </div></div>
      </section>

      <section>
        <SectionHead title="Segmented" sub="2~4개 옵션의 enum 선택. WebAuthn UV/AC 같은 fixed-set 필드용." />
        <div className="card"><div className="card__body row" style={{ flexWrap: "wrap", gap: 16 }}>
          <Segmented value="REQUIRED" onChange={() => {}} options={["REQUIRED", "PREFERRED", "DISCOURAGED"]} />
          <Segmented value="DIRECT" onChange={() => {}} options={["NONE", "INDIRECT", "DIRECT", "ENTERPRISE"]} />
        </div></div>
      </section>

      <section>
        <SectionHead title="Toggle" sub="boolean — MFA 강제, MDS strict 등." />
        <div className="card"><div className="card__body row" style={{ gap: 24 }}>
          <Toggle on={true} onChange={() => {}} label="MFA 필수" />
          <Toggle on={false} onChange={() => {}} label="MDS strict OFF" />
        </div></div>
      </section>

      <section>
        <SectionHead title="Chip input (multi-value)" sub="WebAuthn origins, AAGUID allowlist — 여러 값을 enter로 누적." />
        <div className="card"><div className="card__body">
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 8px", border: "1px solid var(--border)", borderRadius: 8, background: "var(--surface)" }}>
            <span className="chip mono" style={{ fontSize: 11 }}>https://acme.example.com<button className="chip__x"><Icons.X size={11} /></button></span>
            <span className="chip mono" style={{ fontSize: 11 }}>https://app.acme.example.com<button className="chip__x"><Icons.X size={11} /></button></span>
            <input placeholder="https://… 입력 후 Enter" style={{ border: 0, outline: "none", fontSize: 12, padding: "2px 4px", flex: 1, minWidth: 200, background: "transparent", color: "var(--text)" }} />
          </div>
        </div></div>
      </section>
    </div>
  );
}

// ─────── Badges / Status ───────

function BadgesSection() {
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Tone" sub="모든 badge는 ${tone}-soft 배경 + ${tone} 텍스트. dot은 앞에 6px circle 추가." />
        <div className="card"><div className="card__body" style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {[
            ["default", "default"],
            ["success", "ACTIVE"],
            ["warning", "PENDING"],
            ["danger", "REVOKED"],
            ["info", "RP_ADMIN"],
            ["violet", "PLATFORM"],
            ["teal", "MDS"],
            ["accent", "Apple Passkey"],
          ].map(([t, label]) => (
            <span key={t} className={`badge ${t==="default"?"":"badge--"+t}`}>{label}</span>
          ))}
        </div></div>
      </section>

      <section>
        <SectionHead title="Dotted (status)" sub="상태값에 사용. dot이 가독성을 더하고 색맹에도 보임." />
        <div className="card"><div className="card__body" style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          <span className="badge badge--success badge--dot">INTACT</span>
          <span className="badge badge--danger badge--dot">TAMPERED · 2</span>
          <span className="badge badge--warning badge--dot">PENDING</span>
          <span className="badge badge--info badge--dot">PROCESSING</span>
        </div></div>
      </section>
    </div>
  );
}

// ─────── Cards / Layout ───────

function LayoutSection() {
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Card" sub=".card__head + .card__body. 헤더에 타이틀 + 우측 액션, body는 24px padding." />
        <div className="card">
          <div className="card__head">
            <div>
              <h3 className="card__title">예시 카드 헤더</h3>
              <div className="card__sub">설명 한 줄. 12px text-mute.</div>
            </div>
            <button className="btn btn--sm"><Icons.Plus size={12} /> 액션</button>
          </div>
          <div className="card__body">
            <p style={{ margin: 0, fontSize: 13, color: "var(--text-soft)", lineHeight: 1.6 }}>카드 body. 1px border, 10px radius, shadow-sm. 안쪽 padding은 <code style={{ background: "var(--surface-3)", padding: "1px 4px", borderRadius: 3 }}>--card-pad</code> (compact 20 / comfortable 24).</p>
          </div>
        </div>
      </section>

      <section>
        <SectionHead title="Metric card" sub="KPI 4개씩 grid-4. 클릭 가능한 경우는 hover에 옅은 outline." />
        <div className="grid-4">
          <DSMetric label="활성 Tenant" value="58" sub="전체 9건" />
          <DSMetric label="등록 Credential" value="449,071" sub="모든 tenant 합산" />
          <DSMetric label="검증된 ROW" value="1,284,920" sub="누적 chain length" />
          <DSMetric label="평균 응답" value="18ms" sub="p95 42ms · p99 89ms" />
        </div>
      </section>

      <section>
        <SectionHead title="Tabs" sub="페이지 내 서브 네비. 활성 탭은 accent border-bottom 2px." />
        <div className="card"><div style={{ padding: "0 16px" }}>
          <div className="tabs" style={{ marginBottom: 0, borderBottom: 0 }}>
            <button className="tabs__btn tabs__btn--active">개요</button>
            <button className="tabs__btn">WebAuthn</button>
            <button className="tabs__btn">AAGUID 정책</button>
            <button className="tabs__btn">API Keys</button>
          </div>
        </div></div>
      </section>
    </div>
  );
}

function DSMetric({ label, value, sub }) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-delta">{sub}</div>
    </div>
  );
}

// ─────── Table ───────

function TableSection() {
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="Table" sub="기본은 row 사이 1px 라인. Tweaks에서 striped/borderless로 전환. row hover는 surface-2." />
        <div className="card">
          <table className="table">
            <thead>
              <tr><th>Tenant</th><th>RP ID</th><th style={{ textAlign: "right" }}>Credentials</th><th>Status</th></tr>
            </thead>
            <tbody>
              <tr><td><div className="row"><div style={{ width: 22, height: 22, borderRadius: 5, background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 10 }}>A</div><span style={{ fontWeight: 500 }}>Acme Corp</span></div></td><td className="mono" style={{ fontSize: 12 }}>acme.example.com</td><td className="mono" style={{ textAlign: "right" }}>14,823</td><td><span className="badge badge--success badge--dot">ACTIVE</span></td></tr>
              <tr><td><div className="row"><div style={{ width: 22, height: 22, borderRadius: 5, background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 10 }}>G</div><span style={{ fontWeight: 500 }}>Globex Financial</span></div></td><td className="mono" style={{ fontSize: 12 }}>auth.globex-fin.com</td><td className="mono" style={{ textAlign: "right" }}>92,471</td><td><span className="badge badge--success badge--dot">ACTIVE</span></td></tr>
              <tr style={{ opacity: 0.55 }}><td><div className="row"><div style={{ width: 22, height: 22, borderRadius: 5, background: "var(--accent-soft)", color: "var(--accent)", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 10 }}>P</div><span style={{ fontWeight: 500 }}>Pied Piper</span></div></td><td className="mono" style={{ fontSize: 12 }}>id.piedpiper.app</td><td className="mono" style={{ textAlign: "right" }}>412</td><td><span className="badge badge--warning badge--dot">SUSPENDED</span></td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

// ─────── Icons ───────

function IconsSection() {
  const names = Object.keys(Icons);
  return (
    <div>
      <SectionHead title={`Icons · ${names.length}개`} sub="모두 1.6px stroke · 24px viewBox · currentColor 상속. <Icons.X size={n} />로 사용." />
      <div className="card"><div className="card__body" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(120px, 1fr))", gap: 4 }}>
        {names.map((n) => {
          const I = Icons[n];
          return (
            <div key={n} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: 6, background: "var(--surface)" }}>
              <div style={{ width: 26, height: 26, display: "grid", placeItems: "center", borderRadius: 5, background: "var(--surface-3)", color: "var(--text)", flex: "none" }}>
                <I size={16} />
              </div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-soft)", overflow: "hidden", textOverflow: "ellipsis" }}>{n}</div>
            </div>
          );
        })}
      </div></div>
    </div>
  );
}

// ─────── Patterns ───────

function PatternsSection() {
  return (
    <div className="stack-6">
      <section>
        <SectionHead title="확인 다이얼로그" sub="회수/삭제 같은 비가역적 액션은 항상 별도 다이얼로그. 대상 식별자 마지막 N자 표시 + 위험 버튼은 danger 톤." />
        <div className="card" style={{ padding: 20, maxWidth: 480 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>API key를 회수하시겠습니까?</div>
          <div style={{ fontSize: 12, color: "var(--text-mute)", marginBottom: 14 }}>회수된 키는 다음 ceremony부터 401을 받습니다.</div>
          <div style={{ padding: 12, border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface-2)", fontSize: 12 }}>
            <div style={{ display: "grid", gridTemplateColumns: "80px 1fr", rowGap: 6 }}>
              <span className="muted">prefix</span><span className="mono">pk_aB3xY7Q9</span>
              <span className="muted">이름</span><span>production</span>
            </div>
          </div>
          <div style={{ marginTop: 12, padding: 10, background: "var(--danger-soft)", color: "var(--danger)", borderRadius: 6, fontSize: 12, display: "flex", gap: 8 }}>
            <Icons.Alert size={14} />
            <span>이 작업은 되돌릴 수 없습니다.</span>
          </div>
          <div style={{ marginTop: 14, display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button className="btn">취소</button>
            <button className="btn btn--danger">회수</button>
          </div>
        </div>
      </section>

      <section>
        <SectionHead title="Plaintext 1회 노출" sub="API key 발급 직후. 복사 강제 체크박스 + 닫으면 영구 소실 안내. 사용자가 실수로 닫지 못하게 closeOnScrim=false." />
        <div className="card" style={{ padding: 20, maxWidth: 600 }}>
          <div className="row" style={{ gap: 8, marginBottom: 6 }}>
            <Icons.Alert size={18} />
            <div style={{ fontWeight: 600, fontSize: 14 }}>새 API key가 발급되었습니다 — 지금만 표시됩니다</div>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-mute)", marginBottom: 14 }}>이 창을 닫으면 plaintext는 영구히 사라집니다.</div>
          <div style={{ position: "relative" }}>
            <div style={{ fontFamily: "var(--mono)", fontSize: 12, padding: "14px 96px 14px 16px", background: "var(--surface-3)", borderRadius: 8, border: "1px solid var(--border)", wordBreak: "break-all" }}>
              <span style={{ color: "var(--accent)", fontWeight: 600 }}>pk_aB3xY7Q9</span>.7M9bK2pXqL4nVe8RtY3uHj1KsAo5fG6dWmZxCpVbN…
            </div>
            <button className="btn btn--primary btn--sm" style={{ position: "absolute", top: 8, right: 8 }}><Icons.Copy size={12} /> 클립보드</button>
          </div>
          <label style={{ display: "flex", gap: 10, padding: 12, marginTop: 12, background: "var(--warning-soft)", border: "1px solid color-mix(in oklab, var(--warning) 25%, transparent)", borderRadius: 8 }}>
            <input type="checkbox" style={{ marginTop: 2 }} />
            <div style={{ fontSize: 13 }}>
              <div style={{ fontWeight: 600, color: "var(--warning)" }}>안전한 장소에 복사했습니다.</div>
              <div style={{ color: "var(--text-soft)", fontSize: 12, marginTop: 2 }}>닫기 후에는 재조회 불가능합니다.</div>
            </div>
          </label>
        </div>
      </section>

      <section>
        <SectionHead title="Diff 표시" sub="WebAuthn config 변경 저장 직전. - 빨강 / + 초록. origins 같은 배열은 added/removed 라인 단위로." />
        <div className="card" style={{ padding: 20, maxWidth: 600 }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600 }}>origins</div>
          <div style={{ marginTop: 8, display: "grid", gap: 4 }}>
            <div style={{ display: "flex", gap: 8, padding: "4px 10px", background: "color-mix(in oklab, var(--danger-soft) 70%, transparent)", borderRadius: 4, fontFamily: "var(--mono)", fontSize: 12, color: "var(--danger)" }}>
              <span style={{ width: 10, fontWeight: 700 }}>-</span>
              <span style={{ color: "var(--text)" }}>https://staging.acme.example.com</span>
            </div>
            <div style={{ display: "flex", gap: 8, padding: "4px 10px", background: "color-mix(in oklab, var(--success-soft) 70%, transparent)", borderRadius: 4, fontFamily: "var(--mono)", fontSize: 12, color: "var(--success)" }}>
              <span style={{ width: 10, fontWeight: 700 }}>+</span>
              <span style={{ color: "var(--text)" }}>https://app.acme.example.com</span>
            </div>
          </div>
        </div>
      </section>

      <section>
        <SectionHead title="Toast" sub="우측 하단 stack. 4.2초 후 자동 dismiss. traceId 노출로 디버그 가능." />
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {[
            { kind: "ok", title: "WebAuthn config 저장됨", message: "3개 필드 업데이트", traceId: "tr_4f2c1b" },
            { kind: "warn", title: "API key가 회수되었습니다", message: "pk_aB3xY7Q9 · production", traceId: "tr_8c9e21" },
            { kind: "err", title: "권한이 없습니다", message: "M002 · requireTenantAccess", traceId: "tr_991a82" },
          ].map((t, i) => (
            <div key={i} className="toast" style={{ position: "static", animation: "none" }}>
              <div className={`toast__icon toast__icon--${t.kind}`}>{t.kind === "err" ? <Icons.X size={11} /> : t.kind === "warn" ? <Icons.Alert size={11} /> : <Icons.Check size={11} />}</div>
              <div style={{ flex: 1 }}>
                <div className="toast__title">{t.title}</div>
                <div className="toast__sub">{t.message}</div>
                <div className="toast__trace">traceId · {t.traceId}</div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

// ─────── Field & Section helpers ───────

function SectionHead({ title, sub }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 18, fontWeight: 600, letterSpacing: "-0.01em" }}>{title}</div>
      {sub && <div style={{ fontSize: 13, color: "var(--text-mute)", marginTop: 4, maxWidth: 720 }}>{sub}</div>}
    </div>
  );
}

// ─────── App ───────

const SECTIONS = [
  { id: "colors", label: "Colors", icon: "Sparkles", render: () => <ColorsSection /> },
  { id: "type", label: "Typography", icon: "Receipt", render: () => <TypeSection /> },
  { id: "spacing", label: "Spacing · Radii · Shadow", icon: "Filter", render: () => <SpacingSection /> },
  { id: "buttons", label: "Buttons", icon: "Plus", render: () => <ButtonsSection /> },
  { id: "inputs", label: "Inputs · Form", icon: "Menu", render: () => <InputsSection /> },
  { id: "badges", label: "Badges · Status", icon: "Shield", render: () => <BadgesSection /> },
  { id: "layout", label: "Cards · Layout · Tabs", icon: "Building", render: () => <LayoutSection /> },
  { id: "table", label: "Tables", icon: "Receipt", render: () => <TableSection /> },
  { id: "icons", label: "Icons", icon: "Sparkles", render: () => <IconsSection /> },
  { id: "patterns", label: "Patterns", icon: "Activity", render: () => <PatternsSection /> },
];

function DesignSystemApp() {
  const hashParams = (() => {
    const out = {};
    (location.hash || "").replace(/^#/, "").split("&").forEach((p) => {
      if (!p) return;
      const [k, v] = p.split("=");
      out[decodeURIComponent(k)] = decodeURIComponent(v || "");
    });
    return out;
  })();

  const [t, setTweak] = useTweaks({
    theme: hashParams.theme || "light",
    accent: hashParams.accent || "#5469d4",
  });

  useEffectDS(() => {
    const root = document.documentElement;
    root.setAttribute("data-theme", t.theme);
    root.setAttribute("data-density", "comfortable");
    root.setAttribute("data-tablestyle", "lines");
    root.style.setProperty("--accent", t.accent);
    root.style.setProperty("--accent-hover", shadeDS(t.accent, -10));
    root.style.setProperty("--accent-soft", withAlphaDS(t.accent, 0.12));
    root.style.setProperty("--accent-soft-2", withAlphaDS(t.accent, 0.22));
  }, [t]);

  const [active, setActive] = useStateDS("colors");
  const sec = SECTIONS.find((s) => s.id === active);

  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", minHeight: "100vh" }}>
        <aside style={{
          background: "var(--surface)", borderRight: "1px solid var(--border)",
          position: "sticky", top: 0, height: "100vh", overflow: "auto",
          padding: "20px 14px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 6px 18px", borderBottom: "1px solid var(--border)", marginBottom: 14 }}>
            <BrandMark size={26} />
            <div>
              <div style={{ fontWeight: 600, fontSize: 13, letterSpacing: "-0.01em" }}>Passkey Admin</div>
              <div style={{ fontSize: 11, color: "var(--text-mute)" }}>Design System v1.0</div>
            </div>
          </div>

          <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-mute)", textTransform: "uppercase", letterSpacing: "0.06em", padding: "8px 8px 4px" }}>FOUNDATIONS</div>
          {SECTIONS.slice(0, 3).map((s) => <DSNavBtn key={s.id} item={s} active={active === s.id} onClick={() => setActive(s.id)} />)}
          <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-mute)", textTransform: "uppercase", letterSpacing: "0.06em", padding: "16px 8px 4px" }}>COMPONENTS</div>
          {SECTIONS.slice(3, 8).map((s) => <DSNavBtn key={s.id} item={s} active={active === s.id} onClick={() => setActive(s.id)} />)}
          <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-mute)", textTransform: "uppercase", letterSpacing: "0.06em", padding: "16px 8px 4px" }}>REFERENCE</div>
          {SECTIONS.slice(8).map((s) => <DSNavBtn key={s.id} item={s} active={active === s.id} onClick={() => setActive(s.id)} />)}

          <div style={{ marginTop: 24, padding: "10px 12px", background: "var(--surface-3)", borderRadius: 8 }}>
            <div className="row" style={{ gap: 8 }}>
              <Icons.ExternalLink size={13} />
              <a href="Passkey Admin Console.html" target="_blank" style={{ fontSize: 12, color: "var(--accent)", textDecoration: "none", fontWeight: 500 }}>실제 프로토타입 열기</a>
            </div>
            <div style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 4 }}>이 시스템이 사용되는 곳</div>
          </div>
        </aside>

        <main style={{ padding: "36px 44px 80px", maxWidth: 1280 }}>
          <div style={{ marginBottom: 32 }}>
            <div style={{ fontSize: 11, color: "var(--text-mute)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600 }}>{
              SECTIONS.indexOf(sec) < 3 ? "Foundations" : SECTIONS.indexOf(sec) < 8 ? "Components" : "Reference"
            }</div>
            <h1 style={{ fontSize: 32, fontWeight: 600, letterSpacing: "-0.02em", margin: "6px 0 0" }}>{sec.label}</h1>
          </div>
          {sec.render()}
        </main>
      </div>

      <TweaksPanel title="Tweaks">
        <TweakSection label="테마" />
        <TweakRadio label="모드" value={t.theme} onChange={(v) => setTweak("theme", v)} options={[{value:"light",label:"Light"},{value:"dark",label:"Dark"}]} />
        <TweakColor label="Accent" value={t.accent} onChange={(v) => setTweak("accent", v)} options={["#5469d4", "#7c3aed", "#0d9488", "#d97706"]} />
      </TweaksPanel>
    </>
  );
}

function DSNavBtn({ item, active, onClick }) {
  const I = Icons[item.icon] || Icons.ChevronRight;
  return (
    <button onClick={onClick} style={{
      display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "7px 10px",
      background: active ? "var(--accent-soft)" : "transparent",
      color: active ? "var(--accent)" : "var(--text-soft)",
      border: 0, borderRadius: 7,
      fontSize: 13, fontWeight: active ? 600 : 500, cursor: "pointer", textAlign: "left",
      marginBottom: 1,
    }}
      onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "var(--surface-3)"; }}
      onMouseLeave={(e) => { if (!active) e.currentTarget.style.background = "transparent"; }}
    >
      <I size={14} />
      <span>{item.label}</span>
    </button>
  );
}

function shadeDS(hex, p) {
  const h = hex.replace("#", "");
  const n = parseInt(h, 16);
  let r = Math.max(0, Math.min(255, (n >> 16) + Math.round(2.55 * p)));
  let g = Math.max(0, Math.min(255, ((n >> 8) & 0xff) + Math.round(2.55 * p)));
  let b = Math.max(0, Math.min(255, (n & 0xff) + Math.round(2.55 * p)));
  return `rgb(${r},${g},${b})`;
}
function withAlphaDS(hex, a) {
  const h = hex.replace("#", "");
  const n = parseInt(h, 16);
  return `rgba(${n >> 16},${(n >> 8) & 0xff},${n & 0xff},${a})`;
}

const dsRoot = ReactDOM.createRoot(document.getElementById("root"));
dsRoot.render(<DesignSystemApp />);
