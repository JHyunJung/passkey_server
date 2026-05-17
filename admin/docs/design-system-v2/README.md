# Design System v2

> Linear/Vercel 풍 OKLCH 디자인 시스템. claude.ai/design 핸드오프 번들 v2(2026-05-16).
> 현재 `/console` 라우트에 적용되어 있으며, 추후 admin 전역에 채택할 수 있도록 원본 자료를 보관함.

## 어디에 적용되어 있나

| 위치 | 적용 여부 | 비고 |
|------|-----------|------|
| `/console/*` (`src/pages/console/console.css`) | ✅ v2 적용 완료 | `.console-scope` 안에서만 동작, 외부 admin과 격리 |
| admin 본체 (`src/index.css`, `tailwind.config.ts`) | ❌ 미적용 (shadcn 기본값 유지) | 추후 채택할 때 본 디렉토리 참조 |

## 디렉토리 구조

```
docs/design-system-v2/
├── README.md                      # 이 파일
└── source/
    ├── tokens.css                 # v2 원본 토큰 (OKLCH)
    ├── tokens.v1.css              # v1 원본 (비교용 · 변경 전)
    ├── Design System.html         # specimen 페이지 (브라우저에서 열면 시각화됨)
    ├── design-system.jsx          # specimen 페이지의 React 코드
    ├── design-system.v1.jsx       # v1 specimen (비교용)
    └── chat-history.md            # 디자이너와의 의사결정 기록
```

## v2 변경점 (v1 대비)

### 토큰

- **색공간**: HEX → **OKLCH** (브라우저 native 지원, 폴리필 불필요)
- 신규 surface: `--surface-sunk`
- 신규 border: `--border-subtle` (`--border`보다 더 옅음, 카드/테이블 row 구분선용)
- 신규 accent: `--accent-press` (active 상태), `--accent-fg` (accent 위 텍스트 색)
- 신규 shadow: `--shadow-xs` (hairline depth용)
- 신규 radius: `--radius-xs` (4px), `--radius-pill` (999px)
- 신규 typography: `--letter-tight` (-0.011em), `--letter-tighter` (-0.022em)
- **모션 토큰 신규**: `--dur-fast/--dur/--dur-slow`, `--ease-out/in-out/spring`
- 신규 a11y: `--focus-ring` (모든 인터랙티브 요소에 통일된 포커스 링)

### 타이포

- **폰트**: Geist Sans / Geist Mono 추가 (영문/숫자), Pretendard는 한글 fallback
- 숫자에 `tabular-nums` 적용 → 표/메트릭 정렬
- OpenType `cv11/ss01/ss03` 활성화

### 컴포넌트 — 신규 4종

- `.skeleton` — shimmer 로딩 placeholder
- `.banner` — neutral/info/success/warning/danger 톤의 inline alert
- `.empty` — 빈 상태 표시 (icon + title + sub)
- `.kbd` — refined 키보드 힌트 (KbdCombo로 조합 가능)

### 다크 모드

- v1 대비 더 따뜻한 black (`oklch(0.155 0.005 270)`) — Linear 스타일
- 다크 그림자는 RGBA로 fallback (브라우저별 OKLCH 알파 호환성)

### 접근성

- `@media (prefers-reduced-motion: reduce)` — 모션 자동 비활성화

## 추후 admin 전역에 채택하려면

본 v2를 `/console`이 아닌 admin 본체에 적용하려면 대략 다음 작업이 필요함:

1. **토큰 도입**
   - `src/index.css`의 shadcn HSL 변수를 `tokens.css`의 OKLCH로 교체 (또는 병행)
   - shadcn 변수와 매핑 필요:
     - `--primary` ← `--accent`
     - `--destructive` ← `--danger`
     - `--muted` ← `--surface-3`
     - `--accent` (shadcn) ← `--accent-soft` (v2)
   - `tailwind.config.ts`에 의미론적 색상 추가:
     `success/warning/info/violet/teal` 각각 DEFAULT + soft 페어

2. **폰트 로딩**
   - `index.html`에 Geist + Pretendard CDN `<link>` 추가
   - `tailwind.config.ts`의 `fontFamily.sans/mono` 에 Geist 우선 등록

3. **shadcn 컴포넌트 업그레이드**
   - `button.tsx`: `--focus-ring` 사용, motion 토큰 `--dur/--ease-out` 적용
   - `badge.tsx`: variant에 `warning/info/violet/teal/accent` 추가
   - `card.tsx`: border를 `--border-subtle`로

4. **신규 컴포넌트 포팅**
   - `src/components/ui/skeleton.tsx`, `banner.tsx`, `empty-state.tsx`, `kbd.tsx`
   - 이미 `src/pages/console/shell.tsx`에 `Skeleton`, `Banner`, `EmptyV2`, `KbdCombo` 구현체가 있음 — 그것을 generic 컴포넌트로 끌어올리면 됨

5. **다크 모드**
   - admin 본체에 `[data-theme="dark"]` 또는 `class="dark"` 토글 진입점 추가
   - 현재 admin에는 다크 모드 미구현 상태

## 시각적으로 확인하려면

### 옵션 A — `/console` 라우트에서 확인 (이미 적용됨)

```bash
npm run dev
# 브라우저: http://localhost:5173/console
# 우측 하단 토글로 라이트/다크 전환 가능
```

`/console` 화면 전체가 v2 토큰으로 렌더링됨. 9개 mock tenant, 7개 탭, 4개 설정 탭 모두 v2 적용 상태.

### 옵션 B — 원본 specimen 페이지 열기

```bash
open "docs/design-system-v2/source/Design System.html"
```

좌측 nav에서 Foundations(Colors / Type / Spacing) · Components(Buttons / Inputs / Badges / Layout / Table) · New v2(Motion / Skeleton & Banner) · Reference(Icons) · Patterns 섹션을 모두 둘러볼 수 있음.

## 라이센스 / 출처

- 출처: claude.ai/design 핸드오프 (Anthropic Claude Design)
- 디자인 의도/결정 기록: `source/chat-history.md`
- 폰트: Pretendard (OFL), Geist (MIT, Vercel)
