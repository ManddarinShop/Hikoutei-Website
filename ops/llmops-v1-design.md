# LLMOps v1 — 내부용 (동결)

첫 파이프라인 하나만 굴린다: `QA failure → fix PR`.
두 번째 자율 루프가 생기기 전까지 일반화 금지.

## 아키텍처

```
VM (발견+Q, 키 0개)                    GitHub Actions (뇌)              사람
demo-server + qa ─verdict→ qa-history.jsonl
                              ├─ watcher(tail+dedupe) → Q(SQLite)
                              └─ Q: pending→leased→done (UNIQUE dedupe_key)
                                            │ lease (10분 schedule)
                                            ▼
                              Website/qa-fix.yml: replay→opencode+Zen→PR
                                            │ cross-repo PAT
                                            ▼
                              ManddarinShop/Hikoutei 에 branch+PR ─→ 리뷰/머지
```

- library 레포는 순수 유지. 워크플로우는 Website 레포에만.
- VM에 시크릿 상주 금지. 키는 전부 Website 레포 Secrets.

## 컴포넌트

| # | 것 | 위치 | 상태 |
|---|---|---|---|
| 1 | qa harness (5s tick 퍼징) | Website `qa/` | 운영 중 |
| 2 | verdict 로그 | VM `demo/data/qa/qa-history.jsonl` | 운영 중 |
| 3 | Q watcher + Q (SQLite) | VM (신규) | 미구현 |
| 4 | qa-fix.yml (schedule 10분) | Website `.github/workflows/` | 미구현 |
| 5 | run record 로그 | Actions 로그 + 집계 (신규) | 미구현 |

## Q 스키마 (v1)

```sql
tasks(id INTEGER PK, dedupe_key TEXT UNIQUE,   -- sha1(seed|step|detail)
      status TEXT,          -- pending|leased|done|failed
      lease_until INTEGER, attempts INTEGER,
      payload TEXT, result TEXT, created_at INTEGER)
```

- lease = visibility timeout. worker는 `lease_until` 지난 pending만 잡는다.
- 중복 PR 방지 = `UNIQUE(dedupe_key)` 한 줄.

## Run record (실행당 1줄, LLMOps 원석)

```
{task, model, tokens_in, tokens_out, cost, latency_s, verdict, pr_url}
```

- opencode API가 cost/tokens/time을 반환하므로 수집 비용 0.
- 신규 failure 없으면 모델 호출 없이 종료 (비용 가드).

## Secrets (Website 레포, 전부 등록·검증됨)

- `DEMO_SSH_HOST/USER/KEY` — 기존, VM 읽기용
- `OPENCODE_ZEN_API_KEY` — opencode 실행용 (`OPENCODE_AUTH_CONTENT` 주입, 파일残留 없음)
- `HIKOUTEI_PR_TOKEN` — fine-grained PAT, 대상 `ManddarinShop/Hikoutei`에
  `contents:write` + `pull-requests:write`만. 검증됨 (`push: true`, 모델 응답 `ok`).
- 스크립트는 env만 읽는다. AWS 이전 시 매핑 5줄 교체로 끝나게 유지.

## 자동화 등급 (옵션 A)

- **auto-PR:** 수정 패턴이 증명된 서명만. 시작은 최다 1종
  (`user_input projection is blocked: delete …`, 440회).
- **auto-issue:** 나머지 서명. 재현 시드 포함 적재.
- **승급 규칙:** 동일 서명 replay 성공 + 수정 1회 검증되면 auto-PR로 승급.
- 재현 실패 → PR 대신 issue로만 적재.

## P1 수락 기준

1. 10분 주기 수집, 중복 PR 0건.
2. 재현 안 되면 PR 없이 issue 적재.
3. 실행마다 run record 1줄 (cost 포함).
4. 신규 failure 없으면 모델 호출 0회.

## 나중 (트리거 조건, 지금 손 안 댐)

- self-hosted runner `[self-hosted,hikoutei-ci]`: P1 안정 후. `concurrency: 1`, fork PR 금지.
- k3s Job: worker 2개↑. (k3s v1.36.4 바이너리 VM에 존재, 클러스터 미확인)
- n8n급 오케스트레이터: 자율 루프 2개↑.
- AWS (OIDC+SSM): 돈·감사·VPC 중 하나가 터질 때.
- 범위 밖: 쿠버 풀셋, 풀자체 CI, 커스텀 퍼저 고도화, 제품화.

## 결정 로그

- 2026-09-29: library 순수 유지 / Website에 워크플로우 / GH Secrets 유지(AWS 조건부)
- 2026-09-29: VM 키 제거 완료 (serve 중단, auth.json 삭제)
- 2026-09-29: 옵션 A 채택 (1종 auto-PR + 나머지 issue + 승급 규칙)
