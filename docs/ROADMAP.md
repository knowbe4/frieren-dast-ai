# Frieren DAST-AI — Roadmap e Auditorias (2026-11-22)

> Documento de estado e plano. Gerado a partir da comparação com o ARTEX
> (`/opt/tools/artex-global`, pentest autônomo multi-agente em Go) e de duas
> auditorias orientadas a defeito: login/sessão e agentes. Sessão nova deve
> começar por aqui. **Processo acordado: sempre entrar em plan mode antes de
> alterar qualquer coisa.**

Direção do projeto: ser uma **evolução do Burp** — proxy + dashboard, com a
opção **agentless** e a presteza do ARTEX. Safeguards de modelos bloqueiam
parte dos ataques (limitação aceita). Prioridade máxima: **copilot e login**.

---

## 1. Estado da rodada 1 (2026-11-15) — ✅ COMMITADA

Commitada no branch `develop` no split planejado: `444f868` feat(copilot) wrap-up,
`029df0d` feat(ai) provider failover, `9ca3223` docs (drift + este roadmap +
.gitignore `.zcode/`). Verificação da época: 2393 unit tests + ruff limpo.

| Mudança | Arquivos |
|---|---|
| Wrap-up do copilot: salvamento de findings antes de kill do watchdog (≤3 passos, fail-open, mesmos gates do loop) | `dast/ai/copilot/wrapup.py` (novo), `dast/ai/copilot/session.py` (`_finalize_forced()` nos 5 kill paths), `tests/unit/test_copilot_wrapup.py` |
| Failover de provedores LLM com health tracking + promoção sticky | `dast/ai/provider_health.py` (novo), `dast/ai/bedrock_client.py` (`_failover_chain`, `_invoke_provider`, `_promote_active_provider`, `_heal_active_model`), `dast/config.py` (`ai_failover_chain`), `dast/proxy/api/status_routes.py` (`/api/ai/availability`), `tests/unit/test_provider_failover.py` |
| Isolamento de testes (registry de health resetado por teste) | `tests/unit/conftest.py`, `tests/unit/test_model_fallback.py` |
| Doc drift | `README.md` (91 regras reais — dizia 47/62; tabela com os 25 agentes — dizia 10), `dast/proxy/runner.py` (docstring: Coordinator), `docs/CHANGELOG.md` (path pré-rename), refs a `CLAUDE.md` removidas de `docs/ARCHITECTURE.md` e `tests/live/README.md`, `Makefile` (bump-version = 3 sites), `.github/workflows/tests.yml` (motivo da exclusão do `test_spa_explorer.py` documentado — passa, é suíte Playwright real de ~2min) |

Nota de ambiente: `.venv` foi recriado com Python 3.12 via `uv` (o antigo era
3.15 sem pytest/wheels).

---

## 2. Auditoria de login/sessão — causa-raiz da dor operacional

O ARTEX **não tem nenhum mecanismo de login** (sem vault, sem cookie jar, sem
reação a auth wall, sem MFA/SSO — o skill `api-recon` proíbe login real). O
frieren está muito à frente; os problemas são internos, não de conceito.

### 2.1 Defeitos críticos (com referência)

**Sucesso de login mentiroso** — a raiz de "login falha mas a tool diz OK":
- `dast/session/flow_replayer.py:146` — replay declara `"success": bool(cookies)`:
  qualquer cookie (analytics/Cloudflare) = autenticado; storage_state podre é
  persistido e o scan segue em 401 → re-login em loop até o breaker
- `dast/browser/login_strategies/spa_api.py:48-58` — `_looks_success` aceita
  qualquer 200 sem substring de erro ("MFA pending" vira sucesso; body com
  "not found" vira falha)
- `dast/browser/login_strategies/base.py:109-122`, `dast/browser/agent_browser.py:1000-1007`
  — sucesso = "URL não contém /login" (login falhando que cai em `/welcome` = OK)
- `dast/browser/login_strategies/llm.py:51` — exige mudança de URL: SPA
  hash-routed nunca "sucede"
- `dast/triage/auth_wall.py:18-24` — substrings largas demais: página que só
  carrega script Cloudflare = "sessão expirada" → re-login toda execução

**Breaker de re-auth sem recuperação:**
- `dast/session/refresh_worker.py:226` — `_gave_up=True` após 3 falhas, nunca
  resetado (sem API/hook; log promete retomada que não existe)
- 403 do próprio scanner (authz probe) dispara re-auth (`refresh_worker.py:58-80`);
  cooldown descarta sinais em vez de coalescer; `_last_reauth` setado antes da
  tentativa (falha consome o cooldown)

**Outros relevantes:**
- OTP two-step com seletores mais estreitos que o single-step
  (`agent_browser.py:952` vs `_OTP_SELECTORS:656`) → `mfa_required` fantasma;
  race TOTP→`accepted=False` por redirect lento (`agent_browser.py:716-722`)
- Crypto silencioso: `dast/profiles/crypto.py:96-104` — decrypt falho (chave
  `DAST_PROFILES_KEY` errada) retorna `""` sem sinal → perfil com senha vazia
- Writes não-atômicos (`dast/profiles/store.py:33`), slug collision
  sobrescreve perfil (`models.py:25-29`), merge de credenciais no PATCH apaga
  entradas (`dast/proxy/api/profiles_routes.py:79-96`)
- `spa_api.py:37-45` — até 25 POSTs de credencial por tentativa (lockout);
  CSRF só `X-CSRF-Token` (Spring/Django/Rails 403 forever);
  `timezone="America/Fortaleza"` hardcoded (line 83)
- Journal winner envenenado por falso sucesso persiste para sempre
  (`dast/browser/login_strategies/registry.py:31-36` + `login_journal.py`);
  cookies de import com `secure=True` hardcoded (`profiles/session_import.py:49-58`)
- `_last_login` armado sem `totp_secret` em 2 dos 4 caminhos (`login_tools.py:86`,
  `spa_api.py:149`) → auto-relogin bate no MFA
- 5 componentes fazem login sem coordenação (copilot RELOGIN dormente —
  `copilot_service.py:811-814` admite em comentário; breaker do copilot = 1
  relogin/run; `role` drifta entre caminhos `profiles_routes.py:207` vs
  `session_tools.py:339`); relogin achata cookies por nome entre domínios
  (`copilot/session.py:1000`)
- Tokens cruzam domínios em TLD multi-label (`session/auth_provider.py:197-198`)

### 2.2 Gaps vs "sucessor do Burp"

SAML/OIDC replay (só o LLM strategy de 8 passos), client certs/mTLS, NTLM/
Kerberos, captcha-pause só no flow_replayer (cascade/refresh/spa_api não têm
canal de pausa), JWT em localStorage invisível (harvest só de headers
`Authorization` do proxy), refresh proativo por `exp` (hoje tudo reativo a 401),
session diffing entre named sessions, CSRF que rotaciona por request.

### 2.3 Top-5 fixes por dor removida

1. **Sinais de sucesso confiáveis + sync do jar** — `verify_authenticated()`
   compartilhado (probe configurável por perfil) usado por replay, spa_api e
   heurísticas de URL; checks estruturais (token no body, Set-Cookie, probe de
   endpoint de sessão); auth_wall menos agressivo → mata "login diz OK mas
   scan 401" e o re-login-toda-execução
2. **Breaker recuperável e probe-aware** — reset em ativação de perfil/re-auth
   manual + endpoint de estado; ignorar 401/403 gerados pelo próprio scanner;
   coalescer durante cooldown
3. **SPA hardening** — parar no primeiro 4xx; CSRF multi-convenção
   (X-XSRF-TOKEN, X-CSRFToken, meta-tag); journal winner expira em falha;
   só journalar sucesso verificado por probe
4. **Crypto/storage ruidoso e durável** — flag `secrets_unreadable` surfaced na
   UI; writes atômicos (`os.replace`); slug único; armar `totp_secret` em todo
   caminho de `_last_login`
5. **Um login coordinator** — lock compartilhado entre copilot/refresh
   worker/login_worker/breaker; roles consistentes; relogin sempre armado

---

## 3. Auditoria dos agentes (25 módulos em `dast/agents/`)

### 3.1 Bug real (validado)

`dast/agents/xxe_agent.py:195` chama `await collaborator.poll()` — método que
**não existe** em `CollaboratorService` (só `was_hit(token)`,
`dast/scanners/collaborator.py:48`). O AttributeError é engolido pelo
`run_safe` → **todo finding de blind XXE é descartado** quando há collaborator.
Fix ~5 linhas: `was_hit(token)` token-scoped por payload, dentro do loop.

### 3.2 Grade resumida

- **Fortes:** sqli (referência do repo: probe→extract→prove→calibrate, oracle
  DuckDB, severity por escopo — `dast/tools/sqli_probe_tools.py`), xss
  (browser-confirm), ssrf (OOB token-scoped), llm_injection (melhor FP
  engineering), csrf (gating), cmdi, blazor (deepest specialist; dispatch
  frágil), business_logic (mass assignment + JWT alg:none/kid/jku)
- **Adequados:** idor (só ±1 vizinho), graphql (IDOR-only), cross_session_idor,
  auth (9 headers, sem path tricks), open_redirect, nosql, mfa (docstring
  promete OTP reuse não implementado), password_reset, prototype_pollution
  (yaml de 38 quase não usado), secrets, lfi (sem baseline/decode)
- **Fracos:** xxe (bug OOB), discovery (gras-bea-galo duplicando ssti/
  open_redirect com menos payloads)

### 3.3 Descoberta de cobertura — o vazamento maior

- **8 agentes órfãos** no dispatch determinístico (`dast/ai/coordinator.py::
  _select_attack_types_for_params`, sem regra no `_PARAM_ATTACK_MAP`):
  open_redirect, xxe, prototype_pollution, graphql_idor, cross_session_idor,
  password_reset, discovery, blazor → em modo no-LLM (ou se o planner não os
  nomeia) **nunca rodam**. `"token": []` = JWT nunca testado em GET
  `?token=<jwt>`; `"boolean": []` exclui flips/PP
- **Canary gate mata classes blind no no-LLM:** `_CANARY_PAYLOADS` é todo
  echo-based → SQLi/CMDi time-based e SSRF OOB nunca despachados; planner
  recebe nota "não selecione injection sem canary signal"
- **SSTI injeta só em query-string** (`ssti_agent.py::_probe`/`_introspection_probe`
  hardcodam `_inject_query`) — body/multipart (a maioria dos targets reais)
  nunca testado
- **SQLi booleano** deliberadamente descartado — falta oracle diferencial
  true/false (usar `ResponseAttrs`/`_structure_hash` de `probe_diff.py`)

### 3.4 Dedup (~250 linhas recuperáveis)

`_send_probe` copiado em xss/discovery/ssrf (+variantes sqli/cmdi/lfi); loop
baseline→detect_block→mutator duplicado 5×; time-oracle duplicado sqli/cmdi;
4 similaridades divergentes; 3 implementações JWT. Extrair
`dast/agents/probe_common.py` (injector + OOB confirm compartilhado) — o bug
do xxe é artefato direto dessa duplicação.

### 3.5 Passive-only que merece agente ativo

Request smuggling (só hints), CSWSH genérico (só Blazor ativo), GraphQL
introspection ativa/batching/depth, JWT como VulnAgent agendável
(`plugins/jwt_tester.py` é ativo mas não-registrável; `jwt.yaml` já tem 45
payloads), HTTP/2, CORS validado ativamente, DOM XSS em fragments,
deserialization (gap total), HPP, cache deception, SSRF redirect-chain/rebinding,
XXE-SSRF (grupo escrito mas desligado). Validação (`red_team.py`) **não** é o
gargalo — dispatch e evidência contextual são.

---

## 4. O que reaproveitar do ARTEX

1. **Playbook agentless "three auth gates"** (`skills/api-recon/SKILL.md`):
   análise estática dos bundles JS (isLogin/getToken/localStorage, interceptors
   axios, código de permissão/menu) + hook/stub runtime das APIs de
   auth/permission com respostas fake → SPA renderiza o shell pós-login SEM
   backend session → gravar o tráfego outbound de API. ✅ Base da rodada 2-D
2. **proxyEnv + CA trust por ecossistema** (`agent/worker.go:194-224`):
   SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO,
   NODE_EXTRA_CA_CERTS, NODE_USE_ENV_PROXY injetados em todo subprocess
3. **Tráfego como banco pesquisável** (SQLite+FTS, `body_contains`) —
   "arqueologia de sessão" entre workers
4. **Headless browser como tool de primeira classe auto-ligado ao MITM**
   (`server/manager.go:syncBrowserMCPProxy`)
5. **Transcript durável por intent** (WorkerSessionID + Resume) — login pela
   metade é retomável
6. Já roubado: wrap-up e llmpool/health (rodada 1); **gravador de LLM**
   (`llmrec/` upstream) → ✅ rodada 3-F frieren (JSONL por tentativa + painel de
   uso); telemetria de contexto do `llmrec` segue como follow-up (item 11)

**Re-baseline vs upstream `BaaRai/ARTEX` 0.7.0 (2026-11-21):** a cópia local
`/opt/tools/artex-global` não existe nesta máquina — a fonte agora é o GitHub
(cópia de referência: `~/Downloads/ARTEX-main`). Novidade relevante no upstream:

7. **Noise governor / target noise profile** (#205/#212/#233): token bucket por
   host com jitter, caps de in-flight, backoff 429/503, dedup GET com cache
   curto, UA configurável, chaveável em runtime — e os limites são injetados nos
   prompts dos agentes (nmap/nuclei/ffuf/sqlmap paced, inclusive via proxy do
   Bash). O antigo "sem rate limit" **não é mais verdade**; rate limit de
   egress é o que falta ao frieren para escanear targets frágeis com segurança
   — ✅ roubado na rodada 3-G frieren (ver linha 3-G do §5)
8. **Coverage ledger** (#207): o worker registra o que examinou / descartou /
   deixou aberto por superfície e classe de risco; gaps alimentam o planner e o
   relatório — ataca direto o buraco de descoberta de cobertura do §3.3
   — ✅ roubado na rodada 3-H frieren (v1 machine-observed; ver linha 3-H do §5)
9. **Rewrite rules + tamper hooks** (`traffic/rewrite`, `traffic/hookvm`):
   match&replace estilo Burp com dry-run, versionamento/rollback e limites duros
   (hooks operator-only, Go-subset sandboxed, off por default)
   — rewrite rules ✅ roubado na rodada 3-I frieren (hooks/VM seguem fora de escopo)
10. **HAR 1.2 import/export + traffic replay** (#266): replay de request
    gravada do tráfego = mini-Repeater; export HAR para entrega de report
    — ✅ replay + export HAR roubados na rodada 3-I frieren (import HAR segue aberto)
11. **Context telemetry** (`llm_context` + `/api/llm/context/summary`): bytes
    por seção do prompt, ratios cache_read/input, p50/p90/p99 por (worker,
    model) — follow-up natural da 3-F
12. **Budgets hierárquicos** (#206): budget por task e por intent (mín. com o
    do pai), reserva força wrap-up — versão sistemática do watchdog do copilot
13. **Closed-question judge** (#208): juiz LLM responde 8 perguntas fixas e o
    CÓDIGO decide (falha → ask, nunca allow) — padrão para validação honesta

Fraco no ARTEX (não imitar) — atualizado em 2026-11-22 vs 0.7.0: ~~sem rate
limit~~ (corrigido pelo noise governor) e ~~guardrails prompt-first
desativáveis~~ (muito mais fortes: untrusted boundary, adversarial gates,
closed-question judge com o código dono da decisão). Seguem fracos: plaintext
creds no Postgres, sem multi-user. **Login de target continua AUSENTE** — o
skill `api-recon` proíbe login real/credenciais (confirmado no SKILL.md da
cópia 2026-11): o sistema de login do frieren (vault, verify_authenticated,
breaker recuperável, three-gates agentless) segue muito à frente; nada a copiar
daqui.

---

## 5. Roadmap por rodadas

| Rodada | Escopo | Arquivos-alvo principais |
|---|---|---|
| **2-A Login núcleo** — ✅ FEITA (2026-11-15): `96a20d8` (gatilho de re-auth morto: `status_code`→`response_status`), `d51700e` (`verify_authenticated` tri-state + probe config por perfil + replayer/spa_api/llm/gate-check), `8ce6c43` (auth_wall por evidência forte), `d353935` (breaker recuperável/probe-aware + sync do jar), `184e5f9` (`/api/session/state` + reset). Adiado p/ 2-B: auto-reset do breaker no caminho do tool `activate_login_profile` do copilot (sem handle do runner — espera o coordinator) | `verify_authenticated()` compartilhado + checks estruturais + auth_wall menos agressivo + breaker recuperável/probe-aware + estado via API | `dast/session/flow_replayer.py`, `dast/session/account_state.py`, `dast/browser/login_strategies/*`, `dast/triage/auth_wall.py`, `dast/session/refresh_worker.py`, `dast/proxy/api/*routes*` |
| **2-B Login robustez** — ✅ FEITA (2026-11-16): `5278836` (spa_api anti-spray + CSRF multi-convenção + timezone local + TOTP arming), `2a30e67` (journal TTL 7d + invalidação por falha + sucesso só probe-verificado no cascade), `02d89ef` (save_profile atômico + slug collision 409 + crypto ruidoso surfaced + recusa de senha vazia), `c686d6c` (login coordinator único: lock por site + reset do breaker via tools + cookie flattening por domínio + roles canônicos). Trabalho na branch `feat/login-agents-hardening` | spa_api sem spray + CSRF multi-convenção + journal que expira; crypto/storage ruidoso + atômico + totp sempre armado; login coordinator único (lock, roles, relogin armado) | `dast/browser/login_strategies/spa_api.py`, `dast/profiles/*`, `dast/session/refresh_worker.py`, `dast/ai/copilot/session.py`, `copilot_service.py`, `session_tools.py`, `profiles_routes.py` |
| **2-C Agents quick wins** — ✅ FEITA (2026-11-16): `3a35f6f` (XXE OOB: 3 falhas empilhadas + prefixo no `was_hit` para sub-paths), `d2f2808` (dispatch dos 8 órfãos + nota do planner), `e8269da` (canaries blind time/OOB), `fac289d` (`probe_common.py`: injector + time-oracle + OOB confirm; SSTI body/multipart), `b886dc8` (oracle booleano SQLi com âncora + reprodução). Adiado: unificação das 4 similaridades divergentes (bandas intencionais) e dedup JWT (vai com o agente JWT da 3-E) | bug XXE; regras determinísticas para os 8 órfãos; canaries blind (time SLEEP vs zero-control + OOB); SSTI body/multipart via injector compartilhado; oracle booleano SQLi | `dast/agents/xxe_agent.py`, `dast/ai/coordinator.py`, `dast/agents/ssti_agent.py`, `dast/agents/sqli_agent.py`, novo `dast/agents/probe_common.py` |
| **2-D Agentless auth-bypass (ARTEX)** — ✅ FEITA (2026-11-16): `a32cf0d` (`dast/browser/auth_gates.py`: detecção estática + storage hook + route stub; wiring em `proxied_browser_context`), `f04468a` (modo `bypass_auth` no SpaExplorer em 2 rodadas + tool `explore` + worker; teste de integração com SPA guardada client-side). Browse (agent_browser) documentado como follow-up | three auth gates no JS + hook/stub das APIs de auth no browser → pós-login sem credenciais, gravando o tráfego de API — novo modo do browse/spa_explorer | `dast/proxy/spa_explorer.py`, `dast/browser/*`, novo módulo de auth-gates |
| **3-E Novos agents** — ✅ FEITA (2026-11-16): `571e11b` (`smuggling_agent`: raw-socket CL.TE/TE.CL por diferencial de resposta + hints → `focus_attack_types` + regra CL+TE + coverage), `6a52276` (`jwt_agent`: alg:none/weak-secret/escalation/kid via probe_common proxy-routed + `_PARAM_ATTACK_MAP["token"]: ["jwt"]` + regra JWT-bearing). Detalhe de design: smuggling exige cliente raw direto (proxy/_send re-enquadram CL/TE); detecção por contagem de respostas vs controle (não timing) | request smuggling ativo (CL.TE/TE.CL com o time-oracle existente, disparado pelos hints de `dast/plugins/request_smuggling_hints.py`) + JWT como VulnAgent registrado | novo `dast/agents/smuggling_agent.py`, `dast/agents/jwt_agent.py`, `dast/agents/__init__.py`, `dast/ai/coordinator.py` |
| **3-F Gravador de LLM** — ✅ FEITA (2026-11-22, branch `feat/llm-recorder`): `839a512` (`dast/ai/llm_recorder.py`: JSONL por tentativa no chokepoint `_invoke_raw`, ring + counters; outcomes ok/cache_hit/safety_block/throttled/provider_error/unavailable/caller_error; excerpts request/response ≤500 e erro ≤200; refusal capturado no raise site; latency sanitizada), `ac1b192` (`purpose=` em todos os ~30 call sites — planner, copilot, triage, agents, login, explore…), `a541e64` (GET `/api/ai/usage` + POST `/api/ai/usage/clear` + painel LLM Usage). Follow-up: telemetria de contexto (4.11) | toda chamada LLM persistida (request/response/tokens/latência/refusal reason) + painel de uso — essencial para debugar safeguards/refusals do copilot | `dast/ai/bedrock_client.py` (chokepoint único), novo `dast/ai/llm_recorder.py`, rota no dashboard |
| **3-G Noise governor (ARTEX 4.7)** — ✅ FEITA (2026-11-23, branch `feat/noise-governor`): `6d0c77a` (`dast/scanners/noise_governor.py`: perfis quiet/balanced/aggressive com os números do ARTEX, token bucket lazy por host, slots in-flight host+global — ordem host→bucket→global, pausa `notBefore` do host inteiro em 429/503 com Retry-After capado, UA configurável, wait fail-open 60s; off = passthrough; clock injetável p/ testes), `5521605` (wiring no chokepoint `_send` com kwarg `pace` — slot paced ANTES da concorrência de scan, delay fixo subsumido, UA no `forward_headers`, race agent com `pace=False` pois o burst É o experimento; `_send_value` do sqli_probe_tools + 2 sites do http_tools paced), `bfecdd4` (chaves `noise_profile`/`noise_user_agent` no scan-config + `GET /api/noise-status` com contadores por host + card Target Noise no dashboard com poll 10s), `2b8107f` (nota low-noise no prompt do planner, code-owned; off = prompt byte-a-byte igual). v1 mínimo: sem GET-dedup e sem retry (seguem os oráculos de tempo); crawler e browsing do operador fora do pacing | rate limit pró-ativo de egress por perfil de operador para targets frágeis (o ARTEX 0.7.0 corrigiu o próprio "sem rate limit") | novo `dast/scanners/noise_governor.py`, `dast/scanners/active_checks.py`, `dast/tools/sqli_probe_tools.py`, `dast/tools/http_tools.py`, `dast/agents/race_condition_agent.py`, `dast/proxy/api/{context,settings_routes,status_routes}.py`, `dast/ai/coordinator.py`, UI scan-config |
| **3-H Coverage ledger (ARTEX 4.8)** — ✅ FEITA (2026-11-23, branch `feat/coverage-ledger`): `70bc647` (`dast/coverage/ledger.py`: entradas por (superfície=chave de scan, risk_area=attack_type) com outcome fechado reported/no_issue_found/ruled_out/not_applicable/needs_follow_up; upsert última-vence + histórico limitado; caps do ARTEX como ERRO nunca truncamento; campos normalizados a uma linha — anti-injection, vão para o prompt; gaps derivados com o invariante central primeiro: **classe sem entrada = unexamined, nunca clean**; completude com caveat nunca vazio — ausência de finding ≠ alvo limpo), `8947cbf` (`Coordinator._record_coverage` machine-observed por attack_type despachado + seção `[Coverage ledger]` gated no `_plan` com top-3 gaps fenced untrusted — prompt byte-a-byte igual sem entradas), `fbfc5d7` (`ProxyEntry.coverage_ledger` persistido pelo scan_worker no finally + `GET /api/coverage` + card Coverage no AI panel). v1 machine-observed: a tool `record_coverage` de LLM para o copilot fica de follow-up | registro durável de EXAMINADO/DESCARTADO/ABERTO por endpoint×classe (hoje "rodou e não achou" é efêmero no log rotativo) → planner testa como humano (não repete classe limpa, segue o gap aberto) e dashboard mostra o que falta testar | novo `dast/coverage/ledger.py`, `dast/ai/coordinator.py`, `dast/proxy/session_store.py`, `dast/proxy/workers/scan_worker.py`, `dast/proxy/api/status_routes.py`, UI AI panel |
| **3-I Rewrite rules + replay + HAR (Burp/ARTEX 4.9-4.10)** — ✅ FEITA (2026-11-23, branch `feat/rewrite-replay-har`): rewrite rules (evolução do match&replace de `proxy_settings.py`: matchers methods/host exato-ou-`*.sufixo`/url_regex path+query/status response-only com AND, ids estáveis uuid — fim dos toggles por índice, contadores hits/last_applied_at persistidos, validação como ERRO (regex/enum/caps 100/50 → 400) em vez do fallback silencioso, skips de integridade p/ body (1 MiB/encoded/HEAD-1xx-204-304), migration de rules legadas; `apply_to_response` agora recebe url real e o gate response exclui crawler; trace na entry: `ProxyEntry.rewritten_by` substitui o diff frágil de headers), replay (`POST /api/replay/{id}`: re-envia a request CRUA da entry VIA O PROXY → gravada no history com source `replay`, match&replace aplicado e atribuído; strip de hop-by-hop/x-dast-*; fresh_cookie opcional; caps 8 MiB/60s/resposta 2 MiB; exclusão de pending-import e session-intelligence; UI: item de context menu + botão ↻ Replay no detail pane + `_SRC_TAG['replay']`), HAR 1.2 export (`dast/proxy/har_export.py` puro + `GET /api/history/export/har` sobre in-scope entries: ordem estável (ts,id), placeholders explícitos (timings -1/time 0/cookies[]), pares de headers com multi-Set-Cookie, texto vs base64, redaction de userinfo, caps 1000/20 MiB/31 MiB com truncamento nunca-silencioso `X-DAST-HAR-*`; botão ⇩ HAR na filter bar) | Burp-core: match&replace com escopo por matcher + mini-Repeater gravado + entrega HAR | `dast/proxy/proxy_settings.py`, `dast/proxy/proxy_server.py`, `dast/proxy/session_store.py`, `dast/proxy/api/{settings_routes,proxy_routes}.py`, novo `dast/proxy/har_export.py`, UI `96-mode-intercept-mr.js`/`61-detail-pane.js`/`99-bootstrap-ctxmenu.js`/`10-state-core.js` |

**Ordem recomendada:** ~~commitar rodada 1~~ ✅ → ~~2-A~~ ✅ → ~~2-C~~ ✅ →
~~2-B~~ ✅ → ~~2-D~~ ✅ → ~~3-E~~ ✅ → ~~3-F~~ ✅ → ~~3-G~~ ✅ → ~~3-H~~ ✅ →
~~3-I~~ ✅ — **fase 3 completa** → ~~4-A~~ ✅ → ~~4-B~~ ✅ → ~~4-C~~ ✅ →
~~4-D~~ ✅ → ~~4-E~~ ✅ → ~~4-F~~ ✅ → ~~4-G~~ ✅ — **fase 4 completa** →
~~5-A~~ ✅ → ~~5-B~~ ✅ → ~~5-C~~ ✅ — **fase 5 completa**
(sub-agentes de ataque estilo XBOW + loops de missão — branch `feat/offensive-copilot`).
Follow-ups fase 5-D/6-A na seção *Follow-ups* abaixo.

| **4-A Expansão de agentes (ARTEX api-security)** — ✅ FEITA (2026-11-23, branch `feat/agents-expansion`): `ff6b73f` (quick wins: nosql usava grupo yaml **inexistente** `where_injection` → `mongodb_js_injection`; prototype_pollution adota o próprio yaml — 5 hardcoded vs 40+ — + NOVO vetor header; **xxe-ssrf wired** — o grupo `ssrf_internal` pronto desde sempre finalmente carrega, deteção por assinaturas de metadata cloud (CWE-918); discovery_agent de-duplicado — sub-sweeps SSTI/open-redirect removidos (duplicavam os especialistas com payloads piores), mantém CRLF+TRACE; `llm_injection` era o único agente sem regra de dispatch — regra contextual por marcadores), `7562aa8` (**cors_agent** — probe de origin arbitrário promovido do passive scanner: ACAO refletido + credentials = critical CWE-942; same-site nunca é finding; 1 probe/endpoint), `cd22515` (**hpp_agent** — duplicação de param com canary escalado, confirmado só por reflexão (CWE-436); **rate_limit_trust_agent** — XFF/X-Real-IP refletido = trust-boundary CWE-345 + variantes de path com diferencial de status CWE-436 — o mecanismo, nunca bypass demonstrado sob carga), `bf5d212` (**graphql_abuse_agent** — escada de introspection full→reduced→minimal, field-suggestion leak, alias overload 60×, batching aceito, GraphQL-via-GET (CSRF surface), depth probing limitado — metade que o graphql_agent exclui explicitamente; payloads em `graphql_abuse.yaml`), `675998b` (**cache_deception_agent** — port do probe de 3 passos da tool de copilot (CWE-525): path-mapping autenticado → sinal cacheável → re-leitura anônima com markers sobrevivendo; redaction de secrets; caps de variantes). Registry: 26 → **31 agentes** | planner testa como pentester: classes novas cobertas + bugs de cobertura silenciosos eliminados | novos `dast/agents/{cors,hpp,rate_limit_trust,graphql_abuse,cache_deception}_agent.py`, `dast/payloads/graphql_abuse.yaml`, fixes em `nosql/prototype_pollution/xxe/discovery_agent.py`, `dast/ai/coordinator.py` |
| **4-B Agentes pesados + melhorias (ARTEX)** — ✅ FEITA (2026-11-23, branch `feat/agents-expansion`): cswsh_agent (handshake WS CRU com Origin atacante — transporte do smuggling; 101+Sec-WebSocket-Accept válido = CWE-346; high só com cookie de sessão, senão info/unconfirmed; canal de descoberta: websocket_observer marca 101 com `focus_attack_types=['cswsh']`), deserialization_agent (reflection probe com header Java malformado → sink unconfirmed CWE-502; URLDNS OOB CONFIRMADO com fixture do operador `dast/payloads/urldns.bin` — splice de TC_STRING com patch de length; nunca re-envia body capturado, nunca envia gadget executável), bfla_agent (admin surface com sessão alheia via `_build_session_headers` + downgrade /v2→/v1 — **GET/HEAD only**, nunca métodos com estado; CWE-862), melhorias (jwt RS256→HS256 key-confusion via jwks same-host; mfa OTP reuse implementado — o OTP do body capturado aceito em DUAS submissões consecutivas = CWE-294; xss fragment second-chance no browser confirm; ssrf.yaml +import/avatar/feed/attachment/document) | cobertura de superfícies que nenhum agente cobria + técnicas ARTEX | novos `dast/agents/{cswsh,deserialization,bfla}_agent.py`, melhorias em `jwt/mfa/xss_agent.py`, `dast/payloads/ssrf.yaml`, `dast/plugins/websocket_observer.py`, `dast/ai/coordinator.py` |
| **4-C TOTP plumbing + OAuth flows + HAR import** — ✅ FEITA (2026-11-23, branch `feat/agents-expansion`): mfa_agent resolve o seed TOTP do perfil da ALVO no run-time (`profiles.store.resolve_for_host` + `may_use_totp` hard gate — inacessível via CheckTarget até então) e o reuse check usa um CÓDIGO FRESCO submetido DUAS vezes (confirmação real, não o fallback do valor capturado); oauth_agent (`oauth`: redirect_uri takeover CONFIRMADO — 3xx com Location atacante, CWE-601; state ausente/PKCE ausente/implicit flow = mechanism findings; GET-only, nada é resgatado), HAR import (`dast/proxy/har_import.py` + `POST /api/history/import/har` + botão ⇧ HAR: 1.2-only, ≤2000 entradas/32 MiB, erros por-entrada ≤50 nunca fatais, cookies[] sintetizam headers, postData.params reconstrói urlencoded, base64 decodificado, userinfo redacted, chaves determinísticas har-<sha256>; importados = source imported, SEM match&replace) | flows OAuth cobertos + round-trip HAR completo + reuse de OTP contra código fresco | novo `dast/agents/oauth_agent.py`, `dast/proxy/har_import.py`, melhorias em `dast/agents/mfa_agent.py`, `dast/proxy/api/proxy_routes.py`, UI filter bar |

| **4-D Agentes pesados + HTTP/2** — ✅ FEITA (2026-11-24, branch `feat/agents-expansion`): http2_agent (ALPN `h2` detection informativa + probe de desync CL/DATA com framing h2 MANUAL — a lib cliente `h2` recusa o DATA RFC-violante que o probe precisa: preface + SETTINGS + HEADERS(CL:0) + DATA com GET smuggled via `hpack`; backend respondendo o smuggled em HTTP/1.x plaintext = critical confirmado CWE-444; sem Rapid-Reset floods — DoS fora de escopo por política), dependência `h2` adicionada; recuperação 4-D/4-E do incidente volume-reset (cswsh/deserialization/bfla restaurados dos objetos git) | superfície HTTP/2 coberta + conteúdo perdido restaurado | novo `dast/agents/http2_agent.py`, `pyproject` (`h2`), `tests/unit/test_http2_agent.py` |
| **4-E OAuth token-exchange real** — ✅ FEITA (2026-11-24, branch `feat/agents-expansion`): oauth_agent code single-use (authorize → captura o code same-host → resgata DUAS vezes no token endpoint; ambos 200 com access_token = CWE-294 confirmado; o code é da própria sessão — emissão, não mudança de estado; token endpoint via `/.well-known/openid-configuration` + fallbacks same-origin) | verificação real de reuse de código (antes só mecanismos) | `dast/agents/oauth_agent.py` |
| **4-F Telemetria de contexto + HAR paginado** — ✅ FEITA (2026-11-24, branch `feat/agents-expansion`): llm_recorder grava `req_bytes` (system+user) e cache tokens (`cache_read`/`cache_creation`/`cached_tokens`, shapes Anthropic e OpenAI) por entrada; `usage_snapshot()` com médias, `context_summary()` com p50/p90 por purpose; `GET /api/ai/context`; HAR import streaming (`import_har_incremental` raw_decode sequencial, sem json.loads do doc inteiro) com `?offset` para arquivos ≥2k entradas, body 256 MiB, idempotência har_key por batch, cap 10k nunca-silencioso, loop JS de páginas | orçamento de prompt orientado por dado + import de HAR grande com memória limitada | `dast/ai/llm_recorder.py`, `dast/ai/bedrock_client.py`, `dast/proxy/har_import.py`, `dast/proxy/api/proxy_routes.py`, UI `10-state-core.js` |
| **4-G Vault de client-credentials + wiring do exchange** — ✅ FEITA (2026-11-24, branch `feat/agents-expansion`): `dast/profiles/oauth_clients.py` — client_id/secret por host IdP em `~/.dast-ai/oauth_clients/` (dir 0700, arquivos 0600), secret Fernet-at-rest com o material do login-profile (`DAST_PROFILES_KEY`), plaintext só sai pelo request de exchange, APIs de leitura mascaradas; rotas `GET/PUT/DELETE /api/oauth-clients` (mascaradas) + checagem de credenciais; o code single-use da 4-E passa a autenticar o exchange com o vault — válido para clients CONFIDENCIAIS (antes só flows públicos) | confidential-client code reuse verificável + secret em cofre local criptografado | novo `dast/profiles/oauth_clients.py`, `dast/proxy/api/oauth_client_routes.py`, `dast/agents/oauth_agent.py` |
| **5-A Inteligência do copilot (fase 5)** — ✅ FEITA (2026-11-24, branch `feat/agents-expansion`): 5-A-1 scratchpad entre turnos (uma linha compacta por step `METHOD /path -> status/err`, ring 120, renderizado como *progress ledger* no prompt de passo — últimas 25/4k chars fenced; finalização forçada também salva a navegação: cauda não persistida vira nota em `app_knowledge` do host focus, idempotente por índice), 5-A-2 write-back para a inteligência de host (`record_finding` espelha vereditos confirmados em `session_intelligence.record_scan_complete` found=True+confirmed_param — o brief do coordinator sabe o que o copilot PROVOU; `build_context_brief(paths=)` passa o endpoint em jogo ao `to_planner_hint` — erros estruturais por-path finally surfacam), 5-A-3 router/leads/coverage no passo interativo (`dast/ai/copilot/prompt_blocks.py` builders puros (store, hosts): leads de app-context, evidence-router, coverage ledger com invariante unexamined≠clean — driver autônomo delega aos mesmos builders), 5-A-4 diff_responses tool (2 entry_ids → delta determinístico: status, headers-chave, lengths, linhas added/removed com contagem real + amostras capadas, veredito 'structurally identical') + `_summarize_result` com headers-chave e contagem real de set_cookies à frente do body e janela 2000 para bodies ≤4k | copilot com memória entre turnos, veredito sobre evidência completa e os mesmos blocos de roteamento do driver autônomo — menos repetição de navegação, menos veredito sobre preview truncado | `dast/ai/copilot/session.py`, `dast/ai/copilot/{prompt_blocks,context_brief}.py`, `dast/tools/{record_finding_tools,http_tools}.py`, `tests/unit/{test_copilot_session,test_prompt_blocks,test_diff_responses_tool}.py` |
| **5-B Verificação ofensiva (XBOW/ARTEX)** — ✅ FEITA (2026-11-25, branch `feat/offensive-copilot`): 5-B-1 blind XSS com confirmação OOB (`blind_oob` em `xss.yaml` com `{{COLLAB_*}}/{{TOKEN}}`; segunda via no xss_agent quando não confirma in-band — callback `was_hit(token)` = CWE-79 high confirmed bypass_validation; render pages visitadas no browser quando stored; fallback interactsh documentado como follow-up), `fffe18c`; 5-B-2 SSRF redirect-chain bypass + impacto (listener do collaborator responde `/redirect/<token>?to=` com 302 restrito a espaço interno/privado — externo → 403; template `/follow/<token>` prova deterministicamente que o fetch SEGUIU; metadata hit vai para `extracted_data` capado+redactado), `3639303`; 5-B-3 **authz_ladder** (agents 37→**38**: escada low→admin sobre named sessions de roles distintos, GET/HEAD only, oracle differential privilegiado-200 vs low-priv-200 vs unauth-403 = CWE-862 confirmed sem LLM; dispatch p/ hosts com ≥2 sessões de roles distintos), `2f7650a`; 5-B-4 chain inventor (`dast/ai/chain_inventor.py`: ≥2 findings → LLM propõe ≤2 chains schema-forced com extratores `{{var}}`; engine real valida com ASSERÇÃO DE IMPACTO OBRIGATÓRIA no passo sensível final; confirmada = finding `chain`, refutada = `ruled_out` na ledger; tool `invent_chain` (tools 66→67); driver roda 1 tentativa no fim aceito do run com ≥2 findings), `faceae4`; 5-B-5 PoC/POE/reteste/relatório (`dast/report/poc.py`: curl reproduzível do raw_request + `derive_poe` 0–4 determinístico em toda row de `/api/findings`; `POST /api/findings/{e}/{i}/retest` → `retest_state` Still-reproducible/Fixed/Cannot-confirm com evidência original preservada; `dast/report/pentest_report.py` + `GET /api/report/pentest.md` + botão/Retest/badges no dashboard), `4cabf41`; pre-flight: `diff_responses` over MCP via fallback dashboard, `cab3be2`; jwt import + dispatch http2 (com memo por host), `23b7aef` | fecham os 5 buracos ofensivos do plano XBOW/ARTEX: callback blind, bypass por redirect com impacto, escada de authz, chains compostos e PoC com nível de prova + reteste | `dast/payloads/{xss,ssrf}.yaml`, `dast/scanners/collaborator.py`, `dast/agents/{xss,ssrf,authz_ladder}_agent.py`, `dast/ai/{chain_inventor,attack_subagent}.py` (5-C), `dast/tools/{chain_tools,attack_tools,findings_tools,http_tools}.py`, `dast/report/{poc,pentest_report}.py`, `dast/proxy/api/{copilot_service,findings_routes}.py`, `tests/unit/*` |
| **5-C Sub-agents de ataque + loops de missão** — ✅ FEITA (2026-11-25, branch `feat/offensive-copilot`): 5-C-1 **AttackSubagent** (`dast/ai/attack_subagent.py`: para UM candidato needs_review/não-confirmado, sub-agente LLM de propósito único com TOOLSET RESTRITO (primitivas de escalada + probe determinístico da classe + record_finding/record_coverage), budget duro (≤12 tool calls, 240s, watchdog de no-progress por assinatura, breaker de falhas), fechamento DETERMINÍSTICO (sucesso de record_finding = confirmed; record_coverage ruled_out = refutado — o LLM nunca auto-confirma); `is_escalatable` recusa classes não replay-avaliáveis; tool `attack_finding` (tools 67→68)), `3c4d7c0`; 5-C-2 **todolist de missão com pré-requisitos** (`dast/ai/copilot/todolist.py`: map → auth → scan → escalate → chains → wrapup com `mark` honesto, `next_actionable`, revision p/ stuck; semeada por run autônomo e renderizada em todos os prompts de checkpoint via `{todolist}`; driver marca degraus deterministicamente) + **fan-out no driver** (`_escalate_candidates` após os scan outcomes: ≤2 por turno, cap 6/run, marcador `_escalated`; vereditos broadcastam `escalation_result`), `12657fb`; 5-C-3 **menu de tools consciente de fase** (`session.py`: fase inferida SEM LLM do scratchpad ordenado — a ÚLTIMA chamada mapeada define a fase, então uma chamada deliberada de escalada/report gira a fase; tools da fase + núcleo sempre-prioritário em detalhe, resto em linha compacta; teste de drift exige toda tool num bucket), `1c48a28` | o copilot ganha o padrão XBOW de ponta a ponta: candidato → sub-agente com oráculo e budget → veredito gravado, dentro de um plano ordenado com pré-requisitos e menu enxuto por fase | `dast/ai/{attack_subagent.py,copilot/todolist.py,copilot/session.py}`, `dast/tools/{attack_tools,__init__}.py`, `dast/proxy/api/copilot_service.py`, `tests/unit/{test_attack_subagent,test_mission_todolist,test_phase_menu}.py` |

**Follow-ups de agentes (4-B candidatas, técnicas do ARTEX já mapeadas):**
~~cswsh_agent~~ ✅ 4-B, ~~deserialization_agent~~ ✅ 4-B (URLDNS com fixture
do operador), ~~bfla_agent~~ ✅ 4-B, ~~jwt RS256→HS256~~ ✅ 4-B,
~~mfa OTP reuse~~ ✅ 4-B, ~~xss fragment~~ ✅ 4-B, ~~ssrf sink-hints~~ ✅ 4-B.
~~HTTP/2~~ ✅ 4-D (`h2` adotado), ~~OAuth token-exchange com code real~~ ✅
4-E/4-G. Restantes: TOTP-window timing analysis; headers HMAC no trace de
match&replace (rewritten_by já persiste o quê, falta o payload assinado);
sumarização por LLM do transcript de turnos antigos (o scratchpad cobre o
sinal, o custo/tokens fica para quando a telemetria da 4-F mostrar demanda).

**Descoberta da 2-A que muda a 2-B:** o gate-check do copilot
(`copilot_service._gate_check_account_state`) agora delega para
`account_state.session_endpoint_state`, e o breaker tem API de estado/reset —
o "login coordinator único" da 2-B deve nascer em cima dessas peças
(`reset_refresh_breaker` em `session_state_routes.py` já é um ponto de
integração natural).

---

*Última atualização: 2026-11-25 (fase 5 completa — 5-B verificação ofensiva e
5-C sub-agents de ataque + loops de missão entregues na `feat/offensive-copilot`;
fases 4 e 5-A na `feat/agents-expansion`). Manter este documento vivo: marcar
itens como feitos com referência ao commit.*

## Follow-ups 5-D / 6-A (candidatos, sem compromisso de ordem)

- **Fallback interactsh para o blind XSS** (5-B-1 deixou documentado): o
  `OobCorrelator` é um construto de plugin long-lived (`header_oob_scanner`
  cobre o canal de headers); um loop de poll por agent precisa de outro desenho
  (plugin XSS-OOB observando injeções do agent).
- **WS message tampering/replay** — client de framing WS próprio (o
  observer/cswsh cobrem handshake); **DNS rebinding** (infra DNS própria);
  **SOCKS5/UDP capture** (infra de proxy); **ingestão nmap/nuclei** (import
  para o mesmo pipeline de candidatos → sub-agents); **source maps**;
  **TOTP-window timing analysis**; **headers HMAC no trace de match&replace**;
  **sumarização por LLM do transcript de turnos antigos** (4-F telemetria).
- **Scheduler de runs autônomas** (cron/daemon para runs recorrentes — hoje a
  autonomia é bounded por run) e **resume entre restarts** (estado de sessão
  do copilot é in-memory; todolist/coverage/app_knowledge já persistem).
- **Login gaps vs "sucessor do Burp"** (§2.2): SAML/OIDC replay, client
  certs/mTLS, NTLM/Kerberos, JWT em localStorage, refresh proativo por `exp`,
  session diffing entre named sessions, CSRF que rotaciona por request.
