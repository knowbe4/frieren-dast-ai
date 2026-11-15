# Frieren DAST-AI — Roadmap e Auditorias (2026-11-15)

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
   backend session → gravar o tráfego outbound de API. Base da rodada 2-D
2. **proxyEnv + CA trust por ecossistema** (`agent/worker.go:194-224`):
   SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO,
   NODE_EXTRA_CA_CERTS, NODE_USE_ENV_PROXY injetados em todo subprocess
3. **Tráfego como banco pesquisável** (SQLite+FTS, `body_contains`) —
   "arqueologia de sessão" entre workers
4. **Headless browser como tool de primeira classe auto-ligada ao MITM**
   (`server/manager.go:syncBrowserMCPProxy`)
5. **Transcript durável por intent** (WorkerSessionID + Resume) — login pela
   metade é retomável
6. Já roubado na rodada 1: wrap-up (`agent/wrapup.go`) e llmpool (health)

Fraco no ARTEX (não imitar): guardrails prompt-first desativáveis, sem rate
limit, plaintext creds no Postgres, sem multi-user.

---

## 5. Roadmap por rodadas

| Rodada | Escopo | Arquivos-alvo principais |
|---|---|---|
| **2-A Login núcleo** — ✅ FEITA (2026-11-15): `96a20d8` (gatilho de re-auth morto: `status_code`→`response_status`), `d51700e` (`verify_authenticated` tri-state + probe config por perfil + replayer/spa_api/llm/gate-check), `8ce6c43` (auth_wall por evidência forte), `d353935` (breaker recuperável/probe-aware + sync do jar), `184e5f9` (`/api/session/state` + reset). Adiado p/ 2-B: auto-reset do breaker no caminho do tool `activate_login_profile` do copilot (sem handle do runner — espera o coordinator) | `verify_authenticated()` compartilhado + checks estruturais + auth_wall menos agressivo + breaker recuperável/probe-aware + estado via API | `dast/session/flow_replayer.py`, `dast/session/account_state.py`, `dast/browser/login_strategies/*`, `dast/triage/auth_wall.py`, `dast/session/refresh_worker.py`, `dast/proxy/api/*routes*` |
| **2-B Login robustez** | spa_api sem spray + CSRF multi-convenção + journal que expira; crypto/storage ruidoso + atômico + totp sempre armado; login coordinator único (lock, roles, relogin armado) | `dast/browser/login_strategies/spa_api.py`, `dast/profiles/*`, `dast/session/refresh_worker.py`, `dast/ai/copilot/session.py`, `copilot_service.py`, `session_tools.py`, `profiles_routes.py` |
| **2-C Agents quick wins** | bug XXE; regras determinísticas para os 8 órfãos; canaries blind (time SLEEP vs zero-control + OOB); SSTI body/multipart via injector compartilhado; oracle booleano SQLi | `dast/agents/xxe_agent.py`, `dast/ai/coordinator.py`, `dast/agents/ssti_agent.py`, `dast/agents/sqli_agent.py`, novo `dast/agents/probe_common.py` |
| **2-D Agentless auth-bypass (ARTEX)** | three auth gates no JS + hook/stub das APIs de auth no browser → pós-login sem credenciais, gravando o tráfego de API — novo modo do browse/spa_explorer | `dast/proxy/spa_explorer.py`, `dast/browser/*`, novo módulo de auth-gates |
| **3-E Novos agents** | request smuggling ativo (CL.TE/TE.CL com o time-oracle existente, disparado pelos hints de `dast/plugins/request_smuggling_hints.py`) + JWT como VulnAgent registrado | novo `dast/agents/smuggling_agent.py`, `dast/agents/jwt_agent.py`, `dast/agents/__init__.py`, `dast/ai/coordinator.py` |
| **3-F Gravador de LLM** | toda chamada LLM persistida (request/response/tokens/latência/refusal reason) + painel de uso — essencial para debugar safeguards/refusals do copilot | `dast/ai/bedrock_client.py` (chokepoint único), novo `dast/ai/llm_recorder.py`, rota no dashboard |

**Ordem recomendada:** ~~commitar rodada 1~~ ✅ → ~~2-A~~ ✅ → 2-C (rápidos e
desacoplados) → 2-B → 2-D → 3-E → 3-F.

**Descoberta da 2-A que muda a 2-B:** o gate-check do copilot
(`copilot_service._gate_check_account_state`) agora delega para
`account_state.session_endpoint_state`, e o breaker tem API de estado/reset —
o "login coordinator único" da 2-B deve nascer em cima dessas peças
(`reset_refresh_breaker` em `session_state_routes.py` já é um ponto de
integração natural).

---

*Última atualização: 2026-11-15 (rodada 2-A entregue). Manter este documento
vivo: marcar itens como feitos com referência ao commit.*
