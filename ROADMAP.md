# ROADMAP.md — Plano de Execução com Codex

> Este arquivo é o plano de trabalho **ordenado por sessão de Claude**.
> Cada sessão deve começar lendo CLAUDE.md, depois este arquivo,
> executar a fase atual, atualizar checkboxes e fazer commit.

---

## COMO TRABALHAR COM O CLAUDE NESTE PROJETO

**Prompt de abertura de sessão (copie e adapte):**
```text
Leia o CLAUDE.md e o ROADMAP.md do projeto Syshunt.
Estou na [FASE ATUAL].
Execute as tasks pendentes nessa fase.
Após cada grupo: rode os testes, faça commit com mensagem descritiva.
Atualize os checkboxes no ROADMAP.md ao concluir cada item.
Se precisar de decisão arquitetural, registre no CLAUDE.md antes de implementar.
```

**Regras de sessão:**
- Máximo de 1 fase por sessão (evita contexto longo demais)
- Sempre commitar ao final da sessão, mesmo que parcial
- Nunca deixar testes quebrando ao commitar
- Atualizar CLAUDE.md se qualquer decisão nova for tomada

---

## FASE 1 — FUNDAÇÃO DO PROJETO ✅
*Objetivo: projeto rodando localmente com pipeline básico funcional*

### Setup Inicial
- [x] Criar estrutura de diretórios conforme CLAUDE.md
- [x] `pyproject.toml` com dependências (sqlalchemy, alembic, celery, redis, anthropic, streamlit, structlog, pytest, black, ruff)
- [x] `Dockerfile.worker` (Python 3.12 + tools de segurança instalados)
- [x] `Dockerfile.dashboard` (Python 3.12 + streamlit)
- [x] `.env.example` com todas as variáveis necessárias
- [x] `Makefile` com comandos: `up`, `down`, `migrate`, `test`, `worker`, `dashboard`

### Banco de Dados
- [x] Configuração SQLAlchemy + Alembic
- [x] Model: `Target` com todos os campos do CLAUDE.md
- [x] Model: `Finding` com todos os campos do CLAUDE.md
- [x] Model: `ReconResult` com todos os campos do CLAUDE.md
- [x] Model: `BountyProgram` com todos os campos do CLAUDE.md
- [x] Migration inicial gerada e testada
- [x] Seed script para dados de desenvolvimento

### Core — Wrappers Iniciais
- [x] `tools/base.py` — classe base `ToolWrapper` + `ToolResult` dataclass
- [x] `tools/subfinder_wrapper.py` — wrapper com tests
- [x] `tools/httpx_wrapper.py` — wrapper com tests
- [x] `tools/nuclei_wrapper.py` — wrapper com tests
- [x] Testes unitários mocando subprocess (sem precisar das tools instaladas)

### Core — Pipeline Básico
- [x] `core/pipeline/tasks.py` — configuração Celery
- [x] Task: `run_subdomain_enum(target_id)`
- [x] Task: `run_http_probe(target_id)`
- [x] Task: `run_nuclei_scan(target_id)`
- [x] Task: `run_full_pipeline(target_id)` — chain das 3 anteriores
- [x] Testes de integração do pipeline (com docker de teste)

### Dashboard — Fase 1 (Mínimo Viável)
- [x] `dashboard/app.py` — entry point Streamlit com navegação
- [x] Página Targets: listar targets + adicionar target manual
- [x] Página Findings: tabela básica de findings com filtros simples
- [x] Indicador de status de pipeline (polling Redis)

---

## FASE 1.5 — CORREÇÕES ESTRUTURAIS ✅
*Objetivo: corrigir debt técnico identificado na revisão da Fase 1 antes que a Fase 2 o amplifique*

### Pipeline e Estado
- [x] Alinhar `Target.status` com os estados da spec: estados internos de etapa (`subdomain_enum_completed` etc) viram log/evento, não atualizam o campo `status` diretamente; o campo só assume os valores da spec
- [x] Refatorar `run_full_pipeline`: usar `link=` no `apply_async()` de cada task para encadear a próxima, em vez de `chain().apply_async()` dentro de uma task
- [x] `run_http_probe` e `run_nuclei_scan`: loop tolerante a falhas — coletar erros por item, logar, continuar; só marcar target como falho se zero resultados válidos ao final

### Dados
- [x] Separar `raw_stdout` e `raw_stderr` em `ToolResult`; `parse_output` opera só sobre `raw_stdout`
- [x] Deduplicação de `ReconResult` antes de inserir: upsert ou check por `(target_id, tool, result_type)` + hash do valor
- [x] Implementar `superseded_by` no fluxo de re-scan: marcar resultados anteriores antes de inserir novos

### Organização
- [x] Extrair `create_target`, `list_targets`, `list_findings`, `get_pipeline_status` de `dashboard/app.py` para `core/db/queries.py`
- [x] `dashboard/app.py` passa a importar de `core/db/queries.py`
- [x] Atualizar testes afetados pela refatoração

---

## FASE 2 — RECON COMPLETO ✅
*Objetivo: pipeline de recon completo e recursivo*

### Novos Wrappers
- [x] `tools/amass_wrapper.py` — passive mode, com tests
- [x] `tools/nmap_wrapper.py` — top-1000 ports, com tests
- [x] `tools/katana_wrapper.py` — crawler, com tests
- [x] `tools/gau_wrapper.py` — historical URLs, com tests
- [x] `tools/gowitness_wrapper.py` — screenshots, com tests

### Recon Recursivo
- [x] `core/recon/recursive.py` — orquestrador com controle de profundidade
- [x] Tracking de domínios processados (evitar loops)
- [x] Deduplicação de subdomínios cross-tool
- [x] Testes do orquestrador recursivo

### Pipeline Expandido
- [x] Adicionar etapas 3-6 no pipeline (port scan, crawl, screenshot, vuln scan)
- [x] Configurar concorrência por etapa (não-fatal por item)
- [x] State machine de target funcionando corretamente
- [x] Re-scan com preservação de histórico (skip_recon=True)

### Dashboard — Fase 2
- [x] Import CSV de targets
- [x] Screenshots visíveis no detalhe do alvo
- [x] Página Findings com todos os filtros avançados do SPEC.md
- [x] Painel lateral de detalhe do finding

---

## FASE 2.5 — CORREÇÕES E FUNDAÇÃO PARA IA ✅
*Objetivo: corrigir bugs críticos da Fase 2 e preparar a infra de classificação antes de implementar IA*

### Correções de Pipeline
- [x] Corrigir `run_full_pipeline`: substituir `link=` dentro de `.set()` por `chain([...]).apply_async()` (Canvas correto)
- [x] Corrigir `run_port_scan`: usar `urllib.parse.urlparse` em vez de `_extract_host` manual para extrair hostname
- [x] Refatorar `run_recursive_subdomain_enum` para disparar tasks Celery assíncronas em vez de recursão direta bloqueante
- [x] Atualizar `test_pipeline_docker.py` para refletir Fases 1.5/2 (status `recon_done`, 7 ReconResults)

### Correções de Dados e Segurança
- [x] Validação de domínio por regex em `normalize_domain` e `bulk_create_targets`: rejeitar inputs com caracteres inválidos antes de qualquer operação
- [x] Validação de scope em cada task do pipeline: subdomínios fora de `scope_includes` ou em `scope_excludes` não são processados nas etapas seguintes
- [x] Hash completo sha256 em `_data_hash` (remover `[:16]`)
- [x] `run_web_crawl`: adicionar campo `source_tool` nos data_items (`{"url": u, "source_tool": "katana"}`)
- [x] `run_screenshot`: capturar e armazenar `filename` gerado pelo gowitness no ReconResult data

### Correções de Dashboard
- [x] Corrigir `_parse_domains_from_csv`: fallback para lista sem header não deve excluir linhas com vírgula; deve parsear apenas a primeira coluna
- [x] Adicionar validação de formato de domínio no formulário "Add Target" antes de submeter

### Novos Wrappers
- [x] `tools/dnsx_wrapper.py` — resolução e validação de subdomínios antes do httpx; filtra wildcard e NXDOMAIN
- [x] `tools/ffuf_wrapper.py` — fuzzing de diretórios e parâmetros em hosts ativos; integrar após web crawl
- [x] Integrar `dnsx` entre subdomain enum e http probe no pipeline

### Fundação do Classificador
- [x] `core/analysis/provider.py` — abstração `AIProvider` com métodos `complete(prompt) → str` e `is_available() → bool`
- [x] Implementar `AnthropicProvider`, `OpenAICompatibleProvider`, `OllamaProvider`
- [x] `core/analysis/classifier_base.py` — scoring heurístico puro (severity + template category + evidence + URL context)
- [x] Penalização de score e confidence quando classificador heurístico: score × 0.8, confidence = "heuristic"
- [x] Migration: adicionar campos `classifier_used`, `confidence_note`, `ai_reasoning`, `ai_report_draft` à tabela `findings`
- [x] Testes do classificador heurístico com findings sintéticos cobrindo todos os critérios de score

---

## FASE 3 — ANÁLISE POR IA ✅
*Objetivo: implementar enhancement via IA sobre o classificador heurístico já funcional da Fase 2.5*

### Integração de Providers
- [x] Implementar `AIClassifier` em `core/analysis/classifier_ai.py` usando abstração `AIProvider`
- [x] Orquestrador em `core/analysis/classifier.py`: usa `AIClassifier` se provider disponível, senão `BaseClassifier`
- [x] Fallback automático: se provider configurado mas retorna erro → logar warning → usar heurístico
- [x] Cache de análises: hash do (finding_type + url + evidence_snippet) como chave; TTL configurável
- [x] Testes com providers mockados para Anthropic, OpenAI-compatible e Ollama

### Classifier
- [x] `core/analysis/classifier.py` — aplica scores + ordena findings
- [x] Task Celery: `run_ai_analysis(target_id)`
- [x] Integração no pipeline principal (etapa 8)
- [x] Trigger manual no dashboard para targets já reconhecidos
- [x] `system_settings` table e model: chave/valor para configurações persistidas no banco
- [x] `get_setting` / `set_setting` em `core/db/queries.py`
- [x] `run_ai_analysis` respeita `ai_analysis_limit` do banco; quando null processa tudo

### Geração de Report Draft
- [x] Prompt de geração de report para findings com score ≥ 60
- [x] Formato compatível com HackerOne e Bugcrowd
- [x] Exibição no dashboard + botão "Copy to clipboard"

### Geração de Templates
- [x] `core/analysis/template_generator.py`
- [x] Prompt para gerar YAML nuclei a partir de descrição natural
- [x] Validação básica do YAML gerado
- [x] Salvar em `core/analysis/templates/generated/`
- [ ] Interface no dashboard: input → gerar → revisar → salvar

---

## FASE 3.5 — CORREÇÕES E HARDENING DA FASE 3 ✅
*Objetivo: corrigir bugs críticos da Fase 3 antes de implementar monitoramento*

### Correções Críticas
- [x] `AIClassifier` e providers recebem API key como parâmetro direto em vez de ler `os.environ`; `get_provider(session)` aceita session e lê key do banco sem mutar env vars
- [x] `run_dnsx_filter`: capturar `FileNotFoundError` dentro da task e retornar skip silencioso em vez de propagar exceção que abortaria a Canvas chain
- [x] `classify_finding`: garantir que `finding.ai_report_draft` é atualizado quando `FindingScore.ai_report_draft` está presente
- [x] `run_ai_analysis`: adicionar `force_reanalyze: bool = False`; quando True, pular lookup de cache Redis antes de chamar a IA
- [x] Dashboard botão "Re-analyze with AI": passar `force_reanalyze=True` para `run_ai_analysis.apply_async`
- [x] `set_setting`: usar upsert explícito (`session.merge()` + `session.flush()` no SQLAlchemy) em vez de `session.add()`

### Modelo de Dados
- [x] `Target.auto_analyze` (Boolean, default True): campo no model + migration 20260513_0004; campo no formulário "Add Target" no dashboard
- [x] `run_nuclei_scan`: consultar `target.auto_analyze` antes de disparar `run_ai_analysis`; se False, transitar diretamente para `recon_done` sem análise
- [x] `run_ai_analysis`: adicionar `ai_call_delay_seconds` configurável via `get_setting`; aplicar `time.sleep(delay)` entre cada chamada de IA

### Qualidade e Segurança
- [x] `template_generator`: usar `yaml.safe_load()` + validar campos obrigatórios nuclei (`id`, `info.name`, `info.severity`, ao menos um de `requests`/`http`/`network`) antes de salvar; levantar `ValueError` com mensagem descritivo se inválido
- [x] `pyproject.toml`: adicionar `pyyaml>=6.0` como dependência; adicionar `openai` como dependência opcional (`[openai]`); tratar `ImportError` no `OpenAICompatibleProvider.complete()` com mensagem clara
- [x] `Dockerfile.worker`: instalar `dnsx` via `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest`; instalar `chromium chromium-driver` via apt; rodar `nuclei -update-templates || true` no build
- [x] Testes: `run_ai_analysis` com `force_reanalyze=True` ignora cache; `run_ai_analysis` com `auto_analyze=False` no target não é disparado; `set_setting` com key existente não levanta IntegrityError; `run_dnsx_filter` com dnsx não instalado não aborta pipeline

### Settings Page
- [x] Adicionar campo "AI call delay (seconds)" na seção AI Provider (number input, min=0, max=10, default=1)
- [x] Adicionar campo "Auto-analyze new targets" (checkbox, default True) como setting global que pré-preenche o campo `auto_analyze` em novos targets

---

## FASE 3.6 — SINCRONIZAÇÃO DE DOCS E CONTRATOS ✅
*Objetivo: alinhar CLAUDE.md, ROADMAP.md e SPEC.md com o estado real pós-Fase 3.5 antes de mexer no código.*

### Docs
- [x] Atualizar CLAUDE.md com “Estado atual real — pós Fase 3.5”.
- [x] Atualizar CLAUDE.md com regras de dashboard, Celery, findings, notifications e wrappers.
- [x] Atualizar ROADMAP.md adicionando Fase 3.7 antes da Fase 4.
- [x] Atualizar SPEC.md com comportamento real esperado para dashboard, pipeline, notifications, auth e deployment.
- [x] Remover/evitar itens incorretos:
  - Não afirmar que `SystemSetting.updated_at` não tem `onupdate`; o código atual já tem.
  - Não tratar `insert_recon_results_with_dedup` como falha silenciosa crítica.
  - Não transformar criptografia de secrets em bloqueador da Fase 3.7; documentar como dívida/backlog.

### Critério de saída
- [x] Nenhuma mudança de código.
- [x] Docs refletem que Fase 4 só começa após Fase 3.7.
- [x] Prompt da Fase 3.7 registrado no ROADMAP.md ou em `docs/prompts/fase_3_7.md`.

---

## FASE 3.7 — OPERABILIDADE REAL + HARDENING MÍNIMO ✅
*Objetivo: transformar o Syshunt de “pipeline implementado” em ferramenta usável no dia a dia, segura para notebook e VPS protegida.*

Pré-requisito para Fase 4: concluir esta fase. **CONCLUÍDA — 307 testes passando.**

### Grupo A — Operabilidade mínima ✅

#### A1. Autenticação básica no dashboard
- [x] Implementar verificação de `DASHBOARD_PASSWORD` antes de renderizar sidebar/páginas.
- [x] Se `DASHBOARD_PASSWORD` vazio: permitir acesso local e mostrar warning.
- [x] Se definido: exigir senha via Streamlit e guardar `authenticated` em `st.session_state`.
- [x] Usar comparação segura (`hmac.compare_digest`); `_check_password` separada e testável.
- [x] Testes: senha correta, senha incorreta, env vazia (4 testes).

#### A2. Botões Start Recon e Re-scan rápido
- [x] Importar `run_full_pipeline` no dashboard.
- [x] Adicionar botão `Start Recon` por target.
- [x] Adicionar botão `Re-scan rápido` por target com `skip_recon=True`.
- [x] Desabilitar botões se status em `recon_running` ou `analysis_running`.
- [x] Exibir mensagem de pipeline enfileirado.
- [x] Testes: mock de `apply_async`, target_id correto, skip_recon correto (4 testes).

#### A3. Formulário Add Target completo
- [x] Campos: `domain`, `scope_includes`, `scope_excludes`, `platform`, `program_id`, `recon_depth`, `auto_analyze`.
- [x] Atualizar `create_target()` para aceitar esses campos.
- [x] Defaults:
  - `scope_includes = [domain]`
  - `scope_excludes = []`
  - `recon_depth = 2`
- [x] Testes: target criado com scope/platform/depth customizados (5 testes).

#### A4. Status `analysis_running`
- [x] `run_ai_analysis` seta `target.status = "analysis_running"` ao iniciar.
- [x] Commit imediato após alterar status.
- [x] Ao fim, `target.status = "ready_for_review"`.
- [x] Dashboard inclui `analysis_running` no filtro/lista de status.
- [x] Testes: transição `recon_done → analysis_running → ready_for_review` (4 testes).

### Grupo B — Bugs e consistência ✅

#### B1. `run_dnsx_filter` com retorno consistente
- [x] Todos os paths retornam `{target_id, tool, filtered, kept, skipped}`.
- [x] Paths sem skip retornam `skipped=False`.
- [x] Exceptions retornam `filtered=0`, `kept=0`, `skipped=True`.
- [x] Testes: sucesso, sem subdomínios, wrapper fail, FileNotFoundError/exception.

#### B2. `force_reanalyze` funcional
- [x] Se `force_reanalyze=True`, incluir findings já classificados na query.
- [x] Criar ou planejar `run_ai_analysis_for_finding(finding_id, force_reanalyze=True)`.
- [x] Ajustar botão “Re-analyze with AI” para comportamento real.
- [x] Testes: finding com `classifier_used="heuristic"` é reprocessado com force.

#### B3. Deduplicação de Findings
- [x] Antes de inserir Finding em `run_nuclei_scan`, verificar duplicata por `(target_id, template_id, url)`.
- [x] Criar índice/constraint composto via Alembic, se tecnicamente viável.
- [x] Testes: re-scan não duplica finding.

#### B4. Paginação em Findings
- [x] `list_findings()` recebe `limit` e `offset`.
- [x] Search em memória deve ser revisado para não puxar tudo sem necessidade; se ficar para depois, documentar.
- [x] Dashboard adiciona página atual e page size.
- [x] Testes: `limit/offset` funcionam.

#### B5. CSV com BOM
- [x] `_parse_domains_from_csv` aceita `\ufeffdomain`.
- [x] Usar `utf-8-sig` ou normalizar fieldnames.
- [x] Testes: CSV com BOM e header `domain,notes`.

#### B6. Scope wildcard
- [x] `check_in_scope` suporta:
  - `example.com`: raiz + subdomínios.
  - `*.example.com`: apenas subdomínios.
  - excludes sempre vencem includes.
- [x] Testes cobrindo wildcard, raiz, subdomínio e exclude.

### Grupo C — Uso real ✅

#### C1. Notificações Discord
- [x] Criar `core/notifications.py`.
- [x] Implementar `notify_recon_completed`.
- [x] Implementar `notify_high_score_finding`.
- [x] Stubs seguros para `notify_new_program`, `notify_scope_changed`, `notify_pipeline_error`.
- [x] Webhook lido de `system_settings.DISCORD_WEBHOOK_URL` com fallback para env var.
- [x] Respeitar flags:
  - `notify_recon_done`
  - `notify_high_score_finding`
- [x] Falha nunca propaga.
- [x] Testes com mock HTTP: payload correto e falha não quebra.

#### C2. Integrar notificações ao pipeline
- [x] Ao fim de `run_ai_analysis`, chamar `notify_recon_completed`.
- [x] Para findings com score >= 80, chamar `notify_high_score_finding`.
- [x] Testes com mocks.

#### C3. Export de findings
- [x] `export_findings_csv(session, filters...) -> str`.
- [x] `export_findings_markdown(session, filters...) -> str`.
- [x] Dashboard com `st.download_button` para CSV.
- [x] Dashboard com export/copy Markdown.
- [x] Testes: campos principais presentes.

#### C4. GoWitness
- [x] Testar sintaxe real da versão instalada no `Dockerfile.worker`.
- [x] Ajustado para `gowitness scan single --url ...` (v3+ syntax).
- [x] Atualizar testes do wrapper.
- [x] Garantir que `filename=None` não quebra dashboard.

#### C5. README operacional
- [x] Recriar `README.md` em UTF-8.
- [x] Documentar uso local/notebook.
- [x] Documentar uso VPS protegida.
- [x] Documentar comandos:
  - `make up`
  - `make migrate`
  - `make worker`
  - `make dashboard`
  - `make up-all`
- [x] Avisar: não rodar scans fora de escopo/autorização.
- [x] Avisar: para VPS, usar `DASHBOARD_PASSWORD` e não expor Redis/Postgres/Flower publicamente.

### Fora de escopo da Fase 3.7

- [ ] Criptografia completa de `SystemSetting.value`.
- [ ] Retry/backoff global de Celery tasks.
- [ ] Concorrência avançada no crawl.
- [ ] Join/callback robusto para recon recursivo.
- [ ] Integrações HackerOne/Bugcrowd/Intigriti.
- [ ] API REST própria.
- [ ] Página Programs completa.

Esses itens ficam para Fase 4, Fase 4.5 ou pós-Fase 5.

### Critério de saída

- [x] `pytest` passando (307 testes, 1 skipped docker integration).
- [x] Dashboard protegido por senha quando `DASHBOARD_PASSWORD` definido.
- [x] Recon pode ser disparado pela UI (Start Recon + Re-scan rápido).
- [x] Target pode ser criado com scope/platform/depth.
- [x] `analysis_running` aparece corretamente.
- [x] Re-scan não duplica findings.
- [x] Discord notifica conclusão de recon.
- [x] Findings podem ser exportados (CSV + Markdown).
- [x] README permite rodar o projeto do zero.

---

## FASE 3.8 — AUDITORIA PÓS-3.7 E PREPARAÇÃO REAL PARA FASE 4 ✅
*Objetivo: corrigir inconsistências remanescentes de docs, deploy, performance e contratos antes de iniciar monitoramento automático de plataformas.*

### Grupo A — Documentação e contratos

- [x] Corrigir `SPEC.md`:
  - remover duplicação de `## NOTIFICAÇÕES`;
  - fechar blocos Markdown quebrados;
  - corrigir seção 2.9 `run_dnsx_filter`;
  - corrigir seção de formatos Discord;
  - alinhar estados reais do Target.
- [x] Atualizar `CLAUDE.md` de “pós Fase 3.5” para “pós Fase 3.7”.
- [x] Corrigir arquitetura em `CLAUDE.md`: `core/notifications.py`, não `core/notifications/`.
- [x] Atualizar `.env.example` com:
  - `OUTPUT_DIR`;
  - `OPENAI_API_KEY`;
  - `OPENAI_BASE_URL`;
  - `OPENAI_MODEL`;
  - `OLLAMA_BASE_URL`;
  - `OLLAMA_MODEL`;
  - `AI_PROVIDER`;
  - `AI_CACHE_TTL`;
  - `ANTHROPIC_MODEL`;
  - `ALLOW_LOCAL_TARGETS`.

### Grupo B — Hardening de deploy ✅

- [x] Criar perfil seguro de compose:
  - não expor Postgres publicamente;
  - não expor Redis publicamente;
  - não expor Flower publicamente;
  - dashboard em `127.0.0.1:8501` por padrão.
- [x] Criar `docker-compose.local.yml` para desenvolvimento com portas locais.
- [x] Atualizar README com modo local vs VPS seguro (SSH tunnel, Tailscale, proxy autenticado).
- [x] Avaliar versões das ferramentas Go no Dockerfile.worker: mantidas em `@latest` com comentário
  explicativo; gowitness já é v3+ (que usa `scan single`); pinagem de versões específicas fica
  como backlog — requer verificação dentro do container para confirmar tags exatas.
- [ ] **Backlog pós-Fase 3.8**: fixar versões Go (subfinder, httpx, nuclei, katana, dnsx, ffuf,
  gau, gowitness) em valores verificados. Rastrear em https://github.com/sensepost/gowitness/releases
  e equivalentes. Bloqueante apenas se ferramenta quebrar por mudança de CLI upstream.

### Grupo C — Performance e consistência ✅

- [x] Refatorar `list_findings()` para paginação real no banco:
  - `limit` e `offset` aplicados via SQL (`.offset()` / `.limit()`);
  - text search movido para SQL com `ilike` via `or_()`;
  - removido slice em memória.
- [x] Criar `count_findings()` com os mesmos filtros de `list_findings`.
- [x] Atualizar dashboard Findings para usar `count_findings` + `list_findings(limit, offset)`.
- [x] Refatorar `classify_finding()` para receber `provider` e `redis_client` opcionais (sentinel `_UNSET`).
- [x] Refatorar `run_ai_analysis()` para resolver provider/cache uma vez por execução.
- [x] Refatorar `run_ai_analysis_for_finding()` para resolver provider/cache uma vez.
- [x] Refatorar `render_settings_page()` com `_read_settings()` e `_write_settings()` — sessões curtas por operação.
- [x] Implementar `ALLOW_LOCAL_TARGETS=false`:
  - bloquear localhost, localdomain, `.local`, `.localhost`;
  - bloquear loopback, IPs privados, link-local, reservados, multicast via `ipaddress`;
  - aplicado em `create_target` e `bulk_create_targets`;
  - permitir apenas se `ALLOW_LOCAL_TARGETS=true`.

### Grupo D — Estados de falha e resiliência ✅

- [x] Adicionar estados opcionais:
  - `recon_failed` — setado por `run_full_pipeline` quando dispatch falha;
  - `analysis_failed` — setado por `run_ai_analysis` quando exceção não tratada.
- [x] Garantir que `run_ai_analysis()` não deixa target preso em `analysis_running` se falhar.
- [x] Garantir que falha ao enfileirar pipeline não deixa target preso em `recon_running`.
- [x] Integrar `notify_pipeline_error()` a falhas críticas (implementada em `core/notifications.py`).
- [x] Retry/backoff: registrado como Fase 4.5 — não necessário antes da Fase 4.
- [x] Dashboard target status filter inclui `recon_failed` e `analysis_failed`.

### Grupo E — Validação de promessas de pipeline ✅

- [x] Recon recursivo: **não conectado ao pipeline principal** — disponível via `run_recursive_subdomain_enum_task` Celery task mas não auto-triggerado; documentado em `docs/current_pipeline.md`.
- [x] Amass: **não integrado** — wrapper não existe; apenas subfinder roda no pipeline principal; atualizado em `docs/current_pipeline.md`.
- [x] ffuf: **wrapper existe** (`tools/ffuf_wrapper.py`) mas **sem task Celery** — movido para backlog.
- [x] Criado `docs/current_pipeline.md` com fluxo real executado, ferramentas ausentes, estados de falha e máquina de estados.

### Critério de saída ✅

- [x] `pytest` passando.
- [x] `SPEC.md` renderiza corretamente.
- [x] `CLAUDE.md` reflete estado pós-3.7.
- [x] Compose seguro para VPS existe.
- [x] Findings paginam no banco.
- [x] Provider/Redis não são resolvidos por finding.
- [x] Settings Page usa sessões curtas.
- [x] Targets locais/privados são bloqueados por padrão.
- [x] Fase 4 pode começar sem carregar dívida de operabilidade.

---

## FASE 4 — MONITORAMENTO DE PLATAFORMAS
*Objetivo: detectar novos programas automaticamente*

> Pré-requisito obrigatório: Fase 3.8 concluída.
> A Fase 4 só deve começar quando o sistema já puder rodar recon manual pela UI, proteger dashboard via senha, notificar conclusão, evitar duplicação básica de findings, usar compose seguro para VPS, paginar findings no banco e bloquear targets locais/privados por padrão.

### Grupo 1 — HackerOne MVP ✅

- [x] `core/monitor/base.py` — ABC `PlatformMonitor`, `ProgramInfo`, `PlatformAPIError`, `RateLimitError`
- [x] `core/monitor/hackerone.py` — cliente HTTP com auth Basic, paginação, rate limit, parse de programas e escopos
- [x] `core/monitor/scheduler.py` — task Celery `poll_hackerone` (não auto-agendada ainda)
- [x] `core/db/queries.py` — `upsert_bounty_program`, `list_bounty_programs`, `get_bounty_program_by_handle`
- [x] `core/db/migrations/versions/20260515_0006` — unique index em `bounty_programs(platform, program_handle)`
- [x] `core/notifications.py` — `notify_new_program` e `notify_scope_changed` implementados (flags: `notify_new_program`, `notify_scope_changed`)
- [x] `dashboard/app.py` — `render_programs_page()`: lista básica com platform/handle/name/auto-recon/last_checked/scope count
- [x] `tests/fixtures/hackerone/` — fixtures JSON para programas e escopos
- [x] `tests/unit/test_monitor_hackerone.py` — 43 testes: cliente, normalize, scopes, upsert, detect, notificações, token safety, scheduler

### Integração Bugcrowd
- [ ] `core/monitor/bugcrowd.py` — cliente da API
- [ ] Mesma lógica de detecção

### Integração Intigriti
- [ ] `core/monitor/intigriti.py` — OAuth2 + API REST

### Scheduler Avançado
- [ ] Intervalo configurável por plataforma
- [ ] Task: `poll_all_platforms()` — roda a cada 30 min via Celery Beat
- [ ] Task: `trigger_recon_for_new_program(program_id)`

### Notificações Discord
- [x] `core/notifications.py` — webhook Discord (criado na Fase 3.7)
- [x] Formatos de mensagem para `recon_completed` e `high_score_finding` (Fase 3.7)
- [x] Configuração no dashboard — seção Notifications na página Settings (Fase 3.7)
- [x] Formatos de mensagem para `new_program` e `scope_changed` (Fase 4 Grupo 1)

### Dashboard — Fase 4
- [x] Página Programs básica: platform, handle, name, auto-recon, last_checked, scope entries (Grupo 1)
- [ ] Badge NEW / SCOPE CHANGED persistido no DB
- [ ] Botão de approve para disparar deep scan
- [ ] Histórico de mudanças de escopo por programa

---

## FASE 5 — POLISH E FEATURES FINAIS
*Objetivo: sistema completo e usável no dia a dia*

### Templates
- [ ] Página Templates completa no dashboard
- [ ] Editor YAML inline com syntax highlight
- [ ] Cálculo de false positive rate por template
- [ ] Import/export de templates

### Métricas
- [ ] Página de métricas com gráficos nativos do Streamlit
- [ ] Métricas conforme SPEC.md seção 8
- [ ] Export de relatórios consolidados (PDF ou markdown)

### Operacional
- [ ] Health check endpoint para monitoramento
- [ ] Logs estruturados com structlog em todos os módulos
- [ ] Documentação de operação (README.md)
- [ ] Script de backup do banco
- [ ] Configuração de retenção de outputs antigos

### Segurança do Sistema
- [ ] Validação de inputs em todos os endpoints
- [ ] Sanitização de domínios antes de passar para subprocess
- [ ] Opção de senha para o dashboard (env var)
- [ ] Auditoria de comandos executados

---

## BACKLOG (Pós-Fase 5)

Funcionalidades desejáveis mas não essenciais para v1:

- [ ] Integração com Burp Suite (exportar targets para Burp)
- [ ] Integração com shodan/censys para enriquecimento
- [ ] Detecção de tecnologias via Wappalyzer
- [ ] Comparação de recon entre datas (diff de subdomínios)
- [ ] Modo de "continuous monitoring" por alvo ativo
- [ ] API REST própria para integrar com outras ferramentas
- [ ] Mobile notifications (Telegram bot)
- [ ] Exportação de findings para Jira/Notion

---

## PROMPTS OPERACIONAIS

### Prompt — Fase 3.8 Grupo A

```text
Leia CLAUDE.md, ROADMAP.md e SPEC.md.

Estamos iniciando a FASE 3.8 — AUDITORIA PÓS-3.7 E PREPARAÇÃO REAL PARA FASE 4.

Execute somente o Grupo A — Documentação e contratos.

Não altere código Python.
Não altere Dockerfile.
Não altere docker-compose.
Não implemente Fase 4.

Tarefas:
1. Corrigir SPEC.md:
   - remover duplicação da seção NOTIFICAÇÕES;
   - fechar blocos Markdown quebrados;
   - corrigir seção 2.9 do contrato run_dnsx_filter;
   - corrigir formatos Discord;
   - adicionar estados planejados recon_failed e analysis_failed;
   - adicionar paginação real no banco como requisito;
   - adicionar regra ALLOW_LOCAL_TARGETS=false.

2. Atualizar CLAUDE.md:
   - substituir “Estado atual real — pós Fase 3.5” por “pós Fase 3.7”;
   - remover itens que agora já foram implementados na Fase 3.7;
   - corrigir core/notifications.py na arquitetura;
   - adicionar Fase 3.8 como fase ativa;
   - atualizar regras sobre compose seguro, paginação real, provider/cache uma vez por análise e targets locais.

3. Atualizar ROADMAP.md:
   - adicionar Fase 3.8 antes da Fase 4;
   - marcar Fase 4 como dependente da Fase 3.8;
   - adicionar nota de sessão da auditoria pós-3.7.

4. Atualizar .env.example apenas se você considerar documentação, adicionando variáveis faltantes:
   - OUTPUT_DIR
   - AI_PROVIDER
   - OPENAI_API_KEY
   - OPENAI_BASE_URL
   - OPENAI_MODEL
   - OLLAMA_BASE_URL
   - OLLAMA_MODEL
   - AI_CACHE_TTL
   - ANTHROPIC_MODEL
   - ALLOW_LOCAL_TARGETS

Ao final:
- Não rode pytest se só mudou documentação/env example.
- Mostre diff resumido.
- Faça commit:
  docs(roadmap): add phase 3.8 post-operability audit
```

### Prompt — Fase 3.8 Grupo B

```text
Leia CLAUDE.md, ROADMAP.md e SPEC.md.

Continue a FASE 3.8.
Execute somente o Grupo B — Hardening de deploy.

Não implemente Fase 4.
Não mexa em monitoramento de plataformas.

Tarefas:
1. Tornar compose seguro:
   - não expor Postgres publicamente;
   - não expor Redis publicamente;
   - não expor Flower publicamente;
   - dashboard deve bindar em 127.0.0.1 por padrão ou ficar em arquivo separado.

2. Criar docker-compose.local.yml:
   - expõe portas locais para desenvolvimento;
   - deixa claro que não é para VPS pública.

3. Atualizar README:
   - explicar compose local vs VPS;
   - explicar Tailscale/SSH tunnel/proxy autenticado;
   - explicar que make up-all em VPS não deve expor db/redis/flower.

4. Dockerfile.worker:
   - avaliar se ferramentas Go devem ser fixadas em versões.
   - se for simples, fixar gowitness em versão compatível com `gowitness scan single`.
   - se não fixar todas agora, registrar como pendência explícita no ROADMAP.

Testes/validação:
- docker compose config deve passar.
- docker compose -f docker-compose.yml -f docker-compose.local.yml config deve passar.
- README atualizado.

Commit:
chore(deploy): separate local and vps compose profiles
```

### Prompt — Fase 3.8 Grupo C

```text
Leia CLAUDE.md, ROADMAP.md e SPEC.md.

Continue a FASE 3.8.
Execute somente o Grupo C — Performance e consistência.

Não implemente Fase 4.

Tarefas:
1. Paginação real:
   - refatorar list_findings para aplicar limit/offset no banco antes de all().
   - criar count_findings com os mesmos filtros.
   - atualizar dashboard Findings para usar count_findings + list_findings(limit, offset).
   - remover slice em memória.

2. Provider/cache:
   - refatorar classify_finding para aceitar provider e redis_client opcionais.
   - run_ai_analysis deve resolver provider e redis uma vez.
   - run_ai_analysis_for_finding também deve resolver uma vez.
   - manter compatibilidade com chamadas antigas.

3. Settings Page:
   - remover session_ctx = SessionLocal(); __enter__/__exit__ manual.
   - quebrar em funções menores com with SessionLocal() por operação.
   - preservar comportamento atual.

4. ALLOW_LOCAL_TARGETS:
   - implementar bloqueio padrão para localhost, loopback, IP privado/link-local e .local.
   - permitir apenas com ALLOW_LOCAL_TARGETS=true.
   - aplicar em create_target e bulk_create_targets.

Testes:
- list_findings usa limit/offset corretamente.
- count_findings retorna total correto.
- provider chamado uma vez para múltiplos findings.
- settings page helpers salvam/carregam com sessões curtas.
- localhost/private IP rejeitados por padrão.
- ALLOW_LOCAL_TARGETS=true permite targets locais.

Commit:
fix(core): enforce real pagination and target safety
```

### Prompt — Fase 3.8 Grupos D/E

```text
Leia CLAUDE.md, ROADMAP.md e SPEC.md.

Continue a FASE 3.8.
Execute Grupos D e E — Estados de falha e validação do pipeline real.

Não implemente APIs HackerOne/Bugcrowd/Intigriti ainda.

Tarefas:
1. Estados de falha:
   - adicionar suporte a recon_failed e analysis_failed se simples.
   - run_ai_analysis não deve deixar target preso em analysis_running em erro.
   - run_full_pipeline não deve deixar target preso em recon_running se dispatch falhar.
   - integrar notify_pipeline_error quando viável.

2. Validar pipeline real:
   - documentar o pipeline atual em docs/current_pipeline.md.
   - verificar se recon recursivo está conectado ao pipeline principal.
   - verificar se amass está realmente integrado.
   - verificar se ffuf está realmente integrado.
   - se não estiverem, ajustar SPEC/ROADMAP para não prometer como implementado ou mover para backlog.

3. Testes:
   - erro em run_ai_analysis seta analysis_failed ou status seguro.
   - erro em dispatch do pipeline não prende recon_running.
   - docs/current_pipeline.md criado.

Ao final:
- Rode pytest.
- Atualize ROADMAP.md marcando Fase 3.8.
- Commit:
  chore(roadmap): close phase 3.8 readiness audit
```

---

## NOTAS DE SESSÃO

*Registre aqui o que foi feito em cada sessão para manter continuidade:*

| Data | Fase | O que foi feito | Pendências |
|------|------|-----------------|------------|
| 2026-05-13 | Spec | CLAUDE.md, SPEC.md, docker-compose.yml, ROADMAP.md criados | Começar Fase 1 |
| 2026-05-13 | 2.5 | Pipeline Canvas chain, urlparse, async recursive recon task, normalize_domain regex, check_in_scope, sha256 completo, source_tool no crawl, filename no screenshot, CSV fix, dnsx/ffuf wrappers, AIProvider, classifier_base, migration findings | — |
| 2026-05-13 | 2.5+3 | scope validation em tasks, run_dnsx_filter, form validation, SystemSetting, migration 0003, get_setting/set_setting, AIClassifier, classifier.py com Redis cache, template_generator, run_ai_analysis, settings dashboard, AI badges/expanders, Re-analyze button | Interface dashboard para template generator (Fase 5) |
| 2026-05-14 | 3.5 | provider.py refatorado (api_key nos construtores, get_provider(session)), classify_finding(force_reanalyze), run_dnsx_filter try/except, run_ai_analysis (force_reanalyze+delay+remove os.environ), set_setting merge+flush, Target.auto_analyze+migration 0004, run_nuclei_scan auto_analyze check, template_generator yaml.safe_load, pyproject.toml pyyaml+openai opcional, Dockerfile.worker dnsx+chromium, dashboard Re-analyze+AI delay+auto_analyze settings, 20 novos testes (234 total) | Fase 4 — Monitoramento de Plataformas |
| 2026-05-15 | Análise | Auditoria combinada pós-3.5: maioria dos achados do Claude validada; removidos exageros/itens incorretos; criada Fase 3.6 para docs e Fase 3.7 para operabilidade antes da Fase 4. | Fase 3.6 e 3.7 |
| 2026-05-15 | 3.7-C | Grupo C concluído: core/notifications.py (C1), integração notify em run_ai_analysis (C2), export_findings_csv/markdown + dashboard buttons (C3), gowitness v3 scan single (C4), README.md UTF-8 recriado (C5). 307 testes passando. | Fase 4 após Fase 3.7 completa |
| 2026-05-15 | 3.7 ✅ | Revisão final: todos os 17 critérios de saída confirmados no código. Fase 3.7 encerrada. Próxima: Fase 4 — Monitoramento de Plataformas. | — |
| 2026-05-15 | Auditoria pós-3.7 | 3.7 validada em grande parte; encontrados problemas remanescentes em SPEC.md, CLAUDE.md, compose exposto, paginação em memória, provider por finding, settings session longa e ALLOW_LOCAL_TARGETS não implementado. Criada Fase 3.8 antes da Fase 4. | Fase 3.8 |
| 2026-05-15 | 3.8 Grupo B | Compose seguro: removidas portas de db/redis/flower, dashboard em 127.0.0.1. Criado docker-compose.local.yml. Makefile: up-local. README: local vs VPS, SSH tunnel, Tailscale, Caddy. Dockerfile.worker: comentário sobre pinagem de versões Go. | Grupos C/D/E da 3.8 |
| 2026-05-15 | 3.8 Grupo C | Paginação real: list_findings/count_findings com SQL limit/offset e ilike search. Dashboard findings: count+page query. classify_finding: provider/redis_client opcionais (sentinel). run_ai_analysis: provider+redis resolvidos uma vez. Settings page: _read_settings/_write_settings com sessões curtas. ALLOW_LOCAL_TARGETS: bloqueia localhost/private/link-local por padrão. 342 testes passando. | Grupos D/E da 3.8 |
| 2026-05-15 | 3.8 Grupos D/E ✅ | run_ai_analysis: try/except → analysis_failed + notify_pipeline_error. run_full_pipeline: try/except → recon_failed + notify_pipeline_error. Dashboard: recon_failed/analysis_failed nos filtros de status. docs/current_pipeline.md: pipeline real documentado. Amass não integrado (só subfinder). ffuf wrapper existe mas sem task Celery (backlog). Recon recursivo existe mas não auto-triggerado. ROADMAP.md: Fase 3.8 encerrada. | Fase 4 — Monitoramento de Plataformas |
| 2026-05-15 | 4 Grupo 1 ✅ | HackerOne MVP: base.py (ABC), hackerone.py (cliente HTTP, paginação, parse, rate limit), scheduler.py (poll_hackerone task), upsert_bounty_program + list/get queries, migration 0006 (unique index platform+handle), notify_new_program + notify_scope_changed implementadas, render_programs_page no dashboard, fixtures JSON, 43 testes. 399 passando. | Bugcrowd, Intigriti, auto-recon, scheduler automático |
