# ROADMAP.md — Plano de Execução com Codex

> Este arquivo é o plano de trabalho **ordenado por sessão de Claude**.
> Cada sessão deve começar lendo CLAUDE.md, depois este arquivo,
> executar a fase atual, atualizar checkboxes e fazer commit.

---

## COMO TRABALHAR COM O CLAUDE NESTE PROJETO

**Prompt de abertura de sessão (copie e adapte):**
```
Leia o CLAUDE.md e o ROADMAP.md do projeto Syshunt.
Estou na [FASE 3 — FUNDAÇÃO DO PROJETO].
Execute as tasks pendentes nessa fase.
Após cada task: rode os testes, faça commit com mensagem descritiva.
Atualize os checkboxes no ROADMAP.md ao concluir cada item.
Se precisar de decisão arquitetural, registre no CLAUDE.md antes de implementar.
```

**Regras de sessão:**
- Máximo de 1 fase por sessão (evita contexto longo demais)
- Sempre commitar ao final da sessão, mesmo que parcial
- Nunca deixar testes quebrando ao commitar
- Atualizar CLAUDE.md se qualquer decisão nova for tomada

---

## FASE 1 — FUNDAÇÃO DO PROJETO
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


## FASE 1.5 — CORREÇÕES ESTRUTURAIS
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


## FASE 2 — RECON COMPLETO
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


## FASE 2.5 — CORREÇÕES E FUNDAÇÃO PARA IA
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



## FASE 3 — ANÁLISE POR IA
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


## FASE 3.5 — CORREÇÕES E HARDENING DA FASE 3
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
- [x] `template_generator`: usar `yaml.safe_load()` + validar campos obrigatórios nuclei (`id`, `info.name`, `info.severity`, ao menos um de `requests`/`http`/`network`) antes de salvar; levantar `ValueError` com mensagem descritiva se inválido
- [x] `pyproject.toml`: adicionar `pyyaml>=6.0` como dependência; adicionar `openai` como dependência opcional (`[openai]`); tratar `ImportError` no `OpenAICompatibleProvider.complete()` com mensagem clara
- [x] `Dockerfile.worker`: instalar `dnsx` via `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest`; instalar `chromium chromium-driver` via apt; rodar `nuclei -update-templates || true` no build
- [x] Testes: `run_ai_analysis` com `force_reanalyze=True` ignora cache; `run_ai_analysis` com `auto_analyze=False` no target não é disparado; `set_setting` com key existente não levanta IntegrityError; `run_dnsx_filter` com dnsx não instalado não aborta pipeline

### Settings Page
- [x] Adicionar campo "AI call delay (seconds)" na seção AI Provider (number input, min=0, max=10, default=1)
- [x] Adicionar campo "Auto-analyze new targets" (checkbox, default True) como setting global que pré-preenche o campo `auto_analyze` em novos targets

---

## FASE 3.6 — SINCRONIZAÇÃO DE DOCS E CONTRATOS
*Objetivo: alinhar CLAUDE.md, ROADMAP.md e SPEC.md com o estado real pós-Fase 3.5 antes de mexer no código.*

### Docs
- [ ] Atualizar CLAUDE.md com “Estado atual real — pós Fase 3.5”.
- [ ] Atualizar CLAUDE.md com regras de dashboard, Celery, findings, notifications e wrappers.
- [ ] Atualizar ROADMAP.md adicionando Fase 3.7 antes da Fase 4.
- [ ] Atualizar SPEC.md com comportamento real esperado para dashboard, pipeline, notifications, auth e deployment.
- [ ] Remover/evitar itens incorretos:
  - Não afirmar que `SystemSetting.updated_at` não tem `onupdate`; o código atual já tem.
  - Não tratar `insert_recon_results_with_dedup` como falha silenciosa crítica.
  - Não transformar criptografia de secrets em bloqueador da Fase 3.7; documentar como dívida/backlog.

### Critério de saída
- [ ] Nenhuma mudança de código.
- [ ] Docs refletem que Fase 4 só começa após Fase 3.7.
- [ ] Prompt da Fase 3.7 registrado no ROADMAP.md ou em `docs/prompts/fase_3_7.md`.


---

## FASE 3.7 — OPERABILIDADE REAL + HARDENING MÍNIMO
*Objetivo: transformar o Syshunt de “pipeline implementado” em ferramenta usável no dia a dia, segura para notebook e VPS protegida.*

Pré-requisito para Fase 4: concluir esta fase.

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

---

### Grupo B — Bugs e consistência

#### B1. `run_dnsx_filter` com retorno consistente
- [x] Todos os paths retornam `{target_id, tool, filtered, kept, skipped}`.
- [x] Paths sem skip devem retornar `skipped=False`.
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
- [x] `_parse_domains_from_csv` deve aceitar `\ufeffdomain`.
- [x] Usar `utf-8-sig` ou normalizar fieldnames.
- [x] Testes: CSV com BOM e header `domain,notes`.

#### B6. Scope wildcard
- [x] `check_in_scope` deve suportar:
  - `example.com`: raiz + subdomínios.
  - `*.example.com`: apenas subdomínios.
  - excludes sempre vencem includes.
- [x] Testes cobrindo wildcard, raiz, subdomínio e exclude.

---

### Grupo C — Uso real

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

---

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

- [ ] `pytest` passando.
- [ ] Dashboard protegido por senha quando `DASHBOARD_PASSWORD` definido.
- [ ] Recon pode ser disparado pela UI.
- [ ] Target pode ser criado com scope/platform/depth.
- [ ] `analysis_running` aparece corretamente.
- [ ] Re-scan não duplica findings.
- [ ] Discord notifica conclusão de recon.
- [ ] Findings podem ser exportados.
- [ ] README permite rodar o projeto do zero.



## FASE 4 — MONITORAMENTO DE PLATAFORMAS
*Objetivo: detectar novos programas automaticamente*

> Pré-requisito obrigatório: Fase 3.7 concluída.
> A Fase 4 só deve começar quando o sistema já puder rodar recon manual pela UI, proteger dashboard via senha, notificar conclusão e evitar duplicação básica de findings.

### Integração HackerOne
- [ ] `core/monitor/hackerone.py` — cliente da API
- [ ] Parsing de programas e escopos
- [ ] Detecção de novos programas (por `launched_at`)
- [ ] Detecção de mudanças de escopo
- [ ] Testes com fixtures JSON da API

### Integração Bugcrowd
- [ ] `core/monitor/bugcrowd.py` — cliente da API
- [ ] Mesma lógica de detecção

### Integração Intigriti
- [ ] `core/monitor/intigriti.py` — OAuth2 + API REST

### Scheduler
- [ ] `core/monitor/scheduler.py` — Celery Beat task de polling
- [ ] Intervalo configurável por plataforma
- [ ] Task: `poll_all_platforms()` — roda a cada 30 min
- [ ] Task: `trigger_recon_for_new_program(program_id)`

### Notificações Discord
- [ ] `core/notifications.py` — webhook Discord
- [ ] Formatos de mensagem para cada tipo de evento
- [ ] Configuração no dashboard

### Dashboard — Fase 4
- [ ] Página Programs completa
- [ ] Badge NEW / SCOPE CHANGED
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