# ROADMAP.md — Plano de Execução com Codex

> Este arquivo é o plano de trabalho **ordenado por sessão de Codex**.
> Cada sessão deve começar lendo CLAUDE.md, depois este arquivo,
> executar a fase atual, atualizar checkboxes e fazer commit.

---

## COMO TRABALHAR COM O CODEX NESTE PROJETO

**Prompt de abertura de sessão (copie e adapte):**
```
Leia o CLAUDE.md e o ROADMAP.md do projeto Syshunt.
Estou na [FASE 2.5 — FUNDAÇÃO DO PROJETO].
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
- [ ] Validação de scope em cada task do pipeline: subdomínios fora de `scope_includes` ou em `scope_excludes` não são processados nas etapas seguintes
- [x] Hash completo sha256 em `_data_hash` (remover `[:16]`)
- [x] `run_web_crawl`: adicionar campo `source_tool` nos data_items (`{"url": u, "source_tool": "katana"}`)
- [x] `run_screenshot`: capturar e armazenar `filename` gerado pelo gowitness no ReconResult data

### Correções de Dashboard
- [x] Corrigir `_parse_domains_from_csv`: fallback para lista sem header não deve excluir linhas com vírgula; deve parsear apenas a primeira coluna
- [ ] Adicionar validação de formato de domínio no formulário "Add Target" antes de submeter

### Novos Wrappers
- [x] `tools/dnsx_wrapper.py` — resolução e validação de subdomínios antes do httpx; filtra wildcard e NXDOMAIN
- [x] `tools/ffuf_wrapper.py` — fuzzing de diretórios e parâmetros em hosts ativos; integrar após web crawl
- [ ] Integrar `dnsx` entre subdomain enum e http probe no pipeline

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
- [ ] Implementar `AIClassifier` em `core/analysis/classifier_ai.py` usando abstração `AIProvider`
- [ ] Orquestrador em `core/analysis/classifier.py`: usa `AIClassifier` se provider disponível, senão `BaseClassifier`
- [ ] Fallback automático: se provider configurado mas retorna erro → logar warning → usar heurístico
- [ ] Cache de análises: hash do (finding_type + url + evidence_snippet) como chave; TTL configurável
- [ ] Testes com providers mockados para Anthropic, OpenAI-compatible e Ollama

### Classifier
- [ ] `core/analysis/classifier.py` — aplica scores + ordena findings
- [ ] Task Celery: `run_ai_analysis(target_id)`
- [ ] Integração no pipeline principal (etapa 8)
- [ ] Trigger manual no dashboard para targets já reconhecidos
- [ ] `system_settings` table e model: chave/valor para configurações persistidas no banco
- [ ] `get_setting` / `set_setting` em `core/db/queries.py`
- [ ] `run_ai_analysis` respeita `ai_analysis_limit` do banco; quando null processa tudo

### Geração de Report Draft
- [ ] Prompt de geração de report para findings com score ≥ 60
- [ ] Formato compatível com HackerOne e Bugcrowd
- [ ] Exibição no dashboard + botão "Copy to clipboard"

### Geração de Templates
- [ ] `core/analysis/template_generator.py`
- [ ] Prompt para gerar YAML nuclei a partir de descrição natural
- [ ] Validação básica do YAML gerado
- [ ] Salvar em `core/analysis/templates/generated/`
- [ ] Interface no dashboard: input → gerar → revisar → salvar

---

## FASE 4 — MONITORAMENTO DE PLATAFORMAS
*Objetivo: detectar novos programas automaticamente*

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
| 2026-05-13 | 2.5 | Pipeline Canvas chain, urlparse, async recursive recon task, normalize_domain regex, check_in_scope, sha256 completo, source_tool no crawl, filename no screenshot, CSV fix, dnsx/ffuf wrappers, AIProvider, classifier_base, migration findings | Pendente: scope validation no pipeline, dnsx integração, validação no form Add Target |
