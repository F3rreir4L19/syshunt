# CLAUDE.md — BugHunter Automated Bug Bounty System

> Este arquivo é a **spec viva** do projeto. Ele é lido pelo agente de IA (Codex/Claude Code)
> no início de cada sessão. Toda decisão arquitetural, convenção de código e escopo do sistema
> está documentada aqui. Quando algo mudar, este arquivo muda junto.

---

## VISÃO GERAL

**BugHunter** é um sistema de bug bounty automatizado com foco em **volume inteligente**.
Ele não substitui o julgamento do pesquisador — ele amplifica a capacidade operacional:
realiza recon completo e recursivo, organiza achados, analisa vulnerabilidades e classifica
tudo por probabilidade de ser um positivo real, criticidade e dificuldade de exploração.
O pesquisador fica com as partes que exigem criatividade, contexto e profundidade.

**Estratégia central:**
- Automação → volume de achados razoáveis → consistência de renda
- Pesquisa manual → profundidade → reputação e payouts maiores
- Combinação das duas = crescimento sustentável no bug bounty

---

## ESTADO ATUAL REAL — pós Fase 3.7

O Syshunt concluiu as fases 1, 1.5, 2, 2.5, 3, 3.5, 3.6 e 3.7.

Implementado:
- Docker/Compose para db, redis, worker, beat, flower e dashboard.
- Models SQLAlchemy: Target, Finding, ReconResult, SystemSetting, BountyProgram.
- Pipeline Celery: subfinder → dnsx → httpx → nmap → webcrawl → screenshot → nuclei → análise.
- Classificação heurística sempre disponível.
- Classificação por IA via Anthropic, OpenAI-compatible e Ollama.
- Cache Redis de análise.
- Dashboard Streamlit com autenticação via DASHBOARD_PASSWORD.
- Add Target com scope_includes, scope_excludes, platform, program_id, recon_depth e auto_analyze.
- Start Recon e Re-scan rápido pela UI.
- Status analysis_running.
- Re-análise individual de Finding via run_ai_analysis_for_finding.
- Deduplicação app-level de Finding por target_id/template_id/url.
- Export CSV/Markdown.
- Notificações Discord para recon_completed e high_score_finding.
- Dashboard Streamlit com Targets, Import CSV, Findings e Settings.
- Geração backend de templates nuclei por IA.
- README operacional em UTF-8.

Ainda incompleto:
- Página Programs ainda é placeholder.
- Integrações HackerOne/Bugcrowd/Intigriti ainda não existem.
- Notificações new_program/scope_changed/pipeline_error ainda são stubs.
- Página Templates ainda não existe.
- Paginação de Findings ainda precisa ser feita no banco, não em memória.
- Provider/Redis ainda são resolvidos dentro de classify_finding; deve ser otimizado para uma vez por análise.
- docker-compose ainda expõe Postgres/Redis/Flower/Dashboard em todas as interfaces.
- SPEC.md precisa ser saneado para remover blocos quebrados e duplicações.
- API keys em system_settings ainda ficam em plaintext.
- ALLOW_LOCAL_TARGETS está documentado, mas precisa ser implementado.

Fase ativa antes da Fase 4: Fase 3.8 — Auditoria pós-3.7 e preparação real para monitoramento de plataformas.

---

## ARQUITETURA DO SISTEMA

```
bughunter/
├── CLAUDE.md                  ← este arquivo (spec viva)
├── SPEC.md                    ← especificação funcional detalhada
├── docker-compose.yml         ← orquestração de todos os serviços
├── .env.example               ← variáveis de ambiente necessárias
│
├── core/                      ← engine principal (Python)
│   ├── recon/                 ← módulos de reconhecimento
│   │   ├── subdomain.py       ← enumeração de subdomínios
│   │   ├── portscan.py        ← varredura de portas
│   │   ├── webprobe.py        ← probing HTTP/HTTPS
│   │   ├── crawl.py           ← crawling de URLs e JS
│   │   ├── screenshot.py      ← screenshots automáticos
│   │   └── recursive.py       ← orquestrador recursivo de recon
│   │
│   ├── analysis/              ← módulos de análise
│   │   ├── vuln_scanner.py    ← scanner de vulnerabilidades (nuclei)
│   │   ├── ai_analyzer.py     ← análise de contexto via LLM
│   │   ├── classifier.py      ← classificação e scoring
│   │   └── templates/         ← templates customizados de nuclei
│   │       ├── custom/        ← templates criados pelo usuário
│   │       └── generated/     ← templates gerados por IA
│   │
│   ├── monitor/               ← monitoramento de plataformas
│   │   ├── hackerone.py       ← HackerOne API
│   │   ├── bugcrowd.py        ← Bugcrowd API
│   │   ├── intigriti.py       ← Intigriti API
│   │   └── scheduler.py       ← scheduler de polling
│   │
│   ├── notifications.py       ← Discord webhook e eventos fire-and-forget
│   ├── pipeline/              ← orquestração de workflows
│   │   ├── tasks.py           ← Celery tasks
│   │   ├── workflow.py        ← fluxos de execução
│   │   └── state.py           ← máquina de estados do alvo
│   │
│   └── db/                    ← modelos e acesso a dados
│       ├── models.py          ← SQLAlchemy models
│       ├── migrations/        ← Alembic migrations
│       └── queries.py         ← queries frequentes
│
├── dashboard/                 ← interface Streamlit
│   ├── app.py                 ← entry point
│   ├── pages/
│   │   ├── 01_targets.py      ← gestão de alvos
│   │   ├── 02_findings.py     ← visualização de achados
│   │   ├── 03_programs.py     ← programas monitorados
│   │   ├── 04_templates.py    ← gestão de templates
│   │   └── 05_settings.py     ← configurações
│   └── components/            ← componentes reutilizáveis
│
└── tools/                     ← wrappers para ferramentas externas
    ├── nuclei_wrapper.py
    ├── subfinder_wrapper.py
    ├── httpx_wrapper.py
    ├── nmap_wrapper.py
    └── katana_wrapper.py
```

---

## STACK TECNOLÓGICA

### Backend / Engine
- **Python 3.12** — linguagem principal
- **Celery + Redis** — fila de tarefas assíncronas
- **SQLAlchemy + Alembic** — ORM e migrations
- **PostgreSQL** — banco principal (achados, alvos, histórico)
- **SQLite** — cache local de sessão de recon

### Dashboard
- **Streamlit** — UI principal (rápido, funcional, sem overhead de frontend)

### Dashboard / Streamlit

- `DASHBOARD_PASSWORD` deve ser verificado no início de `main()`, antes de renderizar sidebar ou páginas.
- Se `DASHBOARD_PASSWORD` estiver vazio, permitir acesso local e mostrar warning visual.
- Se `DASHBOARD_PASSWORD` estiver definido, exigir senha via `st.text_input(type="password")` e guardar autenticação em `st.session_state`.
- Sessões SQLAlchemy no Streamlit devem usar `with SessionLocal() as session:` em escopo estreito por operação.
- Evitar manter uma sessão aberta durante toda a renderização de uma página Streamlit.
- Listas que podem crescer, especialmente Findings, devem ter paginação.
- Paginação deve ser feita no banco com `LIMIT/OFFSET`; evitar `query.all()` seguido de slice em memória para listas grandes.
- Settings Page deve evitar sessão SQLAlchemy longa. Preferir funções pequenas com `with SessionLocal()`.
- Targets devem ter ações visíveis:
  - Start Recon
  - Re-scan rápido / nuclei only
- Botões de recon devem ser desabilitados quando `target.status` estiver em `recon_running` ou `analysis_running`.

### Ferramentas de Segurança (externas, chamadas via subprocess/wrapper)
- **subfinder** — enumeração de subdomínios
- **amass** — enumeração passiva/ativa de subdomínios
- **httpx** — probing HTTP massivo
- **nmap** — port scanning
- **katana** — crawling moderno
- **nuclei** — scanner de vulnerabilidades com templates
- **gowitness / aquatone** — screenshots automáticos
- **ffuf** — fuzzing de diretórios e parâmetros
- **gau** — coleta de URLs históricas (Wayback + CommonCrawl)

### IA / LLM
- **Anthropic Claude API** — análise contextual de achados, geração de templates, scoring
- Prompt engineering estruturado para classificação de vulnerabilidades

### Infraestrutura
- **Docker + Docker Compose** — isolamento e reprodutibilidade
- **Flower** — monitoramento de filas Celery (dev/ops)

---

## CONVENÇÕES DE CÓDIGO

### Python
- Type hints **obrigatórios** em todas as funções públicas
- Docstrings no padrão Google para funções complexas
- `black` para formatação, `ruff` para linting
- `pytest` para testes, cobertura mínima de 70% nos módulos core
- Exceções sempre logadas com contexto; nunca silenciadas

### Banco de Dados
- Migrations sempre via Alembic, nunca editar schema manualmente
- Nomes de tabelas no plural snake_case: `targets`, `findings`, `recon_results`
- Todo registro tem `created_at` e `updated_at`
- Findings têm estado explícito: `new` → `reviewing` → `valid` → `reported` → `closed`
- Finding deve ser deduplicado por `(target_id, template_id, url)` antes de inserir em re-scan.
- Re-scan não deve criar findings duplicados quando o mesmo template encontra a mesma URL novamente.
- `SystemSetting.value` pode conter secrets em plaintext no estado atual. Para uso local é aceitável temporariamente; para VPS, preferir env vars. Criptografia de settings sensíveis fica como backlog pós-operabilidade.

### Celery Tasks
- Tasks **idempotentes** sempre que possível
- Pipeline chain usa Celery Canvas `chain()` como objeto e `.apply_async()` na chain completa; não usar `link=` dentro de `.set()` (não é API válida)
- Recon recursivo dispara sub-tasks Celery assíncronas (`run_recursive_subdomain_enum.apply_async`) em vez de recursão direta; worker não bloqueia
- Falhas de ferramenta em loops são não-fatais: coletar erros, logar, continuar; só falhar a task se zero resultados válidos
- Deduplicação obrigatória antes de qualquer `session.add()` de ReconResult: checar existência por `(target_id, tool, result_type, data hash)` antes de inserir
- Re-scan sempre marca resultados anteriores com `superseded_by` antes de inserir novos
- Tasks longas divididas em sub-tasks encadeadas
- Retry com backoff exponencial em falhas de rede
- Resultados de recon nunca deletados, apenas marcados como superseded
- Tasks devem ser testáveis em modo eager (`CELERY_TASK_ALWAYS_EAGER=true`) sem Redis ativo; em runtime, Redis continua sendo o broker/result backend padrão.
- `run_ai_analysis` deve setar `target.status = "analysis_running"` imediatamente ao iniciar e commitar antes de processar findings.
- `run_ai_analysis(force_reanalyze=True)` deve reprocessar findings já classificados; `force_reanalyze` não deve apenas pular cache.
- `get_provider(session)` não deve ser chamado dentro do loop de cada finding. Resolver provider uma vez por execução de `run_ai_analysis`.
- `_get_redis()` também deve ser resolvido uma vez por execução de análise quando possível.
- `classify_finding()` deve aceitar provider/redis_client opcionais para evitar resolver provider/cache por finding.
- `run_ai_analysis()` deve resolver provider/cache uma vez por execução e repassar ao classificador.
- Tasks que colocam Target em estado running devem tratar exceções e evitar status preso para sempre.
- Estados de falha (`recon_failed`, `analysis_failed`) devem ser considerados antes da Fase 4.
- `run_dnsx_filter` deve retornar contrato consistente em todos os caminhos: `{target_id, tool, filtered, kept, skipped}`.
- Falhas de notificação Discord nunca propagam; são fire-and-forget com `structlog.warning`.

### Wrappers de Ferramentas
- Cada wrapper: `run(target, options) → ToolResult`
- `ToolResult` sempre tem: `success`, `raw_output`, `parsed_data`, `error`
- Timeout configurável por ferramenta
- Output salvo em disco antes de parsear (auditoria)
- `ToolResult` tem `raw_stdout` e `raw_stderr` separados; `raw_output` é mantido apenas para compatibilidade; `parse_output` opera sempre sobre `raw_stdout`
- Wrappers devem usar subprocess com lista de argumentos, nunca `shell=True`.
- GoWitnessWrapper deve ser compatível com a versão instalada no Dockerfile.worker.
- Se usar gowitness latest, testar a sintaxe real no container. Preferir fixar versão ou ajustar o comando para `gowitness scan single --url ... --screenshot-path ...` caso a versão instalada seja v3+.
- `filename` no ReconResult de screenshot pode ser `None`; consumidores devem tolerar isso.

### Deploy / Docker
- `docker-compose.yml` base não deve expor Postgres/Redis/Flower publicamente.
- Para desenvolvimento local, usar `docker-compose.local.yml` ou binds em `127.0.0.1`.
- Em VPS, dashboard deve ser acessado por Tailscale, SSH tunnel, Cloudflare Access ou proxy autenticado.
- Ferramentas Go no Dockerfile devem ter versões fixadas; evitar `@latest` em produção.

---

## MODELOS DE DADOS PRINCIPAIS

### Target
```
id, domain, scope_includes[], scope_excludes[], status,
platform, program_id, created_at, last_recon_at, recon_depth
```

### Finding
```
id, target_id, type, title, description, url, parameter,
severity (critical/high/medium/low/info),
confidence (confirmed/likely/possible/unlikely),
exploitation_difficulty (trivial/easy/medium/hard),
auto_score (0-100), status, template_id,
raw_evidence, screenshots[], created_at, reviewed_at
```

### ReconResult
```
id, target_id, tool, result_type, data (JSONB),
created_at, superseded_by
```

### BountyProgram
```
id, platform, program_handle, name, scope[], bounty_table,
auto_recon_enabled, last_checked_at, first_seen_at
```

---

## SISTEMA DE CLASSIFICAÇÃO DE FINDINGS

O sistema opera em dois modos, selecionados automaticamente:

### Modo Heurístico (sempre disponível)
- `core/analysis/classifier_base.py` — scoring por regras determinísticas
- Critérios: severidade do template, categoria nuclei, qualidade da evidência, contexto da URL
- Score resultante penalizado em 20% e confidence marcado como `"heuristic"`
- `confidence_note` no finding explica as limitações da classificação sem IA

### Modo IA (opcional, requer provider configurado)
- `core/analysis/classifier_ai.py` — enhancement via LLM
- Providers suportados: Anthropic Claude (padrão), OpenAI-compatible (qualquer endpoint), Ollama (local)
- Abstração em `core/analysis/provider.py`: todos os providers expõem `complete(prompt) → str`
- Se provider configurado mas indisponível: fallback automático para heurístico com log de warning
- Se IA disponível: score heurístico é substituído pelo score da IA; confidence = "ai:{provider}"

### Campos adicionados ao Finding
classifier_used: "heuristic" | "ai:anthropic" | "ai:openai" | "ai:ollama"
confidence_note: str  # explicação das limitações quando heurístico
ai_reasoning: str | None  # reasoning da IA quando disponível
ai_report_draft: str | None  # draft de report gerado pela IA

### Variáveis de ambiente para providers
AI_PROVIDER=anthropic|openai|ollama  # default: anthropic se ANTHROPIC_API_KEY presente
OPENAI_API_KEY=...
OPENAI_BASE_URL=...  # para qualquer API OpenAI-compatible
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

---

## SCORING DE FINDINGS

O sistema classifica cada achado com um score 0-100 baseado em:

| Critério | Peso |
|---|---|
| Tipo de vulnerabilidade (OWASP Top 10 = mais alto) | 30% |
| Confirmação de evidência (tem resposta diferencial?) | 25% |
| Contexto do alvo (prod vs staging, autenticado vs não) | 20% |
| Dificuldade de exploração | 15% |
| Histórico de falsos positivos do template | 10% |

Scores:
- **80-100**: Alto valor — priorizar validação manual imediata
- **60-79**: Médio valor — revisar em batch
- **40-59**: Possível — analisar quando houver tempo
- **<40**: Baixo — arquivo, apenas para referência

---

## PIPELINE DE RECON (FLUXO)

```
1. TARGET_INGESTED
   └→ 2. SUBDOMAIN_ENUM (subfinder + amass + passive sources)
         └→ 3. HTTP_PROBE (httpx — filtrar ativos)
               └→ 4. PORT_SCAN (nmap — portas principais)
                     └→ 5. WEB_CRAWL (katana + gau)
                           └→ 6. SCREENSHOT (gowitness)
                                 └→ 7. VULN_SCAN (nuclei — templates base)
                                       └→ 8. AI_ANALYSIS (claude — contexto + scoring)
                                             └→ 9. FINDINGS_CLASSIFIED
                                                   └→ [aguarda aprovação] → DEEP_SCAN (opcional)
```

Etapas 1-8 são **totalmente automáticas**.
Etapa 9 → pesquisador valida e decide o que reportar.

---

## MONITORAMENTO DE PLATAFORMAS

- Polling a cada **30 minutos** (configurável)
- Plataformas suportadas: HackerOne, Bugcrowd, Intigriti
- Quando novo programa detectado: dispara recon automático até etapa 8
- Deep scan (etapa 9+) só executa com **aprovação manual** no dashboard
- Novos programas ficam em `programs_pending_review` com destaque visual

---

## GESTÃO DE TEMPLATES NUCLEI

Três categorias:
1. **Built-in**: templates oficiais do nuclei (atualizados automaticamente)
2. **Custom**: templates criados/importados pelo usuário via dashboard
3. **AI-Generated**: templates gerados pelo Claude baseado em patterns de achados

Templates custom têm campos extras: `author`, `confidence_baseline`, `false_positive_rate`

---

## REGRAS PARA O AGENTE DE IA

Quando o Codex/Claude Code trabalhar neste projeto:

1. **Sempre consultar este arquivo primeiro** antes de qualquer implementação
2. **Nunca implementar features fora do escopo** sem atualizar CLAUDE.md
3. **Testes antes de features**: escrever test stub antes de implementar
4. **Um módulo por vez**: completar e testar antes de passar ao próximo
5. **Wrappers de ferramentas são contratos**: não mudar a interface sem atualizar todos os callers
6. **Banco imutável**: findings e recon_results nunca são deletados, apenas atualizados de estado
7. **Rate limiting nos wrappers**: respeitar limites das ferramentas e das APIs de plataformas
8. **Segurança primeiro**: inputs de usuário (targets, templates) sempre sanitizados antes de passar para subprocess
9. **Logs estruturados**: usar `structlog` com contexto (target_id, task_id, tool)
10. **Atualize este arquivo** quando uma decisão arquitetural for tomada
11. Nunca iniciar Fase 4 enquanto Fase 3.8 não estiver concluída.
12. Nunca expor dashboard sem DASHBOARD_PASSWORD em VPS.
13. Nunca expor Redis/Postgres/Flower publicamente por padrão.
14. Nunca inserir Finding sem checar duplicata por `(target_id, template_id, url)`.
15. Nunca chamar provider detection dentro do loop de cada finding.
16. Nunca quebrar o contrato de retorno de tasks; retornos devem ter shape estável.
17. Se um item for apenas documentação de dívida conhecida, não transformar em grande refactor sem aprovação.
18. Antes de implementar Fase 4, validar o pipeline real em `docs/current_pipeline.md`.

---

## FASES DE DESENVOLVIMENTO

### Fase 1 ✅ — Core + Pipeline Básico
### Fase 1.5 ✅ — Correções Estruturais
### Fase 2 ✅ — Recon Completo
### Fase 2.5 ✅ — Correções e Fundação para IA
### Fase 3 ✅ — Análise por IA
### Fase 3.5 ✅ — Hardening IA/providers/settings
### Fase 3.6 ✅ — Sincronização de docs e contratos
### Fase 3.7 ✅ — Operabilidade real + hardening mínimo
### Fase 3.8 ✅ — Auditoria pós-3.7 e preparação para Fase 4
### Fase 4 ✅ — Monitoramento de Plataformas (Grupos 1-4 concluídos)
### Fase 5 ⏳ — Dashboard Completo e Polish

---

## VARIÁVEIS DE AMBIENTE NECESSÁRIAS

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/bughunter
DB_PASSWORD=bughunter_dev

# Redis / Celery
REDIS_URL=redis://localhost:6379/0

# AI
AI_PROVIDER=anthropic|openai|ollama
ANTHROPIC_API_KEY=sk-...
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
AI_CACHE_TTL=86400

# Platforms
HACKERONE_API_TOKEN=...
HACKERONE_USERNAME=...
BUGCROWD_API_TOKEN=...
INTIGRITI_CLIENT_ID=...
INTIGRITI_CLIENT_SECRET=...

# Discord (optional)
DISCORD_WEBHOOK_URL=...

# Dashboard
DASHBOARD_PASSWORD=

# Storage
OUTPUT_DIR=/tmp/syshunt

# Settings
RECON_CONCURRENCY=10
NUCLEI_RATE_LIMIT=150
SCREENSHOT_TIMEOUT=30
MAX_RECON_DEPTH=2

# Safety
ALLOW_LOCAL_TARGETS=false
```

---

## DECISÕES ARQUITETURAIS REGISTRADAS

| Data | Decisão | Motivo |
|------|---------|--------|
| 2026-05-13 | Streamlit em vez de React/FastAPI | Velocidade de desenvolvimento; UI funcional suficiente para uso pessoal |
| 2026-05-13 | PostgreSQL como banco principal | JSONB para dados de recon não estruturados; melhor que MongoDB para queries analíticas |
| 2026-05-13 | Celery em vez de asyncio puro | Persistência de tasks, retry automático, visibilidade via Flower |
| 2026-05-13 | Wrappers subprocess em vez de libs Python | Ferramentas de segurança têm melhor suporte em CLI; easier to update |
| 2026-05-13 | Claude API para análise, não modelo local | Qualidade de análise contextual muito superior; custo aceitável por volume |
| 2026-05-13 | Estados internos de pipeline (`subdomain_enum_completed` etc) são opacos; o campo `status` do Target expõe apenas os estados da spec (`pending`, `recon_running`, `recon_done`, `ready_for_review`, `archived`) | Consistência entre spec, dashboard e filtros |
| 2026-05-13 | Lógica de queries (`list_targets`, `list_findings`, `create_target`) em `core/db/queries.py`, não em `dashboard/app.py` | Reutilização entre páginas do dashboard na Fase 2+ |
| 2026-05-13 | `ToolResult` expõe `raw_stdout` e `raw_stderr` separados; `raw_output` mantido como alias de `raw_stdout` para compatibilidade; `parse_output` recebe sempre `raw_stdout` | Evitar que stderr contamine parsing; auditoria em disco só grava stdout |
| 2026-05-13 | `insert_recon_results_with_dedup` em `core/db/queries.py` centraliza dedup por sha256 do JSON e supersessão de resultados antigos; todos os `session.add(ReconResult(...))` passam por essa função | Garantir imutabilidade do histórico (sem delete) e evitar duplicatas em re-scans |
| 2026-05-13 | `run_full_pipeline` usa `chain([task.si(target_id), ...]).apply_async()` (Canvas); `.set()` não aceita `link=` | API Celery correta; cadeia funciona em modo eager e em produção |
| 2026-05-13 | `ToolOptions.screenshot_dir` adicionado para GoWitnessWrapper; `output_path` continua sendo o caminho do arquivo de auditoria do stdout | Evitar conflito entre `output_path` (arquivo) e o diretório de screenshots do gowitness |
| 2026-05-13 | `run_http_probe` consulta `result_type='subdomain'` de qualquer tool (não apenas `tool='subfinder'`); aceita resultados do `recursive_recon` | Permitir que o recon recursivo popule subdomínios usados pelo probe HTTP sem duplicar lógica |
| 2026-05-13 | `core/recon/recursive.py` usa Redis set `syshunt:recon:{root_target_id}:processed` (TTL 24h) para evitar loops; todos resultados são armazenados sob `root_target_id` sem criar novos Target records para sub-subdomínios | Simplicidade: resultado unificado por alvo raiz; Redis best-effort (falha silenciosa pode gerar trabalho duplicado mas não loops) |
| 2026-05-13 | `bulk_create_targets` em `queries.py` usa `session.flush()` + rollback por IntegrityError para deduplicar sem abortar o batch inteiro | Permite importação CSV com duplicatas parciais sem falhar toda a operação |
| 2026-05-13 | `get_target_screenshot_paths` resolve caminhos de screenshots do filesystem em vez de ler o banco; path convention é `OUTPUT_DIR/screenshots/{target_id}/*.{png,jpg}` | Screenshots são artefatos de disco; o banco guarda só metadados (URL + dir relativo) |
| 2026-05-13 | Pipeline chain usa `chain([t1, t2, ...]).apply_async()` em vez de `link=` dentro de `.set()` | `.set()` não aceita `link=`; forma correta é Canvas chain |
| 2026-05-13 | Recon recursivo dispara tasks Celery assíncronas em vez de recursão direta | Evitar bloqueio de worker por horas em targets com muitos subdomínios |
| 2026-05-13 | Classificação heurística sempre disponível como fallback; IA é enhancement opcional | Sistema funcional sem API key; score e confidence refletem qual modo foi usado |
| 2026-05-13 | Abstração `AIProvider` suporta Anthropic, OpenAI-compatible e Ollama | Flexibilidade de usar modelo local ou trocar provider sem mudar o classificador |
| 2026-05-13 | Validação de domínio por regex em `normalize_domain` antes de qualquer operação | Rejeição limpa de inputs inválidos; evitar erros obscuros nas ferramentas |
| 2026-05-13 | Validação de scope em cada etapa do pipeline contra `scope_includes`/`scope_excludes` | Evitar scan out-of-scope, que é violação de regras de bug bounty |
| 2026-05-13 | `webcrawl` ReconResult inclui campo `source_tool` para preservar proveniência katana vs gau | URLs do katana (ativas) têm prioridade sobre gau (históricas) na análise |
| 2026-05-13 | Screenshot ReconResult inclui campo `filename` com o nome do arquivo gerado pelo gowitness | Permite relacionar screenshot específico com URL específica na análise da Fase 3 |
| 2026-05-13 | `run_port_scan` usa `urllib.parse.urlparse` para extrair hostname; cobre IPv6, portas não-padrão, paths | Substituição do `_extract_host` manual que falhava em URLs complexas |
| 2026-05-13 | `_data_hash` usa sha256 completo (sem `[:16]`); colisões de 16 chars causariam dedup incorreto em volumes altos | Integridade do hash em todos os re-scans |
| 2026-05-13 | `run_recursive_subdomain_enum` dispara `run_recursive_subdomain_enum_task.apply_async()` para cada sub-domínio; retorna `dispatched` em vez de `recursed` | Worker não bloqueia; função principal retorna imediatamente |
| 2026-05-13 | `DnsxWrapper.run()` sobrescreve o método base para passar a lista de subdomínios via stdin ao invés de argumento posicional | dnsx não aceita lista por argumento; stdin é o padrão da ferramenta |
| 2026-05-13 | `_parse_domains_from_csv` fallback sem header usa `split(",")[0]` de cada linha (primeira coluna); header inválido como domínio é rejeitado pela validação | Suporte a CSVs com múltiplas colunas mas sem coluna "domain" nomeada |
| 2026-05-13 | `run_dnsx_filter` cria um ReconResult marcador (`tool='dnsx'`, `result_type='dns_filter'`) e aponta `superseded_by` dos subdomínios não-resolvidos para esse marcador | Mantém imutabilidade do histórico sem precisar deletar; marcador é criado mesmo quando nenhum subdomain é filtrado (all-resolve) |
| 2026-05-13 | `run_ai_analysis` carrega API keys de `system_settings` via `get_setting` e as injeta em `os.environ` antes de chamar `get_provider()` | Permite que settings da UI tenham efeito imediato nas tasks, sem reiniciar workers |
| 2026-05-13 | Cache Redis de análises usa hash sha256 de `(finding.type + url + evidence[:500])` com TTL configurável via `AI_CACHE_TTL` env var (default 86400s); results em cache recebem sufixo `:cached` em `classifier_used` | Evita chamadas repetidas à API para findings idênticos (re-scan, importação CSV) |
| 2026-05-13 | `AIClassifier` faz duas chamadas ao provider: primeira para score/confidence/reasoning; segunda (somente se score ≥ 60) para geração do report draft | Segunda chamada é opcional e falha silenciosamente para não bloquear a classificação |
| 2026-05-13 | `SystemSetting(key PK, value TEXT, updated_at)` armazena configurações persistidas; API keys salvas no banco são carregadas em env pelo task; env vars são fallback quando setting ausente | Permite configuração via dashboard sem reiniciar o sistema; API keys nunca logadas |
| 2026-05-13 | `FindingScore` estendido com campos opcionais `ai_reasoning`, `ai_report_draft`, `severity`, `exploitation_difficulty` (default None) para compatibilidade com classificador heurístico existente | Heurístico usa apenas os quatro campos originais; IA preenche os adicionais quando disponíveis |
| 2026-05-13 | API keys do banco são injetadas diretamente no construtor do provider, nunca via `os.environ`; race condition em workers concorrentes | Workers Celery compartilham processo; mutação de env var é não thread-safe |
| 2026-05-13 | `run_ai_analysis` aceita `force_reanalyze=False`; quando `True`, ignora cache Redis e força nova chamada à IA | Necessário para botão "Re-analyze with AI" funcionar corretamente |
| 2026-05-14 | `AnthropicProvider(api_key=...)`, `OpenAICompatibleProvider(api_key=..., base_url=..., model=...)`, `OllamaProvider(base_url=..., model=...)` aceitam parâmetros no construtor; `get_provider(session=None)` lê keys do banco via `get_setting` quando session fornecida, sem mutar `os.environ` | Race condition em workers Celery concorrentes que compartilham processo |
| 2026-05-14 | `run_dnsx_filter` envolvido em try/except capturando `FileNotFoundError`, `RuntimeError` e `Exception` genérica; retorna `{"skipped": True}` sem propagar; `ValueError` ("Target not found") continua propagando | Task é sempre não-fatal; falha de dnsx não deve abortar a Canvas chain |
| 2026-05-14 | `set_setting` usa `session.merge()` + `session.flush()` para upsert true; evita `IntegrityError` mesmo com múltiplas chamadas na mesma sessão sem commit intermediário | `session.add()` falha se key já existe em sessão concorrente; `merge+flush` garante que identity map fica atualizado |
| 2026-05-14 | `Target.auto_analyze` (Boolean, default True) adicionado ao model; migration 20260513_0004; `run_nuclei_scan` verifica esse campo antes de disparar `run_ai_analysis` | Respeitar preferência do usuário definida na criação do target |
| 2026-05-14 | `classify_finding(finding, target, session, force_reanalyze=False)` — `force_reanalyze` passado de `run_ai_analysis` para `classify_finding`; quando True, `redis.get` é pulado mas `redis.setex` ainda executa após chamada à IA | Manter cache atualizado mesmo em re-análise forçada |
| 2026-05-14 | `template_generator` usa `yaml.safe_load()` + `_validate_nuclei_yaml()` antes de salvar; valida `id` (str não vazia), `info.name`, `info.severity`, e ao menos um de `requests/http/network`; levanta `ValueError` descritivo | Arquivos YAML inválidos quebram o nuclei silenciosamente |
| 2026-05-14 | `pyyaml>=6.0` adicionado como dependência obrigatória; `openai>=1.0` como opcional (`pip install syshunt[openai]`); `OpenAICompatibleProvider.complete()` levanta `ImportError` com mensagem clara se `openai` não instalado | Evitar instalar SDK OpenAI para quem usa só Anthropic ou Ollama |
| 2026-05-14 | `Dockerfile.worker` instala `dnsx` via go install, `chromium chromium-driver` via apt, e roda `nuclei -update-templates || true` no build | Pipeline completo requer essas ferramentas; sem elas etapas falham silenciosamente |
| 2026-05-13 | Target.auto_analyze (bool, default True) controla se run_ai_analysis é disparado automaticamente após nuclei | Respeitar preferência do usuário definida na criação do target |
| 2026-05-13 | Rate limiting entre chamadas de IA: `ai_call_delay_seconds` em system_settings (default 1); aplicado com time.sleep entre findings | Evitar TPM rate limit da Anthropic em targets com muitos findings |
| 2026-05-13 | template_generator usa yaml.safe_load() + validação de campos obrigatórios nuclei (id, info.name, info.severity, requests ou http) antes de salvar | Arquivos YAML inválidos quebram o nuclei silenciosamente |
| 2026-05-13 | `openai` adicionado como dependência opcional em pyproject.toml: `pip install syshunt[openai]`; ImportError em runtime se não instalado e provider=openai configurado | Evitar instalar SDK OpenAI para quem usa só Anthropic ou Ollama |
| 2026-05-13 | Dockerfile.worker instala dnsx, chromium e roda nuclei -update-templates no build | Pipeline completo requer essas ferramentas; sem elas etapas falham silenciosamente |
| 2026-05-15 | Fase 3.6 criada para sincronizar docs antes de mexer no código | Evitar que o agente trabalhe com specs antigas e reimplemente fases concluídas |
| 2026-05-15 | Fase 3.7 criada antes da Fase 4 | Monitoramento automático amplificaria bugs de operabilidade, escopo e notificação |
| 2026-05-15 | Dashboard exige `DASHBOARD_PASSWORD` antes de uso em VPS | Segurança mínima para não expor painel, targets, findings e API keys |
| 2026-05-15 | Start Recon e Re-scan rápido entram antes de monitoramento de plataformas | O sistema precisa ser operável manualmente antes de automação contínua |
| 2026-05-15 | `run_ai_analysis` usa `analysis_running` | Dashboard deve refletir análise longa em andamento |
| 2026-05-15 | Findings são deduplicados por `(target_id, template_id, url)` | Re-scans não devem duplicar achados idênticos |
| 2026-05-15 | `run_dnsx_filter` retorna shape estável | Evitar que consumidores quebrem em caminhos de erro diferentes |
| 2026-05-15 | Provider/Redis resolvidos uma vez por análise | Evitar overhead por finding, especialmente com Ollama |
| 2026-05-15 | Notificações Discord são fire-and-forget | Erro no webhook nunca pode derrubar pipeline |
| 2026-05-15 | `GoWitnessWrapper` usa sintaxe v3: `gowitness scan single --url ... --screenshot-path ...` | Dockerfile instala `@latest` que é v3+; sintaxe v2 (`gowitness single`) não existe mais |
| 2026-05-15 | `core/notifications.py` com `notify_recon_completed` e `notify_high_score_finding` integradas em `run_ai_analysis`; stubs para `notify_new_program`, `notify_scope_changed`, `notify_pipeline_error` | Stubs preparam a interface para Fase 4 sem bloquear operação atual |
| 2026-05-15 | `export_findings_csv` e `export_findings_markdown` em `core/db/queries.py`; dashboard usa `st.download_button` | Export de findings é requisito de operabilidade antes de monitoramento contínuo |
| 2026-05-15 | Fase 3.8 criada antes da Fase 4 | Corrigir docs quebradas, compose exposto, paginação em memória, provider por finding, Settings Page com sessão longa e ALLOW_LOCAL_TARGETS documentado mas não implementado |
| 2026-05-15 | `PlatformMonitor` ABC em `core/monitor/base.py`; `HackerOneMonitor` implementa via urllib.request (stdlib, sem nova dep) com Basic Auth; token nunca logado | Manter dependências mínimas; stdlib suficiente para chamadas REST simples |
| 2026-05-15 | `upsert_bounty_program` retorna `(program, is_new, added, removed)` — diff de `asset_identifier` entre scope antigo e novo; `first_seen_at` nunca sobrescrito | Permite detectar novo programa vs mudança de escopo num único passo |
| 2026-05-15 | Migration 0006 usa `create_index(..., unique=True)` em vez de `create_unique_constraint` | `create_unique_constraint` não é suportado em SQLite sem batch mode; unique index é equivalente em PostgreSQL |
| 2026-05-15 | `poll_hackerone` Celery task criada mas **não auto-agendada** via Beat; credenciais lidas de env; skip silencioso se ausentes | Auto-recon agressivo fica para fase posterior; task pode ser chamada manualmente ou agendada via Beat externamente |
| 2026-05-15 | `notify_new_program(program, session=None)` e `notify_scope_changed(program, added, removed, session=None)` — adicionado `session` opcional para consistência com outras notificações; flags `notify_new_program` e `notify_scope_changed` em system_settings | Consistência com o padrão fire-and-forget já estabelecido; flags permitem silenciar sem desabilitar webhook |
| 2026-05-15 | `BugcrowdMonitor` usa `Authorization: Token token=<api_token>` (sem username); handle em `attributes.code`; `uri` → `asset_identifier`; `category` → `asset_type`; targets com `in_scope=false` excluídos em `extract_scopes` | Diferenças de contrato em relação ao HackerOne; campo `in_scope` ausente trata como verdadeiro |
| 2026-05-15 | `IntigritiMonitor` usa OAuth2 Client Credentials: `_fetch_token()` via POST em `login.intigriti.com/connect/token`; token cacheado em instância; `_ensure_token()` renova 60s antes do vencimento; `_get()` tenta novamente em 401 invalidando e buscando novo token; API retorna arrays planos (não JSON:API); `endpoint` → `asset_identifier`; `type.value` → `asset_type`; `inScope=false` exclui domínio | client_secret e bearer token nunca aparecem em logs; token buscado uma vez por execução de `sync_programs` |
| 2026-05-15 | `poll_all_platforms()` chama as três tasks de plataforma como chamadas de função diretas (não `.apply_async()`), coletando resultados em sequência e retornando agregado `{platforms, total_new, total_scope_changed, total_errors}`; exceções por plataforma são capturadas individualmente | Chamadas síncronas são mais simples de testar e agregação de resultados é imediata; task Beat orquestra sem overhead de sub-tasks |
| 2026-05-15 | `trigger_recon_for_new_program(program_id)` carrega BountyProgram, filtra `auto_recon_enabled`, extrai domínios via `_domain_from_scope_identifier`, deduplicação por hostname, limita a `MAX_RECON_TARGETS_PER_PROGRAM` (default 10); busca Target existente antes de criar (evita IntegrityError); fallback para Target existente em race condition IntegrityError | auto_recon_disabled é opt-in; limite evita targets explosivos em programas com escopo amplo |
| 2026-05-15 | `_domain_from_scope_identifier(identifier)` usa `urlparse` para extrair hostname; strip de `*.` para wildcards; rejeita IPs via `ipaddress.ip_address()`; asset types não-web (`android`, `ios`, `cidr`, `executable`, etc.) filtrados em `trigger_recon_for_new_program` antes de chamar o helper | CIDRs são mapeados a IP via `urlparse` e rejeitados; filtro de asset_type evita tentar fazer recon de bundles móveis |
| 2026-05-15 | Celery Beat schedule configurado no módulo `scheduler.py` via `celery_app.conf.beat_schedule.update({...})` com intervalos por plataforma lidos de env vars: `HACKERONE_POLL_INTERVAL_SECONDS`, `BUGCROWD_POLL_INTERVAL_SECONDS`, `INTIGRITI_POLL_INTERVAL_SECONDS`; fallback `PLATFORM_POLL_INTERVAL_SECONDS`; default 1800 | Permite ajustar frequência de polling por plataforma sem deploy; 1800s (30min) é o intervalo padrão especificado na CLAUDE.md |
| 2026-05-15 | `BountyProgram.badge` (nullable string: `"new"`, `"scope_changed"`, `None`) e `BountyProgram.scope_history` (JSON array de `{timestamp, added, removed}`) adicionados via migration 0007; `upsert_bounty_program` seta `badge="new"` no insert, `badge="scope_changed"` em diff não-vazio sem rebaixar de `"new"`; `scope_history` é sempre substituído por nova lista (evita mutation não-detectada pelo SQLAlchemy) | Persistência de estado da UI independente de session_state; histórico imutável por polo |
| 2026-05-15 | `dismiss_program_badge(session, program_id)` e `set_program_auto_recon(session, program_id, enabled)` adicionados a `queries.py`; `get_bounty_program(session, program_id)` retorna por id | Funções atômicas com `session.flush()`; o caller faz `session.commit()` |
| 2026-05-15 | Dashboard Programs page reescrita com: métricas de topo (total/new/scope_changed), tabela overview, painel "Manage Program" com selectbox; botões Dismiss / Approve & Start Recon / Enable-Disable auto-recon; expandables para scope entries e scope history; trigger_recon importado lazy dentro do handler de botão | Streamlit rerun semântico: `st.rerun()` após cada mutação de estado; import lazy evita circular import |
