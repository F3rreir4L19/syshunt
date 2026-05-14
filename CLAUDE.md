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

### Celery Tasks
- Tasks **idempotentes** sempre que possível
- Pipeline chain via `link=` no `apply_async()` da task anterior, nunca `chain().apply_async()` dentro de uma task
- Falhas de ferramenta em loops são não-fatais: coletar erros, logar, continuar; só falhar a task se zero resultados válidos
- Deduplicação obrigatória antes de qualquer `session.add()` de ReconResult: checar existência por `(target_id, tool, result_type, data hash)` antes de inserir
- Re-scan sempre marca resultados anteriores com `superseded_by` antes de inserir novos
- Tasks longas divididas em sub-tasks encadeadas
- Retry com backoff exponencial em falhas de rede
- Resultados de recon nunca deletados, apenas marcados como superseded
- Tasks devem ser testáveis em modo eager (`CELERY_TASK_ALWAYS_EAGER=true`) sem Redis
  ativo; em runtime, Redis continua sendo o broker/result backend padrão.

### Wrappers de Ferramentas
- Cada wrapper: `run(target, options) → ToolResult`
- `ToolResult` sempre tem: `success`, `raw_output`, `parsed_data`, `error`
- Timeout configurável por ferramenta
- Output salvo em disco antes de parsear (auditoria)
- `ToolResult` tem `raw_stdout` e `raw_stderr` separados; `raw_output` é mantido apenas para compatibilidade; `parse_output` opera sempre sobre `raw_stdout`

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

---

## FASES DE DESENVOLVIMENTO

### Fase 1 — Core + Pipeline Básico
- [ ] Setup do projeto (docker-compose, db, celery, redis)
- [ ] Modelos de dados + migrations iniciais
- [ ] Wrappers: subfinder, httpx, nuclei
- [ ] Pipeline básico: ingestion → subdomain → probe → nuclei
- [ ] Dashboard mínimo: injetar alvo, ver status, ver findings

### Fase 2 — Recon Completo
- [ ] Wrappers: amass, nmap, katana, gau, gowitness
- [ ] Recon recursivo (subdomínios de subdomínios até profundidade N)
- [ ] Screenshots no dashboard
- [ ] Filtros e deduplicação de findings

### Fase 3 — Análise por IA
- [ ] Integração Claude API para scoring contextual
- [ ] Classificação automática de findings
- [ ] Geração de templates nuclei via IA
- [ ] Relatório draft automático por finding

### Fase 4 — Monitoramento de Plataformas
- [ ] HackerOne API integration
- [ ] Bugcrowd API integration
- [ ] Scheduler de polling
- [ ] Notificações (Discord webhook)

### Fase 5 — Dashboard Completo
- [ ] Import CSV de alvos
- [ ] Gestão completa de templates
- [ ] Filtros avançados de findings
- [ ] Métricas e histórico
- [ ] Export para formato de report

---

## VARIÁVEIS DE AMBIENTE NECESSÁRIAS

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/bughunter

# Redis / Celery
REDIS_URL=redis://localhost:6379/0

# AI
ANTHROPIC_API_KEY=sk-...

# Platforms
HACKERONE_API_TOKEN=...
HACKERONE_USERNAME=...
BUGCROWD_API_TOKEN=...
INTIGRITI_CLIENT_ID=...
INTIGRITI_CLIENT_SECRET=...

# Discord (optional)
DISCORD_WEBHOOK_URL=...

# Settings
RECON_CONCURRENCY=10
NUCLEI_RATE_LIMIT=150
SCREENSHOT_TIMEOUT=30
MAX_RECON_DEPTH=2
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
