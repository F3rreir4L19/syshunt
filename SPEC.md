# SPEC.md — BugHunter: Especificação Funcional

> Documento de requisitos funcionais e comportamentos esperados do sistema.
> Atualizado conforme o projeto evolui. Leia junto com CLAUDE.md.

---

## 1. GESTÃO DE ALVOS

### 1.1 Injeção Manual
- Usuário digita um domínio (ex: `example.com`) no dashboard
- Sistema valida formato do domínio antes de aceitar
- Usuário pode definir opcionalmente:
  - `scope_includes`: lista de padrões a incluir (ex: `*.example.com`, `api.example.com`)
  - `scope_excludes`: lista de padrões a excluir (ex: `blog.example.com`)
  - `platform`: HackerOne / Bugcrowd / Intigriti / Privado
  - `program_id`: ID do programa na plataforma (para tracking)
  - `recon_depth`: profundidade de enumeração recursiva (1-3, default: 2)
  - `auto_analyze`: se deve rodar análise IA automaticamente após recon (default: true)

### 1.2 Injeção por CSV
Formato esperado do CSV:
```csv
domain,scope_includes,scope_excludes,platform,program_id,recon_depth
example.com,"*.example.com","blog.example.com",hackerone,h1-example,2
target2.com,"","staging.*",bugcrowd,bc-target2,1
```
- Colunas obrigatórias: `domain`
- Colunas opcionais: todas as demais com defaults
- Validação linha a linha com relatório de erros antes de importar
- Importação em batch com confirmação do usuário

### 1.3 Estados de um Alvo
```
pending → recon_running → recon_done → analysis_running → ready_for_review → archived
```
- `pending`: alvo adicionado, aguardando execução
- `recon_running`: pipeline de recon em execução (com etapa atual visível)
- `recon_done`: recon concluído, aguardando análise
- `analysis_running`: análise de IA em execução
- `ready_for_review`: tudo concluído, findings aguardando revisão do pesquisador
- `archived`: alvo inativo

### 1.4 Re-scan
- Usuário pode solicitar re-scan a qualquer momento
- Re-scan preserva histórico anterior (resultados marcados como `superseded`)
- Re-scan incremental: opção de rodar só nuclei sem refazer o recon completo

---

## 2. PIPELINE DE RECON

### 2.1 Etapa 1: Enumeração de Subdomínios
**Ferramentas**: subfinder, amass (passive mode)
**Input**: domínio raiz
**Output**: lista de subdomínios únicos
**Comportamento**:
- Roda subfinder e amass em paralelo
- Deduplica resultados
- Salva todos no banco como `recon_results` (tipo: `subdomain`)
- Inclui fonte (subfinder/amass/ambos) para cada subdomínio

### 2.2 Etapa 2: HTTP Probe
**Ferramenta**: httpx
**Input**: lista de subdomínios
**Output**: hosts ativos com metadados HTTP
**Comportamento**:
- Detecta HTTP e HTTPS
- Captura: status code, título da página, tecnologias (via headers), redirect chain
- Filtra apenas hosts que respondem (200, 301, 302, 403, 401, 500)
- Marca como `interesting` hosts com 401/403 (potencial bypass)

### 2.3 Etapa 3: Port Scan
**Ferramenta**: nmap
**Input**: IPs dos hosts ativos
**Output**: portas abertas e serviços
**Comportamento**:
- Scan nas top-1000 portas (configurável)
- Detecta serviços e versões nas portas abertas
- Foca em portas não-padrão (não-80/443) como pontos de interesse
- Salva fingerprint de serviço para análise posterior

### 2.4 Etapa 4: Web Crawling
**Ferramentas**: katana, gau
**Input**: URLs ativas (HTTP 200)
**Output**: URLs coletadas, endpoints, parâmetros
**Comportamento**:
- katana: crawling ativo (segue links, extrai JS)
- gau: coleta histórica (Wayback Machine + CommonCrawl)
- Deduplica URLs por path (ignora variações de query string similares)
- Extrai e salva: forms, endpoints de API, parâmetros GET/POST, caminhos interessantes

### 2.5 Etapa 5: Screenshots
**Ferramenta**: gowitness
**Input**: URLs ativas
**Output**: screenshots + hashes para deduplicação
**Comportamento**:
- Captura screenshot de cada host ativo
- Armazena path do arquivo no banco
- Exibe no dashboard na aba do alvo

### 2.6 Etapa 6: Vulnerability Scan
**Ferramenta**: nuclei
**Input**: URLs e hosts coletados
**Output**: findings brutos
**Comportamento**:
- Roda templates: `cves`, `exposures`, `misconfiguration`, `technologies`, `vulnerabilities`
- Inclui templates customizados do usuário
- Rate limiting configurável (default: 150 req/s)
- Cada achado do nuclei vira um `finding` no banco com status `new`
- Salva output raw + parsed

### 2.7 Recon Recursivo
- Para cada novo subdomínio encontrado em etapas anteriores que não estava na lista original:
  - Se `recon_depth > 1`: rodar etapas 1-5 nesse subdomínio também
  - Decrementa profundidade a cada nível
  - Evita loops (tracking de domínios já processados na sessão)
  - Status do target durante todo o pipeline recursivo permanece `recon_running`; só transita para `recon_done` quando todas as profundidades estiverem completas


### 2.8 Re-scan e Deduplicação
- Re-scan marca todos os `ReconResult` anteriores do target com `superseded_by = <novo_recon_result_id>` antes de inserir novos resultados
- Findings existentes **não** são deletados nem superseded; o re-scan pode gerar findings adicionais, nunca remover os anteriores
- Deduplicação de subdomínios é feita antes de persistir: se o mesmo valor já existe como `ReconResult` ativo (sem `superseded_by`) para o target, não insere duplicata
- Falhas individuais de ferramenta durante loop (ex: um subdomínio de 50 dando timeout) são logadas como `structlog.warning` com contexto `{target_id, tool, failed_item}` mas não abortam a task; a task só falha se *todos* os itens falharem

---

## 3. ANÁLISE POR IA

### 3.0 Classificação Heurística (Baseline)

O sistema possui um classificador heurístico que opera **sem dependência de IA**,
sempre disponível como baseline. Quando nenhum provider de IA está configurado ou
disponível, todos os findings são classificados por este sistema.

**Critérios de score (soma máxima = 80 antes da penalização):**

| Critério | Pontos |
|----------|--------|
| Severidade: critical | +40 |
| Severidade: high | +30 |
| Severidade: medium | +15 |
| Severidade: low | +5 |
| Categoria: cve | +20 |
| Categoria: exposure | +15 |
| Categoria: misconfiguration | +10 |
| Evidência: matched-at presente | +10 |
| Evidência: request/response diff no raw_evidence | +15 |
| Contexto URL: /admin, /manage, /console | +8 |
| Contexto URL: /api, /v1, /v2 | +5 |
| Contexto URL: staging, dev, test (subdomain) | −10 |

**Penalização por modo heurístico:** score final × 0.8

**Campos preenchidos:**
- `auto_score`: score calculado (já com penalização)
- `classifier_used`: `"heuristic"`
- `confidence`: `"possible"` (teto máximo sem IA)
- `confidence_note`: string explicando que a classificação é heurística e pode ter alta taxa de falso positivo

### 3.1 Scoring por IA (Enhancement)

Quando um provider de IA está configurado e disponível, o classificador heurístico
é substituído pela análise contextual via LLM. O score heurístico não é usado como
input para a IA — a IA recebe os dados brutos e produz seu próprio score independente.

**Providers suportados:**
- **Anthropic Claude** — padrão quando `ANTHROPIC_API_KEY` presente
- **OpenAI-compatible** — qualquer endpoint compatível (OpenAI, Groq, Together, etc.) via `OPENAI_API_KEY` + `OPENAI_BASE_URL`
- **Ollama** — modelos locais via `OLLAMA_BASE_URL` + `OLLAMA_MODEL`

Seleção automática: `AI_PROVIDER` env var; se ausente, detecta pelo primeiro API key presente
na ordem: Anthropic → OpenAI → Ollama. Se nenhum estiver disponível, o sistema cai
automaticamente no classificador heurístico da seção 3.0 com log de warning.

**Input enviado para a IA (por finding):**
- Tipo de vulnerabilidade detectada
- URL/endpoint afetado
- Evidência bruta (response diff, payload, matched-at)
- Contexto do alvo (tecnologias detectadas via httpx, prod vs staging inferido pela URL)
- Template nuclei que gerou o finding (ID + categoria)

**Formato de resposta esperado (JSON estrito):**
```json
{
  "score": 75,
  "confidence": "likely",
  "exploitation_difficulty": "medium",
  "severity": "high",
  "reasoning": "Endpoint expõe painel administrativo sem autenticação em ambiente de produção...",
  "false_positive_risk": "low",
  "suggested_next_steps": [
    "Verificar se o acesso é realmente irrestrito sem cookies de sessão válidos",
    "Testar com User-Agent padrão de browser"
  ]
}
```

Valores válidos por campo:
- `score`: inteiro 0–100
- `confidence`: `"confirmed"` | `"likely"` | `"possible"` | `"unlikely"`
- `exploitation_difficulty`: `"trivial"` | `"easy"` | `"medium"` | `"hard"`
- `severity`: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`
- `false_positive_risk`: `"low"` | `"medium"` | `"high"`

**Campos preenchidos no Finding após análise por IA:**
- `auto_score`: score retornado pela IA (0–100, sem penalização)
- `confidence`: valor retornado pela IA
- `exploitation_difficulty`: valor retornado pela IA
- `severity`: valor retornado pela IA (pode sobrescrever o do nuclei)
- `classifier_used`: `"ai:anthropic"` | `"ai:openai"` | `"ai:ollama"`
- `confidence_note`: vazio quando classificado por IA
- `ai_reasoning`: campo `reasoning` retornado pela IA
- `ai_report_draft`: draft de report gerado (somente para score ≥ 60; ver seção 3.2)

**Comportamento em caso de falha do provider:**
- Timeout ou erro de API → logar `structlog.warning` com provider e erro
- Fallback automático para classificador heurístico da seção 3.0
- `classifier_used` registra `"heuristic"` mesmo que o provider estivesse configurado
- Finding não fica bloqueado aguardando retry da IA; retry pode ser disparado manualmente
  pelo pesquisador no dashboard

### 3.2 Geração de Relatório Draft
Para findings com score ≥ 60, Claude gera um draft de report no formato padrão HackerOne/Bugcrowd:
- Título
- Descrição
- Steps to reproduce
- Impact
- Severidade recomendada
- CVSS sugerido

### 3.3 Geração de Templates Nuclei
Usuário pode pedir ao sistema para gerar um template nuclei baseado em:
- Descrição em linguagem natural de uma vulnerabilidade
- Exemplo de request/response de uma vuln encontrada manualmente
- Padrão de um finding existente para generalizar

---

## 4. MONITORAMENTO DE PLATAFORMAS

### 4.1 HackerOne
- API: `https://api.hackerone.com/v1/hackers/programs`
- Polling a cada 30 minutos (configurável)
- Detecta novos programas pelo campo `launched_at`
- Extrai escopo da seção `structured_scopes`
- Filtra programas com bounty (não só VDP)

### 4.2 Bugcrowd
- API privada (requer credenciais)
- Polling similar ao HackerOne
- Detecta novos programas e mudanças de escopo

### 4.3 Intigriti
- OAuth2 + API REST
- Polling similar

### 4.4 Fluxo ao Detectar Novo Programa
1. Programa salvo em `bounty_programs` com status `new`
2. Destacado no dashboard (badge "NEW")
3. Recon automático disparado automaticamente (etapas 1-6)
4. **Deep scan (análise IA) não roda automaticamente** — usuário confirma no dashboard
5. Notificação via Discord webhook (opcional)

### 4.5 Mudanças de Escopo
- Sistema detecta quando escopo de programa existente muda
- Novos domínios adicionados ao escopo: dispara recon automático nos novos domínios
- Domínios removidos do escopo: marca targets relacionados como `out_of_scope`

---

## 5. DASHBOARD — PÁGINAS E FUNCIONALIDADES

### 5.1 Página: Targets
- Tabela de todos os alvos com: domínio, status, #subdomínios, #findings, última execução
- Botão "Add Target" (formulário inline)
- Botão "Import CSV"
- Por alvo: botão "Re-scan", "View Findings", "Archive"
- Status com indicador visual (cor + ícone)
- Filtros: por status, por plataforma, por data

### 5.2 Página: Findings
- Tabela principal com todos os achados
- Colunas: alvo, tipo, severidade, score, confidence, status, data
- Filtros avançados:
  - Por alvo / domínio
  - Por severidade (critical/high/medium/low)
  - Por status (new/reviewing/valid/reported/closed)
  - Por score (slider 0-100)
  - Por tipo de vulnerabilidade
  - Por data
- Click em finding: painel lateral com detalhes completos
  - Evidência bruta
  - Screenshot (se disponível)
  - Análise da IA (reasoning, suggested steps)
  - Draft de report
  - Botões de ação: "Mark Valid", "Mark False Positive", "Export Report"
- Agrupamento por alvo ou por tipo (toggle)

### 5.3 Página: Programs
- Lista de programas monitorados por plataforma
- Status: ativo/pausado, data de início, bounty range
- Badge "NEW" para programas recém detectados
- Badge "SCOPE CHANGED" para mudanças recentes
- Por programa: botão "Start Recon", "Enable/Disable Auto-Recon"
- Tabela de escopo do programa

### 5.4 Página: Templates
- Lista de todos os templates nuclei (built-in + custom + AI-generated)
- Filtros por: categoria, severidade, fonte
- Botão "New Template" (editor YAML inline)
- Botão "Generate with AI" (input de descrição, Claude gera o YAML)
- Import de arquivo `.yaml` externo
- Por template: taxa de false positive baseada em histórico de uso

### 5.5 Página: Settings
- **API Keys**: Anthropic, HackerOne, Bugcrowd, Intigriti, Discord
- **Recon Defaults**: profundidade default, concorrência, rate limits
- **Nuclei Settings**: rate limit, templates habilitados/desabilitados
- **Monitoring**: intervalo de polling por plataforma, enable/disable por plataforma
- **Notifications**: webhook Discord, tipos de eventos para notificar
- **Storage**: caminho dos outputs, política de retenção

---

## 6. NOTIFICAÇÕES

Eventos que geram notificação Discord:
- Novo programa detectado em plataforma monitorada
- Recon concluído em alvo
- Finding com score ≥ 80 encontrado
- Mudança de escopo em programa ativo
- Erro crítico em pipeline

Formato da mensagem Discord:
```
🔴 [HIGH CONFIDENCE FINDING]
Target: api.example.com
Type: SQL Injection
Score: 87/100
URL: https://api.example.com/users?id=1
→ View in Dashboard: http://localhost:8501/findings?id=xxx
```

---

## 7. SEGURANÇA DO PRÓPRIO SISTEMA

- Inputs de domínio validados com regex antes de qualquer operação
- Comandos subprocess construídos com listas (nunca interpolação de string)
- API keys jamais logadas
- Outputs de ferramentas em diretório isolado com permissões restritas
- Dashboard sem autenticação por padrão (uso local) — mas com opção de senha via env var
- Rate limiting nas chamadas à Claude API para evitar custos inesperados

---

## 8. MÉTRICAS E HISTÓRICO

Sistema mantém:
- Tempo médio de recon por alvo
- Taxa de findings por alvo (total / por severidade)
- Taxa de false positives por template
- Score médio de findings ao longo do tempo
- Programas com maior densidade de findings

Exibição: página de dashboard com gráficos simples (Streamlit native charts)

---

## GLOSSÁRIO

| Termo | Definição |
|-------|-----------|
| Target | Domínio/organização sendo testado |
| Finding | Potencial vulnerabilidade encontrada pelo sistema |
| Recon | Fase de reconhecimento (coleta de informações) |
| Scope | Ativos autorizados para teste no programa de bug bounty |
| Template | Arquivo YAML do nuclei definindo um padrão de vulnerabilidade |
| Score | Pontuação 0-100 indicando valor/confiança do finding |
| VDP | Vulnerability Disclosure Program (sem pagamento) |
| Deep Scan | Análise mais profunda que requer aprovação manual |
