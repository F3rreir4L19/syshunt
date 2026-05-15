# Current Pipeline — Syshunt (post Phase 3.8)

> Validated 2026-05-15. Reflects what is actually implemented and wired,
> not the long-term spec.

---

## Main Pipeline (Celery Canvas chain)

```
run_full_pipeline(target_id)
  └→ [sets target.status = "recon_running"]
  └→ chain(
       run_subdomain_enum       ← subfinder only
       run_dnsx_filter          ← dnsx (non-fatal; skips silently if not installed)
       run_http_probe           ← httpx
       run_port_scan            ← nmap
       run_web_crawl            ← katana + gau (historical URLs)
       run_screenshot           ← gowitness v3 (scan single syntax)
       run_nuclei_scan          ← nuclei; sets target.status = "recon_done"
                                   dispatches run_ai_analysis.apply_async() if auto_analyze=True
     ).apply_async()

run_ai_analysis(target_id)
  └→ [sets target.status = "analysis_running"]
  └→ classify_finding() per finding (heuristic always; AI if provider configured)
  └→ [sets target.status = "ready_for_review" on success]
  └→ [sets target.status = "analysis_failed" on unhandled error]
  └→ notify_recon_completed() + notify_high_score_finding() (Discord, fire-and-forget)
```

## Quick Re-scan (skip_recon=True)

```
run_full_pipeline(target_id, skip_recon=True)
  └→ [sets target.status = "recon_running"]
  └→ run_nuclei_scan.apply_async(args=[target_id])
     (uses existing httpx results; skips subdomain/dns/probe/port/crawl/screenshot)
```

---

## What is NOT in the main pipeline

| Tool / Feature          | Status                                      |
|-------------------------|---------------------------------------------|
| **amass**               | Not wired. Wrapper does not exist. Only subfinder runs in main pipeline. Recursive recon uses subfinder internally. |
| **ffuf**                | Wrapper exists (`tools/ffuf_wrapper.py`) but no Celery task and no pipeline step. Backlog. |
| **Recursive recon**     | `run_recursive_subdomain_enum` exists in `core/recon/recursive.py` and `run_recursive_subdomain_enum_task` Celery task exists. However, it is **not auto-triggered** from the main pipeline. It must be called manually. |
| **Deep scan**           | Not implemented. Spec describes it as post-approval; no code yet. |
| **Platform monitoring** | Not implemented (Phase 4). |

---

## Failure states

| Condition                              | Target status after      |
|----------------------------------------|--------------------------|
| `run_full_pipeline` dispatch error     | `recon_failed`           |
| Any unhandled error in `run_ai_analysis` | `analysis_failed`      |
| Individual task tool failure (non-fatal) | previous status unchanged (tool skipped) |

Pipeline errors are reported to Discord via `notify_pipeline_error` (fire-and-forget).

---

## AI Classification

- **Heuristic** (always available): `core/analysis/classifier_base.py` — rule-based scoring, score penalized 20%, `confidence_note` added.
- **AI** (optional): Anthropic, OpenAI-compatible, or Ollama. Configured via system_settings or env vars.
- Provider and Redis client are resolved **once per `run_ai_analysis` execution**, not per finding.
- Redis cache key: sha256 of `(finding.type + url + evidence[:500])`, TTL = `AI_CACHE_TTL` (default 86400s).
- `force_reanalyze=True` bypasses Redis read but still writes updated result to cache.

---

## Notifications (Discord)

| Event                    | Flag                       | Implemented |
|--------------------------|----------------------------|-------------|
| Recon completed          | `notify_recon_done`        | Yes         |
| High-score finding (≥80) | `notify_high_score_finding`| Yes         |
| Pipeline error           | `notify_pipeline_error`    | Yes         |
| New program              | —                          | Stub (Phase 4) |
| Scope changed            | —                          | Stub (Phase 4) |

---

## Deduplication

- **Findings**: deduplicated by `(target_id, template_id, url)` before insert. Re-scans do not create duplicate findings.
- **ReconResults**: deduplicated by sha256 of JSON data. Old results are marked `superseded_by` on re-scan (never deleted).

---

## Status machine

```
pending
  → recon_running        (set by run_full_pipeline on dispatch)
      → recon_failed     (set by run_full_pipeline on dispatch error)
      → recon_done       (set by run_nuclei_scan on completion)
          → analysis_running   (set by run_ai_analysis on start)
              → analysis_failed    (set by run_ai_analysis on error)
              → ready_for_review   (set by run_ai_analysis on success)
  → archived             (manual, via dashboard)
```
