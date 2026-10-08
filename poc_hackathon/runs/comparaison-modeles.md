# Comparaison de modèles — Huihui vs OBLITERATUS

_Généré le 2026-10-08T12:06:11 — source : `runs/bench-*/trace.jsonl` (événements `llm_call`)._


## Détail par modèle (toutes runs bench confondues)

| modèle | appels | tok_in | tok_out | lat min (s) | lat moy (s) | lat max (s) |
| --- | --- | --- | --- | --- | --- | --- |
| `OBLITERATUS/Qwen3.8-27B-OBLITERATED` | 4 | 1643 | 594 | 4.8 | 7.7 | 10.2 |
| `huihui-ai/Huihui-Qwen3.8-27B-abliterated` | 4 | 2148 | 7531 | 14.7 | 52.8 | 115.7 |

### Répartition par agent

| modèle | agent | appels | tok_in | tok_out | lat moy (s) |
| --- | --- | --- | --- | --- | --- |
| `OBLITERATUS/Qwen3.8-27B-OBLITERATED` | recon | 2 | 1364 | 484 | 9.0 |
| `OBLITERATUS/Qwen3.8-27B-OBLITERATED` | reporter | 2 | 279 | 110 | 6.5 |
| `huihui-ai/Huihui-Qwen3.8-27B-abliterated` | recon | 2 | 1444 | 6636 | 85.2 |
| `huihui-ai/Huihui-Qwen3.8-27B-abliterated` | reporter | 2 | 704 | 895 | 20.5 |

### Détail par run

| modèle | run | appels | tok_in | tok_out |
| --- | --- | --- | --- | --- |
| `OBLITERATUS/Qwen3.8-27B-OBLITERATED` | `bench-20261008-093444-single` | 2 | 876 | 378 |
| `OBLITERATUS/Qwen3.8-27B-OBLITERATED` | `bench-20261008-095139-crew` | 2 | 767 | 216 |
| `huihui-ai/Huihui-Qwen3.8-27B-abliterated` | `bench-20261008-082617-single` | 2 | 1078 | 4473 |
| `huihui-ai/Huihui-Qwen3.8-27B-abliterated` | `bench-20261008-084754-crew` | 2 | 1070 | 3058 |

## Benchmark — Huihui-Qwen3.8-27B-abliterated (baseline)

| run_id | mode | duration_s | llm_calls | tokens_in | tokens_out | tool_calls | confirmed_count | discarded_count | replans | errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 20261008-082618 | single | 1296.116 | 2 | 1078 | 4473 | 13 | 19 | 1 | 0 | 0 |
| 20261008-084754 | crew | 1058.469 | 2 | 1070 | 3058 | 18 | 18 | 1 | 1 | 0 |

## Qualité vs vérité terrain

| mode | précision | rappel | F1 |
| --- | --- | --- | --- |
| single | 0.40 | 0.67 | 0.50 |
| crew | 0.40 | 0.67 | 0.50 |


## Benchmark — OBLITERATUS/Qwen3.8-27B-OBLITERATED

| run_id | mode | duration_s | llm_calls | tokens_in | tokens_out | tool_calls | confirmed_count | discarded_count | replans | errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 20261008-093445 | single | 1014.088 | 2 | 876 | 378 | 7 | 10 | 3 | 0 | 0 |
| 20261008-095139 | crew | 359.79 | 2 | 767 | 216 | 5 | 3 | 0 | 1 | 0 |

## Qualité vs vérité terrain

| mode | précision | rappel | F1 |
| --- | --- | --- | --- |
| single | 0.50 | 0.67 | 0.57 |
| crew | 0.67 | 0.67 | 0.67 |
