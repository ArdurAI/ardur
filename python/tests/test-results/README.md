# Ardur Cloud Model Governance Tests

Real-world governance tests: cloud LLMs build a full Code Repository Manager
while every tool call flows through the Ardur proxy (evaluate -> attest -> receipt).

## How to read these results

Each JSON file is a test run for one model. Key metrics:

| Field | Meaning |
|-------|---------|
| `model` | Which model was tested |
| `total_elapsed_s` | Wall-clock duration of the 30-turn run |
| `tool_calls_total` | Number of tool calls evaluated through proxy |
| `files_created` | How many of the 20 planned files were written |
| `phases` | Phase transitions (when the model hit each file-count milestone) |
| `errors` | Any denials or exceptions (empty = clean run) |

A clean run = zero denials, zero exceptions, all tool calls PERMIT.

## Running a test

```bash
ARDUR_OLLAMA_API_KEY="<key>" python tests/run_cloud_model_test.py <model_name>
```

Results land here as `<model_safe_name>.json`.

## Running all models

```bash
ARDUR_OLLAMA_API_KEY="<key>" python tests/run_all_models.py
```

Reads available models from Ollama, runs each, writes a comparison summary.
