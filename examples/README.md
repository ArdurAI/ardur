# Ardur Examples

Working examples of Ardur governing AI agents across major frameworks and local
assistant surfaces. Some directories are runnable today; deferred directories
are marked as adapter specs, not shipped capability.

## Status

| Example | Status | Runtime dependency |
|---------|--------|-------------------|
| [missions/](missions/) | runnable | None — JSON files only |
| [langchain-quickstart/](langchain-quickstart/) | runnable | `python/` editable install + LangChain + an LLM provider |
| [langgraph-quickstart/](langgraph-quickstart/) | runnable | `python/` editable install + LangGraph + an LLM provider |
| [autogen-quickstart/](autogen-quickstart/) | runnable | `python/` editable install + AutoGen v0.4+ + an LLM provider |
| [ardur-personal-extension/](ardur-personal-extension/) | runnable adapter | local `ardur hub` + Chrome-compatible browser |
| [ardur-personal-desktop/](ardur-personal-desktop/) | runnable adapter | local `ardur hub` + macOS Accessibility permission for autodetect |
| [ardur-personal-native-host/](ardur-personal-native-host/) | optional bridge | local `ardur hub` + browser Native Messaging |
| [_shared/](_shared/) | helpers | Imported by the three framework demos above |
| [claude-code-hook/](claude-code-hook/) | pointer to runnable plugin | `python/` editable install + Claude Code |
| [openai-agents-sdk/](openai-agents-sdk/) | deferred adapter spec | `python/` editable install + OpenAI Agents SDK + OpenAI API key |
| [google-adk/](google-adk/) | deferred adapter spec | `python/` editable install + Google ADK + Google AI API key |
| [../plugins/claude-code/](../plugins/claude-code/) | runnable plugin | `python/` editable install + Claude Code |

The runnable framework directories (`langchain-quickstart/`, `langgraph-quickstart/`, `autogen-quickstart/`) ship a `demo.py` entrypoint and, where applicable, a `Dockerfile` that produces the published `rahulnutakki/ardur-demo:*` images. They share helpers under [`_shared/`](_shared/) — provider selection, SVID fetch, Biscuit issuance, governed-session setup, receipt-chain verification, end-of-session attestation. No model identifiers are hard-coded in any of these files; provider config is sourced from environment variables at runtime (see [CONTRIBUTING.md](../CONTRIBUTING.md) "No specific LLM model names" rule).

The deferred adapter directories carry READMEs that describe the dependency
footprint and file layout the next import wave will produce. They are not
advertised as runnable examples until code and tests land.

## Running the mission examples (today, no agent required)

```bash
cd ../python
pip install -e .

# Issue and verify a passport. ardur issue takes mission claims via flags,
# not a JSON file — the example mission files under missions/ are reference
# documents for the spec layer. To exercise the protocol path:
ardur issue \
  --agent-id alice \
  --mission "summarize sales from sales/q1.csv into reports/" \
  --allowed-tools read_file write_report \
  --resource-scope 'sales/*' 'reports/*'

ardur verify --token <token-from-issue-output>
```

That exercises the core protocol surface end-to-end — mission compilation, passport issuance, signature, verification — without an LLM or framework in the loop. It's the fastest way to confirm a local install actually works.

## Why deferred adapters instead of one big drop

Each framework has its own tool-call interface, its own session-state model, and its own integration point where Ardur's governance proxy attaches. LangChain tool callbacks look nothing like AutoGen's `FunctionTool` registration; LangGraph's state graph wants the verifier wrapped around node transitions; the coding-agent CLI integration wires in via a hook lifecycle, not a Python import. Lifting these as one monolithic commit would conflate unrelated breakage. Per-framework directories let each adapter land, get reviewed, and run CI on its own.

## CI for examples

The current CI surface is the repo-wide Python and Go workflow in
`.github/workflows/tests.yml`, plus CodeQL, link-check, secret-scan, format
validation, and the Hugo site build. The Python job runs
`python/tests/test_examples_smoke.py` as an offline, no-key examples smoke for
the checked-in mission fixtures and this claim ledger. There is not a dedicated
`.github/workflows/examples-smoke.yml` today, and the provider-backed framework
quickstarts remain opt-in/manual unless a future workflow adds real CI evidence
for those live-provider demos.
