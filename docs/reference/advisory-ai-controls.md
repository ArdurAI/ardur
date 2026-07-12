# Advisory AI Controls

Ardur contains two experimental Python library surfaces that use model-backed
signals: `semantic_judge.py` and `behavioral_fingerprint.py`. They are not wired into `python/vibap/proxy.py`, the CLI, Personal Hub, or receipt verification.
Their results are not an authoritative governance verdict.

This is the current implementation boundary, not a promise that advisory
controls can never become gates. Any future integration must change the source,
tests, public documentation, and evidence model together.

## Semantic judge

`judge_from_env()` returns:

- `NullJudge` when `ARDUR_SEMANTIC_JUDGE` is unset or is not `anthropic`; its
  result is `UNSURE`;
- `AnthropicJudge` when `ARDUR_SEMANTIC_JUDGE=anthropic`, a model is configured,
  the optional SDK is installed, and credentials are available.

Every exception inside `AnthropicJudge.evaluate()` is logged and converted to
`UNSURE`. Parse failures also become `UNSURE`. `PERMIT`, `DENY`, and `UNSURE`
remain advisory analysis labels: the module cannot mutate the reference
proxy's structural `Decision`.

Setting the environment variable does not make the proxy call the factory or
the judge. A custom caller must invoke it explicitly.

## Behavioral fingerprint

`ARDUR_BEHAVIORAL_FINGERPRINT=anthropic` only permits construction of
`AnthropicChallenger`; it does not activate a reference-proxy session gate.
The library helper `enforce_fingerprint()` has this policy contract:

| Raw challenger result | Default `policy="fail_open"` | `policy="fail_closed"` |
|---|---|---|
| `OK` | `OK` | `OK` |
| `FAIL` | `FAIL` | `FAIL` |
| `UNSURE` | `OK`, with `raw=UNSURE` preserved in the reason | `FAIL` |

The fail-open default does not ignore a definite mismatch. It permits only
uncertainty such as a provider error. The `fail_closed` option is a Python
function argument, not a CLI flag or environment variable.

## Operator posture

Do not describe either module as an Ardur enforcement control in the current
release. An operator-owned integration that makes behavioral fingerprinting a
gate should, at minimum:

1. pass `policy="fail_closed"` for high-assurance actions;
2. define the known failure state and the availability trade-off for provider
   timeouts, quota exhaustion, SDK errors, and malformed responses;
3. keep the authoritative structural proxy decision separate from the advisory
   model output;
4. record raw versus policy-adjusted status without storing prompts, secrets,
   or unredacted model responses;
5. monitor `UNSURE`, exception, timeout, and rejection rates; and
6. test outage, latency, malformed-output, and calibration behavior under
   deployment-like conditions before making a security claim.

For gradual experiments, the default fail-open policy avoids turning a remote
advisor outage into a session outage. For a real authorization boundary, that
same behavior is insufficient: the caller must deliberately select and test a
known failure state. This follows the risk-based framing in
[NIST SP 800-53 Rev. 5.1, SC-24](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final),
which makes the safe state organization- and mission-defined, and the
[NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/),
which calls for documented scope, uncertainty, deployment-relevant evaluation,
and production monitoring.

## Cost and reliability

The provider-backed implementations introduce network latency, provider API
cost, quota and credential dependencies, and a new external data boundary.
There is no live-provider CI test and no production SLO for either module.
Provider pricing and model availability change independently of Ardur; estimate
cost from the chosen provider/model and expected challenge or tool-call volume
before enabling a custom integration.

No API key is required for the authoritative Ardur governance path or for the
provider-free test suite.
