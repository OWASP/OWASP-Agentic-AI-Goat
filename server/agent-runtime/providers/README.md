# LangChain provider transport

Both existing AI services now use LangChain model classes. Ollama text generation
still uses `/api/generate`; native tool chat uses ChatOllama. OpenAI and Anthropic
use their LangChain chat models, Bedrock uses ChatBedrockConverse with the existing
AWS client/credentials, and LM Studio uses the OpenAI-compatible text interface.
Health/model-discovery requests retain existing HTTP logic. Public response shapes,
provider selection, and offline fallback remain at the existing service boundary.

Native tools are enabled for Ollama/OpenAI/Anthropic/Bedrock; actual support depends
on the configured model. Ollama 8B tool selection remains unreliable, so workshop
pre-interception and deterministic tool execution are unchanged. LM Studio retains
text-only behavior because arbitrary loaded models may not support tool calling.
Historical tool messages without IDs are paired in call order, preserving payload
bytes and original tool arguments. No tool executes inside the adapter itself.

One shared scheduler per provider endpoint bounds active transports (equivalent URL host casing, default ports and root-slash forms use the same budget): 2 local or 8
cloud by default, with 256 waiting requests. Configure `AI_OLLAMA_CONCURRENCY`,
`AI_OLLAMA_QUEUE_LIMIT`, `AI_OLLAMA_OWNER_QUEUE_LIMIT` and equivalent `AI_OPENAI_*`, `AI_ANTHROPIC_*`,
`AI_BEDROCK_*`, `AI_LMSTUDIO_*` before startup. Waiting owners rotate fairly using
trusted request context. Background calls share one owner; tests can inject
`ownerId`. Each owner may hold at most16 waiting calls by default; the owner cap accepts integer configuration1..2000 and does not count active transports. Cancellation of waiting work frees both quotas. These limits are per Node process and endpoint, not a distributed or measured throughput guarantee. Full global or owner queues reject with `AI_QUEUE_FULL`; aborted queued calls are removed.
A cancelled transport retains its active slot until it settles, preventing cancellation
from allowing excess physical requests. Caller deadlines bound waiting, but an SDK
that fails to terminate a request can retain its slot until its own transport ends.

Adapters create a model per invocation, avoid implicit SDK retries, preserve zero
temperature, and reject empty responses without tool calls. Ollama timing/token
metadata is collected from LangChain generation chunks; its optional legacy context
token array is not provided by the current LangChain integration. No application
callsite depends on that array.

Tests use injected models, actual OpenAI/Anthropic classes against localhost HTTP,
an injected Bedrock client, a 200-owner mock burst, and optional local llama3.1:8b.
No live paid-provider qualification or identical-prose claim is made. LangChain
requires no credentials itself; provider credentials remain in existing configuration.

Internal `snapshot()` also reports aggregate diagnostics since scheduler creation:
`accepted` counts admitted jobs (including immediately dispatched jobs); `rejected`
counts submissions denied before admission by an already-aborted signal or either
queue cap. `queuedCancelled` counts accepted jobs removed while waiting;
`preDispatchCancelled` counts accepted jobs cancelled after dequeue but before work
starts. `settled` counts invoked work that finished successfully or exceptionally,
including active work that later aborts, only after its transport promise settles.
Cancellation counters do not also increment `settled` when work never started.
`oldestQueuedAgeMs` is the nonnegative age of the oldest waiting job, zero for an
empty queue; active transports are excluded. The default clock is monotonic
`performance.now()`; tests can inject `now`. Snapshots contain no owner IDs,
request text or endpoint URLs and do not expose a new HTTP route. Counters are
process-local and reset on restart; they are not a throughput guarantee.
