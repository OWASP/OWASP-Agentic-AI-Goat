# Inspect agent decisions with LangSmith

LangGraph runs the agent workflow; LangChain connects it to the configured model. LangSmith records traces so you can inspect the steps, model messages, tool arguments, responses, timing, and errors.

Tracing is optional and disabled by default. Local LangChain, LangGraph, and Ollama do not need a LangSmith account or key. Enabling hosted tracing sends recorded inputs and outputs to LangSmith, including lab prompts and tool results. Use synthetic data and keep the API key private.

## Configure tracing

1. Sign in to [LangSmith](https://smith.langchain.com/) and create an API key in Settings. Select the workspace where you want to keep the traces.
2. Choose a tracing project, such as `owasp-agentic-ai-goat-local`.
3. Edit the installation's existing private `.env`, accessed through `.env` in the repository root. Preserve the file or symlink created by setup. Update existing entries instead of adding duplicates:

   ```dotenv
   LANGSMITH_TRACING=true
   LANGSMITH_API_KEY=replace-with-your-own-langsmith-key
   LANGSMITH_PROJECT=owasp-agentic-ai-goat-local
   LANGSMITH_ENDPOINT=https://api.smith.langchain.com
   # Set this if your key requires an explicit workspace:
   # LANGSMITH_WORKSPACE_ID=your-workspace-id
   ```

   Use your account's regional API endpoint. For an EU account, use `https://eu.api.smith.langchain.com`. The API key is a LangSmith key, separate from any model provider key. Keep your existing `AI_PROVIDER` and model settings; Ollama can remain local while traces go to LangSmith.

   This repository uses the SDK's project-based configuration. If your LangSmith workspace uses the newer agent-based interface, create/select an agent and use its environment's `tracer_session_name` compatibility value for `LANGSMITH_PROJECT`. See [LangSmith's LangGraph integration instructions](https://docs.langchain.com/langsmith/trace-with-langgraph). Do not assume that newer SDK environment variables are supported by the repository's locked dependencies, or upgrade packages just to follow an example.

4. Restart the application from the repository root so backend processes load the new settings:

   ```bash
   ./stop_all.sh
   ./start_all.sh
   ```

   On Windows, stop and restart using the commands in the [quick start](../QUICK_START.md). No database migration, reset, or reinstall is needed. Dependencies are already included in the application installation.

## Generate and find a trace

1. Sign in to the application and open [ARIA SQL](http://localhost:3000/workshop/sql) or [NOVA NoSQL](http://localhost:3000/workshop/nosql). The instructor must have enabled the exercise.
2. Submit a normal request using synthetic workshop data, such as asking ARIA to search its product catalog. Note the time and request text. Use the configured real provider, not a mock or legacy scripted runtime.
3. In LangSmith, open the configured workspace and its tracing project (or the corresponding agent environment). Select the recent trace matching your request. Widen the time filter if needed; export can arrive shortly after the response.
4. Expand the run tree and select individual nodes. Inspect their inputs, outputs, duration, and errors. Expand model child runs to see the messages sent through LangChain and the model's returned content or tool calls.

## Read the decision path

ARIA and NOVA use [workshopGraph.js](../../server/agent-runtime/workshopGraph.js). Their normal path contains these nodes; validation and tool loops can change the sequence:

| Node | What to inspect |
| --- | --- |
| `load_history` | Conversation context loaded for the request. |
| `decide` | The model-selected tool and parameters; look at the nested model response and returned decision state. |
| `validate` | Whether the decision passed the allowed tool/argument checks or was blocked. |
| `tool` | The tool's arguments and returned observation. A model proposing a tool is not proof that it ran. |
| `build_prompt` | Context and tool observations prepared for the final response. |
| `model` | The final model call and its returned response. |
| `persist` | The response-persistence stage. |
| `decision_failed` | A decision that could not be validated after the bounded attempts. |

A return from `validate` to `decide` is a validation retry. A return from `tool` to `decide` lets the model choose its next action after observing a tool result. Other workshops use different graphs and node names; start with their executed run tree rather than expecting this exact sequence.

Traces show recorded decisions and execution, not private model reasoning. Tool code or direct HTTP calls that are not independently instrumented may appear only through their enclosing node. The application's local run IDs are not guaranteed to match LangSmith trace IDs; correlate using the request, time, and available metadata.

Objective grading is separate. Check the application's Judge result and objective progress to confirm completion. A green trace, a convincing answer, or a mock response does not establish a successful exploit or earn objective credit.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No traces | Confirm tracing is enabled in the backend's environment, restart, and make a new request. Existing requests are not exported retroactively. Check the selected workspace, destination, and time filter. |
| Authentication or permission error | Check the key, workspace access, optional workspace ID, and regional endpoint. Inspect backend errors without sharing the key. |
| Traces arrive in an unexpected project | Check `LANGSMITH_PROJECT` and any older `LANGCHAIN_PROJECT` or `LANGCHAIN_SESSION` settings. Remove conflicting destination settings. Shell-exported variables can override `.env`. |
| Graph nodes appear without model calls | Confirm the path actually called a LangChain model. Blocked requests, mock/scripted runs, and direct provider calls can have different coverage. |
| Missing tool details | Inspect the enclosing node's inputs/outputs. Not every custom tool emits its own child span. |
| Trace succeeds but objective stays incomplete | Check canonical grading and effect evidence in the application. LangSmith does not write learner progress. |

To stop exporting new traces, set `LANGSMITH_TRACING=false` and restart the application. This does not delete traces already stored in LangSmith; manage those in your LangSmith workspace.

See the official [tracing quickstart](https://docs.langchain.com/langsmith/observability-quickstart) and [JavaScript SDK reference](https://reference.langchain.com/javascript/langsmith) for account setup and SDK configuration.
