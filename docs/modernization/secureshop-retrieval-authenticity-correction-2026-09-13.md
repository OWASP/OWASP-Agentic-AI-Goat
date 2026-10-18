# SecureShop retrieval exercise authenticity correction

The historical `llm08-embedding-inversion` ID is retained so existing vulnerability links and coverage checks remain valid. Its truthful current description is **sensitive indexed-document disclosure through similarity retrieval**.

The old proof indexed one document, queried using words from its known credential, and asserted that some top-five result contained that credential. With one candidate, that did not establish meaningful retrieval selection. The generated map additionally claimed that uploads returned raw vectors and an attacker recovered model training data. The upload API returns metadata and chunk IDs; `VectorStore.search` returns stored plaintext. No inversion algorithm runs.

Embedding inversion reconstructs text from its embedding representation; retrieving a stored plaintext document is a different mechanism. See the primary research [Text Embeddings Reveal (Almost) As Much As Text](https://aclanthology.org/2023.emnlp-main.765/). The implemented disclosure remains relevant to [OWASP LLM08 vector and embedding weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/), whose risks include unauthorized retrieval of sensitive indexed information.

## Changes and evidence

- Corrected the map generator's attack path, impact and defense, regenerated the authoritative vulnerability map, and corrected the source annotation explanation. The tagged vulnerable behavior is unchanged.
- Strengthened the proof with a public distractor manual and a fresh random synthetic recovery token. A topic-only query, containing none of that token, selects the private manual as its top result and returns its exact stored bytes. A pre-insertion query cannot return the secret. The file upload and indexing are real; all files, databases and vector indexes live in owned temporary directories and are cleaned up.
- Focused compatibility-fixture test passed, one test and no skips. The deterministic hash embedding provider is explicitly selected; this is not a neural embedding, PostgreSQL-runtime, model-training-data or vector-inversion qualification.
- Independent review confirmed the original mismatch and the corrected proof's scope. Its precision feedback was addressed: query/secret token sets are now explicitly disjoint, and the retrieval sink carries the stable annotation so the generated map includes both ingestion and disclosure locations. The final focused test and all-66-ID annotation check pass. No UI styling, formal objective ID, visibility toggle, progress record, Judge rubric or AWS asset changed.

## Remaining implementation requirement

Create the owned SecureShop retrieval-disclosure scenario through the real learner/tool flow, with two synthetic shop personas inside a single attendee boundary. The attacker may submit topic queries but must not receive seed state or choose the platform owner. Its Judge needs retrieval provenance, exact document/marker evidence, caller and reset generation, plus negative cases for public-only documents, unrelated answers and forged evidence. Qualify the supported PostgreSQL path and real embedding/model profile separately from deterministic fixtures. Current internal-method testing does not prove those contracts.

If a separate inversion exercise is introduced, require an actually obtainable embedding with model/provider/dimension provenance, held-out unknown text, an implemented reconstruction method, distractors and measured baseline comparisons. Prove that no plaintext retrieval endpoint supplied the answer. Do not relabel hash collisions or plaintext lookup as successful inversion.
