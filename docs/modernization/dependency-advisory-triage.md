# Dependency advisory triage — 2026-09-11

## Scope and method

This is a source-only triage of the five high-severity package entries reported by
the root `npm audit` after the 2026-09-11 dependency refresh. The client audit has
no findings. This review used the installed lock graph, package source, OWASP Agentic AI GOAT
callers, and the reviewed upstream advisories. It did not run install scripts,
download a model, start the application, read a database, or exercise a teaching
payload.

The five entries represent three dependency paths and five underlying advisories:

| Audit entry | Installed path | Underlying advisory | Audit fix |
| --- | --- | --- | --- |
| `jws@3.2.2` | `owasp-ai-goat > jsonwebtoken@9.0.2 > jws@3.2.2` | [GHSA-869p-cjfg-cm3x](https://github.com/advisories/GHSA-869p-cjfg-cm3x) | Available upstream (`jws@3.2.3`) |
| `@huggingface/transformers@4.2.0` | direct dependency | Aggregate of its ONNX and Sharp paths below | No supported direct-package fix in the current registry graph |
| `onnxruntime-node@1.24.3` | `owasp-ai-goat > @huggingface/transformers@4.2.0 > onnxruntime-node@1.24.3` | Aggregate of its `adm-zip` path below | No supported fix through Transformers 4.2.0 |
| `adm-zip@0.5.18` | `owasp-ai-goat > @huggingface/transformers@4.2.0 > onnxruntime-node@1.24.3 > adm-zip@0.5.18` | [GHSA-xcpc-8h2w-3j85](https://github.com/advisories/GHSA-xcpc-8h2w-3j85) and [GHSA-vwc7-r8mq-g2x9](https://github.com/advisories/GHSA-vwc7-r8mq-g2x9) | `adm-zip@0.6.1` exists, but the installed parent range is `^0.5.16` |
| `sharp@0.34.5` | `owasp-ai-goat > @huggingface/transformers@4.2.0 > sharp@0.34.5` | [GHSA-f88m-g3jw-g9cj](https://github.com/advisories/GHSA-f88m-g3jw-g9cj) and [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c) | Sharp 0.35.4 fixes both, but Transformers declares `^0.34.5` |

`@huggingface/transformers` and `onnxruntime-node` are high audit entries because
they lead to vulnerable children. They do not add separate advisory conditions.

## Reachability and disposition

### `jws@3.2.2`: installed, but the reported call shape is not used

The advisory affects `jws.createVerify()` when all of these conditions hold: the
algorithm is HMAC, the application supplies a secret lookup function, and that
lookup uses attacker-controlled protected-header or payload data. The advisory
explicitly says `jws.verify()` and `node-jsonwebtoken` users are not affected.
OWASP Agentic AI GOAT imports `jsonwebtoken`, not `jws`, throughout the platform and challenge
code. Its hardened identity adapter also restricts verification to `HS256`.

The SecureShop `alg=none` lesson is reachable teaching behavior, but it is a
separate application policy: the route deliberately calls `jsonwebtoken.verify`
with `algorithms: ['none']`. It does not exercise the advisory's HMAC secret
lookup condition. Upgrading this dependency must preserve that explicit teaching
proof, but retaining CVE-2025-65945 does not enable the lesson.

**Disposition:** the npm finding is not reachable through OWASP Agentic AI GOAT's current call
shape. A supported transitive update from `jws@3.2.2` to `jws@3.2.3` fits
`jsonwebtoken@9.0.2`'s declared `^3.2.2` range and would not require an override
or a direct `jsonwebtoken` version change. However,
`learning-dependencies.json` freezes the recorded resolution until the
SecureShop proof and curriculum review pass. Treat that tested lock-only update
as the next remediation, not as an audit suppression.

### Transformers and ONNX: runtime text embeddings, installer-only ZIP handling

`server/services/ragVectorStore.js` dynamically imports Transformers and creates
one `feature-extraction` pipeline for `Xenova/all-MiniLM-L6-v2`. Server startup
initializes that pipeline in the background. Learner document buffers are decoded
as UTF-8, split into text chunks, and passed to the text embedder.

This establishes two different exposure boundaries:

- Transformers and ONNX execute at runtime for text embeddings. A missing local
  model can cause Transformers to download model/configuration files into its
  cache. OWASP Agentic AI GOAT does not expose a model-upload or model-ID parameter to learners;
  the model identifier is fixed in source.
- `adm-zip` is required only by `onnxruntime-node`'s `postinstall` code. That code
  may download Microsoft NuGet packages for platform binaries that are absent
  from the npm package or explicitly requested with an ONNX install flag, then
  extracts manifest-selected entries. It is not used by the running RAG service
  and it does not parse learner uploads or Transformers model downloads.

For the reviewed Darwin ARM64 installation, ONNX's installed metadata has no
default platform download requirement. This observation is platform-specific;
CUDA and other packaging combinations can take the NuGet download path.

#### `adm-zip` conditions

[GHSA-xcpc-8h2w-3j85](https://github.com/advisories/GHSA-xcpc-8h2w-3j85)
affects `adm-zip` before 0.6.0: a crafted central-directory uncompressed size can
cause an allocation of roughly 4 GiB before integrity validation. The installed
ONNX installer opens a downloaded `.nupkg`, so a corrupted or malicious package
at its configured feed could reach this behavior during installation. No OWASP Agentic AI GOAT
HTTP or MCP ZIP input reaches it.

[GHSA-vwc7-r8mq-g2x9](https://github.com/advisories/GHSA-vwc7-r8mq-g2x9)
also covers 0.5.18 and requires extraction with overwrite enabled into a
destination containing an attacker-created symlink. ONNX passes overwrite
enabled, but creates a timestamp-named temporary extraction directory before
extracting selected entries. That makes the advisory precondition difficult to
meet in a normal single-user clean install, without eliminating the installer
supply-chain boundary.

**Disposition:** there is no normal dependency update through
`@huggingface/transformers@4.2.0`: it pins `onnxruntime-node@1.24.3`, which allows
only `adm-zip` 0.5.x. `onnxruntime-node@1.29.0` has moved to `adm-zip ^0.6.0`, but
forcing that native runtime under Transformers would be an unqualified override.
Do not do that. Until Transformers publishes a compatible graph, retain lockfile
integrity, use trusted npm/NuGet sources, keep install/cache directories private,
and do not accept untrusted ONNX install flags or writable model caches in a
shared deployment. Replacing the embedding backend is a functional migration
and needs RAG behavior qualification.

### `sharp@0.34.5`: loaded dependency, no OWASP Agentic AI GOAT image-decoding call

Transformers imports Sharp in its Node image utility, but OWASP Agentic AI GOAT constructs a text
feature-extraction pipeline and passes strings. The application has other image
and upload teaching surfaces, yet none calls this Transformers image utility or
the installed Sharp instance.

Both high advisories require processing untrusted images:

- [GHSA-f88m-g3jw-g9cj](https://github.com/advisories/GHSA-f88m-g3jw-g9cj)
  covers Sharp before 0.35.0 and vulnerable upstream GIF, TIFF, and VIPS
  decoders. The documented workaround blocks those three loaders.
- [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c)
  covers Sharp before 0.35.4 and vulnerable libheif behavior, including possible
  code execution on glibc Linux under the advisory's stated conditions. Its
  workaround blocks the HEIF/AVIF loader.

**Disposition:** the vulnerable code is installed but not reachable from the
current learner-controlled runtime inputs. This conclusion must be revisited if
the RAG pipeline gains image, AVIF/HEIF, GIF, TIFF, or VIPS inputs. Sharp 0.35.4
fixes both advisories, but Transformers 4.2.0 declares `sharp ^0.34.5`; forcing a
new major-minor line is not a supported remediation. The decoder-block
workarounds would require importing and configuring the transitive Sharp
singleton and are unnecessary for the current text-only call path; they become a
minimum gate before any image pipeline is enabled.

## Release decision

None of these findings is part of an intentional OWASP Agentic AI GOAT vulnerability. The four
curriculum-tracked dependencies remain unchanged:
`jsonwebtoken@9.0.2`, `nunjucks@3.2.4`, `sax@1.6.0`, and `xml2js@0.6.2`.

The JWT advisory has a supported remediation path after its existing curriculum
gate. The Transformers group does not have a supported, registry-resolvable fix
through the current direct dependency. Its current learner path is text-only;
the remaining exposure is dependency installation and trusted fixed-model
loading rather than arbitrary ZIP, image, or model input. A release acceptance
for that group should name an owner and expiry tied to either an upstream
Transformers dependency refresh or an embedding-backend migration.

This assessment does not prove that native ONNX/model parsers have no other
vulnerabilities, that every deployment uses the same installer branch, or that a
future route cannot make the dormant image code reachable. The advisories should
remain visible in audit output; reachability findings are not grounds for a
blanket audit ignore.
