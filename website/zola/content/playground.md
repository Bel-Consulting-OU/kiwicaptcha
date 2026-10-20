+++
title = "Widget"
template = "playground.html"
description = "The KiwiCaptcha widget across its ten lifecycle states, host container widths, component text scales and shipped language packs."
+++

<div class="section">

{{ kicker(text="states") }}

## Ten states. Different recovery contracts.

The widget keeps its lifecycle in the open. Each state has a distinct meaning and a distinct recovery contract; state meaning is carried by more than color alone, and the recovery line always names a useful next action.

<div class="table-wrap">

| State | Meaning | Recovery |
| --- | --- | --- |
| pending | Deferred execution has never started. | No extra human control; application invokes execute. |
| idle | Manual reacquisition/reset state after a credential or flow existed. | Native Retry when provided by driver. |
| connecting | Acquiring a challenge. | Bounded flow recovery on failure. |
| solving | Selected computation in progress. | Driver governs completion/failure. |
| done | Browser solver completed and produced response token. | Host continues to authoritative server verification; later expiry remains possible. |
| failed | Terminal flow failure after bounded recovery. | Native Retry. Two automatic retries precede terminal failure in driver. |
| expired | Credential validity ended. | Clear token/binding/aliases; preserve host form data; native Retry reacquires. |
| worker-unavailable | Required off-main-thread solver unavailable. | Native Retry can reacquire; no silent memory-hard downgrade/main-thread solve. |
| execution-unavailable | Required armed execution interpreter failed. | Native Retry reruns flow. No solution submitted without required evidence. |
| solver-mismatch | Worker/driver/glue protocol identities inconsistent. | Reload/update a coherent asset set; ordinary Retry cannot repair mixed assets. Never accept mismatched output. |

</div>

Browser completion produces a response token. Server verification, lifecycle and policy remain the acceptance boundary. Native retries and reload are distinct; no human checkbox is introduced.

{{ notes(paths=["packages/kiwicaptcha-wasm/assets/widget-driver.js", "packages/kiwicaptcha/integrations/symfony/Resources/ACCESSIBILITY.md"]) }}

</div>

<div class="section">

{{ kicker(text="specimen") }}

## The ten states, rendered statically.

Each card below is the production widget markup styled by the production stylesheet, pinned to the light theme and frozen in one state. The specimens do not issue a challenge, run a solver or create a token.

<div class="spec-grid">
  <div class="spec-item">{{ widget(state="pending") }}<p class="mono-caption">pending</p></div>
  <div class="spec-item">{{ widget(state="idle") }}<p class="mono-caption">idle</p></div>
  <div class="spec-item">{{ widget(state="connecting") }}<p class="mono-caption">connecting</p></div>
  <div class="spec-item">{{ widget(state="solving") }}<p class="mono-caption">solving</p></div>
  <div class="spec-item">{{ widget(state="done") }}<p class="mono-caption">done</p></div>
  <div class="spec-item">{{ widget(state="failed") }}<p class="mono-caption">failed</p></div>
  <div class="spec-item">{{ widget(state="expired") }}<p class="mono-caption">expired</p></div>
  <div class="spec-item">{{ widget(state="worker-unavailable") }}<p class="mono-caption">worker-unavailable</p></div>
  <div class="spec-item">{{ widget(state="execution-unavailable") }}<p class="mono-caption">execution-unavailable</p></div>
  <div class="spec-item">{{ widget(state="solver-mismatch") }}<p class="mono-caption">solver-mismatch</p></div>
</div>

{{ notes(paths=["packages/kiwicaptcha-wasm/assets/widget-driver.js", "packages/kiwicaptcha/resources/widget.css", "packages/kiwicaptcha/design/README.md"]) }}

</div>

<div class="section">

{{ kicker(text="widths") }}

## Fits the host container.

The component honors the host-owned container between 240 and 352 pixels. Three fixed-width renders:

<div class="spec-grid">
  <div class="spec-item">{{ widget(state="solving", width="w240") }}<p class="mono-caption">240 px</p></div>
  <div class="spec-item">{{ widget(state="solving", width="w300") }}<p class="mono-caption">300 px</p></div>
  <div class="spec-item">{{ widget(state="solving", width="w352") }}<p class="mono-caption">352 px</p></div>
</div>

{{ notes(paths=["packages/kiwicaptcha/resources/widget.css", "packages/kiwicaptcha/design/brand-preview.html"]) }}

</div>

<div class="section">

{{ kicker(text="component text") }}

## Two text scales.

The component text scale is a token, not a browser zoom. Hosts choose 100 percent or 200 percent; layout wraps instead of clipping.

<div class="spec-grid">
  <div class="spec-item">{{ widget(state="solving", width="w300", scale=1) }}<p class="mono-caption">100 percent component text</p></div>
  <div class="spec-item">{{ widget(state="solving", width="w300", scale=2) }}<p class="mono-caption">200 percent component text</p></div>
</div>

{{ notes(paths=["packages/kiwicaptcha/resources/widget.css", "packages/kiwicaptcha/integrations/symfony/Resources/ACCESSIBILITY.md"]) }}

</div>

<div class="section">

{{ kicker(text="languages") }}

## Ten language packs, with a real right-to-left pack.

English ships eagerly in the driver; every other pack ships lazily and registers on the same bridge. Arabic carries direction so the widget subtree flips when the pack lands. The table shows the real runtime strings for the working badge, the verifying status and the native retry control.

<div class="table-wrap">

| Pack | Badge | Status | Recovery |
| --- | --- | --- | --- |
| en | Working | Verifying… | Retry |
| de | Arbeitet | Prüfe… | Erneut |
| fr | Traitement | Vérification… | Réessayer |
| es | Trabajando | Verificando… | Reintentar |
| it | In corso | Verifica… | Riprova |
| nl | Bezig | Controleren… | Opnieuw |
| pl | Pracuje | Weryfikacja… | Ponów |
| pt | A trabalhar | A verificar… | Tentar novamente |
| pt-br | Trabalhando | Verificando… | Tentar novamente |
| ar (rtl) | يعمل | جارٍ التحقق… | إعادة المحاولة |

</div>

{{ notes(paths=["packages/kiwicaptcha-wasm/assets/widget-driver.js", "packages/kiwicaptcha-wasm/assets/widget-locales.js"]) }}

</div>

<div class="section">

{{ kicker(text="recovery") }}

## Recovery is native, bounded and separate from reload.

Automatic retries are bounded in the driver: two precede a terminal failure. Native Retry reacquires without losing the host's form data on expiry. A solver mismatch cannot be repaired by retrying — the coherent asset set is reloaded instead. No state introduces a checkbox, puzzle or human-certification claim.

{{ notes(paths=["packages/kiwicaptcha-wasm/assets/widget-driver.js", "packages/kiwicaptcha/design/README.md", "SECURITY.md"]) }}

</div>
