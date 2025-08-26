# 🔒 Strategies for Hiding Extension Behavior (Especially JSONP Interception)

## 1. General Detectability of Extensions

-   Websites cannot enumerate extensions directly.
-   Detection relies on **side effects**:
    -   Injected DOM/CSS artifacts.
    -   Modified APIs.
    -   Missing/redirected network requests.
    -   Exposed `chrome-extension://` resources.

## 2. Permissions Hygiene

-   **Drop unnecessary permissions**:
    -   `declarativeNetRequestFeedback` only needed if you use
        `getMatchedRules()`.
    -   `webNavigation` only if actively used.
-   Keep `web_accessible_resources` empty unless strictly required.
-   Use **`optional_host_permissions`** and request access on demand.

## 3. Declarative Net Request (DNR) Rules

-   **Tab-scope rules** (`tabIds: [tab.id]`) → limits fingerprint
    surface.
-   **Session rules** → add/remove dynamically around user actions.
-   **Tight regex filters** → match only what you need.
-   Prefer redirecting **XHR/fetch** over `<script>` if possible (avoids
    SRI/CSP issues).
-   If redirecting scripts:
    -   Serve over **HTTPS** (no mixed-content).
    -   Return **valid JavaScript**, non-zero length, correct MIME type.
    -   Add small latency to look natural.

## 4. JSONP Specifics

-   JSONP loads via `<script src=...&callback=foo>`.
-   **SRI**: If `integrity="..."` is present, any redirect → failure.
-   **CSP**: Page must allow your proxy origin in `script-src`.\
    If not → redirect scripts won't execute.

### Two Modes:

-   **Proxy redirect mode** (works if CSP allows your origin):
    -   Redirect ASTx JSONP → your hosted proxy script.
    -   Proxy extracts params, invokes the extension, returns valid
        JSONP payload.
    -   Optional: put params in **fragment** (`#`) so server doesn't see
        them.
-   **Shim mode (fallback for strict CSP)**:
    -   Block JSONP requests with DNR.
    -   Tiny **content script** watches `<script>` insertions, extracts
        `callback=...`, asks extension for data, and calls
        `window[callback](payload)`.
    -   Avoids CSP, SRI, and mixed-content restrictions.

## 5. Stealth Content Script Practices

-   **Avoid patching natives** (detectable via `.toString()`).
-   Use **`MutationObserver`** to detect added `<script>` nodes instead.
-   Inject inline code and remove the script node immediately.
-   Define JSONP callbacks as non-enumerable, and clean up after
    calling.
-   No stray globals, DOM nodes, or console logs.
-   Add jitter (20--100 ms) before invoking callback to mimic network
    latency.
-   Remove listeners once done.

## 6. Messaging Pattern

-   Page script (proxy or shim) uses `window.postMessage` /
    `CustomEvent`.
-   **Relay content script** bridges page ↔ background:
    -   Listens for page events.
    -   Uses `chrome.runtime.sendMessage` to extension.
    -   Returns data via another page event.
-   Background handles heavy logic and WebVM communication.

## 7. Practical Checklist

-   [ ] Use HTTPS for proxy domains; fragments (`#`) to hide params.\
-   [ ] Drop unused permissions (`declarativeNetRequestFeedback`).\
-   [ ] DNR rules: tab-scoped, session-based, tight regex.\
-   [ ] For JSONP: redirect if CSP allows, otherwise shim.\
-   [ ] Shim: MutationObserver, no global pollution, callback cleanup.\
-   [ ] Realistic timing + valid JS payloads.\
-   [ ] Test on real bank pages: watch **Console** for
    CSP/SRI/mixed-content errors.

------------------------------------------------------------------------

✅ **Bottom line:**\
- Redirect-to-proxy works only if the page's CSP allows your proxy
origin.\
- To be robust across all banks, pair it with a **stealth JSONP shim**
that blocks the original request and fakes the callback locally.\
- With minimal permissions, tab-scoped rules, HTTPS, and a careful
content script, detection becomes very difficult.
