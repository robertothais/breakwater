# WebVM Proxy

Privacy-preserving JSONP interceptor for Korean banking security software.

## Purpose

This script is served from a public domain and receives redirected requests from the browser extension. It maintains privacy by keeping all banking parameters in URL fragments (which are never sent to the server).

## Architecture

```
Korean Banking Site
    ↓ (JSONP script request)
Extension Redirect Rules
    ↓ (redirect with URL fragments)
webvm-proxy.js (this script)
    ↓ (postMessage to extension)
Extension Content Script
    ↓ (chrome.runtime.sendMessage)
Extension Background Script (WebVM)
    ↓ (CheerpX → ASTx daemon)
Banking Response
```

## Privacy Features

- **URL Fragments**: Banking parameters stay in `#` fragments, never sent to server
- **Client-Side Only**: All processing happens in browser, no server-side data collection
- **Open Source**: Fully auditable code that users can verify

## Deployment

Deploy `webvm-proxy.js` to a public HTTPS domain with proper CORS headers.

Example: `https://yourdomain.com/webvm-proxy.js`

## Usage

The extension redirects requests like:
```
https://lx.astxsvc.com/ASTX2/hello?callback=bank123&v=3
```

To:
```
https://yourdomain.com/webvm-proxy.js#endpoint=/ASTX2/hello&callback=bank123&v=3
```

The script then:
1. Parses fragments (never sent to server)
2. Sends postMessage to extension
3. Extension processes via WebVM
4. Response executes JSONP callback