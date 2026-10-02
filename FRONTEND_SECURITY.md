# Frontend security rules (dashboard)

Everything the dashboard displays from the API came from an attacker:
usernames, passwords, commands, SSH client versions, download URLs, file
names. Some bots type HTML/JavaScript into honeypots on purpose, hoping a
dashboard renders it. The dashboard's job is to show that text **as text**.

`fastapi-backend/scripts/test_ingest.py` sends a command containing
`<img src=x onerror=alert(1)>`. After running it, that string should appear
literally on the session page, and no alert should pop up.

## The rules

1. **Never render attacker data as HTML.**
   - React: normal `{value}` in JSX is safe. **Never** use
     `dangerouslySetInnerHTML` with API data.
   - Vue: `{{ value }}` is safe. **Never** use `v-html` with API data.
   - Plain JS: use `textContent`, never `innerHTML`.
   - Charts/tooltips: many chart libraries render labels and tooltips as
     HTML. Pass attacker strings through an escape function, or use the
     library's text-only option, before using them as labels.
2. **Never make attacker URLs clickable.** Show download URLs defanged, as
   plain text:
   ```js
   const defang = (url) =>
     String(url ?? "").replace(/^http/i, "hxxp").replace(/\./g, "[.]");
   ```
   No `<a href={url}>`. No link previews. No automatic `fetch()` of those URLs.
3. **Truncate long values in the UI.** Commands can be 4 KB. Use CSS
   `text-overflow: ellipsis`, plus a "show more" that still renders as text.
4. **Where the login token lives.** The API returns a bearer token. Prefer
   keeping it in memory (a React context or module variable). You'll need to
   log in again after a page refresh, and the token is harder to steal with
   XSS. If you really want it to survive a refresh, use `sessionStorage`,
   not `localStorage`. Clear it on logout and whenever the API returns 401.
5. **CSV / Excel exports.** If you add an export button, prefix any cell
   that starts with `=`, `+`, `-`, `@`, tab or carriage return with a single
   quote (`'`). Otherwise an attacker's "command" becomes a spreadsheet
   formula when someone opens the file.
6. **Keep the dashboard private.** It contains real IP addresses, and the
   passwords attackers try often come from real leaked-credential lists.
   Don't publish screenshots of raw data without redacting.

## Security headers for Firebase Hosting

Add this to `firebase.json`. Replace `https://your-api.example.com` with the
real API origin, and adjust the `script-src`/`style-src` values if you load
fonts or scripts from a CDN.

```json
{
  "hosting": {
    "public": "dist",
    "headers": [
      {
        "source": "**",
        "headers": [
          {
            "key": "Content-Security-Policy",
            "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://your-api.example.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
          },
          { "key": "X-Content-Type-Options", "value": "nosniff" },
          { "key": "Referrer-Policy", "value": "no-referrer" },
          { "key": "X-Frame-Options", "value": "DENY" },
          { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }
        ]
      }
    ]
  }
}
```

The CSP is the safety net. If a rendering mistake does slip through,
`script-src 'self'` stops injected inline scripts from running. Test that
your built app still works with it before deploying (Vite production builds
normally do).

## API facts the frontend relies on

- Auth: `POST /login` with `{"username", "password"}` returns
  `{"access_token"}`. Send it as `Authorization: Bearer <token>`. Tokens
  expire after `JWT_EXPIRE_MINUTES`. Re-running `create_admin.py` invalidates
  all existing tokens.
- CORS allows only `CORS_ALLOWED_ORIGIN`, with `GET`/`POST` and the
  `Authorization` and `Content-Type` headers. Cookies aren't used.
- List endpoints take `limit` (1–500) and `skip`. `/api/stats` includes
  `last_event_received_at`. Show it, so everyone can see when the honeypot
  pipeline stops delivering.
- `/api/stats/top-credentials` returns `username` and `password` as separate
  fields.
