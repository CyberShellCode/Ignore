
# Target Technologies & Infrastructure — XSS, IDOR, Command Injection

## Cross-Site Scripting (XSS)
- **Front-end frameworks:** React/Angular/Vue; risks with unsafe rendering (e.g., React `dangerouslySetInnerHTML`).
- **Server-side templating:** Jinja (Python), EJS (Node), Thymeleaf (Java) — misconfigured or disabled auto-escaping.
- **Legacy/custom stacks:** PHP, Classic ASP, JSP — manual string concatenation into HTML.

## Insecure Direct Object Reference (IDOR)
- **REST & GraphQL APIs:** Endpoints like `/api/v2/users/{user_id}` or `/api/v2/invoices/{invoice_id}`; missing authorization checks in Express/Django/Flask/Spring Boot.
- **Database-driven apps:** Sequential integers or UUIDs exposed via URLs or query params (e.g., `/edit?order_id=123`, `/documents/{uuid}`).
- **Cloud/resource IDs:** Indirection to storage buckets or config resources where `resource_id` can be swapped to access cross-tenant data.

## Command Injection
- **Server-side command exec:** PHP `shell_exec`/`system`, Python `subprocess`/`os.system`, Node `child_process` — untrusted input passed to shell contexts.
- **Legacy admin consoles:** Web UIs that wrap shell tooling for network/monitoring/control-plane tasks.
- **Embedded/IoT:** Minimal web UIs issuing OS commands; flaws can lead to device shells.
