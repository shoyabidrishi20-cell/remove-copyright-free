# CR Remover Admin & Shared Backend Security Specification

## 1. Data Invariants

1. **Zero-Trust Default Deny**: Every Firestore path is denied by default unless explicitly permitted by an authenticated, validated rule.
2. **Verified Admin Gate (`isAdmin()`)**: Admin authorization requires `request.auth != null && request.auth.token.email_verified == true` AND either:
   - Existence and active status of `/admins/$(request.auth.uid)` (`active == true`), OR
   - Bootstrapped primary administrator email `request.auth.token.email == 'shoyabidrishi77@gmail.com'`.
3. **Anti-Privilege-Escalation**: Standard users creating or updating `/users/{userId}` can ONLY set `role: 'creator'` and `status: 'active'`, and cannot modify `role`, `status`, or `totalCases`. Only `isAdmin()` can write to `/admins/{uid}` or promote/suspend accounts.
4. **PII Isolation (Split Collection)**: Emails, WhatsApp/phone numbers, and internal notes are isolated in `/users/{userId}/private/{docId}` (readable only by owner or admin) and inside `/orders/{caseId}` (readable only by `resource.data.ownerUid == request.auth.uid` or `isAdmin()`). Blanket `list` queries on `/users`, `/users/{userId}/private`, `/orders`, or `/payments` without ownership or admin checks are forbidden.
5. **Document ID Poisoning Protection (`isValidId`)**: All single-document `get`, `create`, `update`, and `delete` operations validate document IDs against `^[a-zA-Z0-9_\\-]+$` with length `1..128`.
6. **Strict Schema & Key Validation**: Every `create` and `update` invokes `isValid<Entity>(incoming())` enforcing `keys().hasAll(...)`, `keys().hasOnly(...)`, enum allowlists, bounded string `.size()`, numeric sanity ranges, and immutable `createdAt` / `ownerUid` fields.
7. **Temporal Integrity**: `createdAt == request.time` on creation and `updatedAt == request.time` on every write (`createdAt == existing().createdAt` preserved on updates).
8. **Immutable Audit Trail**: `/auditLogs/{logId}` allows `create` only by `isAdmin()` with `actorUid == request.auth.uid` and `createdAt == request.time`; updates and deletes are strictly forbidden (`allow update, delete: if false;`).

## 2. "Dirty Dozen" Adversarial Payloads (Expected: PERMISSION_DENIED)

1. **Unverified Email Admin Spoof**: `request.auth.token = { email: "shoyabidrishi77@gmail.com", email_verified: false }` reading `/orders` or `/admins`.
2. **Self-Assigned Admin Role Escalation**: Non-admin user creating `/users/{uid}` with `{ role: "admin", status: "active" }`.
3. **Direct `/admins/{uid}` Self-Registration**: Non-admin user creating `/admins/{uid}` with `{ uid: request.auth.uid, role: "super_admin", active: true }`.
4. **Shadow Ghost Field Injection**: Admin or user updating `/orders/{caseId}` with extra undocumented field `{ isFreeBypass: true }`.
5. **Cross-User PII Blanket Read**: Signed-in user `uid_A` attempting `get` on `/users/uid_B/private/info`.
6. **Cross-User Order Scraping (`list`)**: Signed-in non-admin user executing `collection('orders')` without `where('ownerUid', '==', uid)`.
7. **Document ID Poisoning**: Creating `/orders/../../../etc/passwd` or a 1,500-character ID.
8. **Timestamp Forgery**: Creating `/orders/{caseId}` with client-supplied past timestamp `createdAt` (`createdAt != request.time`).
9. **Immutable Field Mutation**: User updating `/orders/{caseId}` to change `ownerUid` or `amountInr` after creation.
10. **Terminal State Tampering**: Non-admin attempting to update an order after `status == 'claim_released'`.
11. **Audit Log Tampering**: Even an admin attempting `update` or `delete` on `/auditLogs/{logId}`.
12. **Public Content/Settings Defacement**: Non-admin signed-in user attempting to write `/siteContent/hero`, `/servicePlans/{id}`, or `/settings/general`.
