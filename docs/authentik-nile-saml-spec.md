# Specification: authentik as SAML IdP and SCIM source for Nile Portal tenants

| | |
|---|---|
| Status | Implemented. First tenant: `nileworkshop-1.com` on `https://authentik.nile.global`. SCIM live for that tenant since 2026-10-22 |
| authentik version | **2026.8.5** (checked against the instance's own OpenAPI schema) |
| Replaces | `Authentik_Nile_Doc.pdf` (written for authentik 2025.10.4) |
| Automation | [`scripts/nile_idp.py`](../scripts/nile_idp.py), configured by `tenants/<domain>.toml` |
| Scope | SAML 2.0 SSO for Nile Portal admins; optional SCIM provisioning of network groups (§3.8, §4.5) |

This document describes exactly what gets configured in authentik and in the Nile Portal, and
why. The script does every authentik step. The Nile Portal steps are manual. Both are described
here, so the integration can be rebuilt by hand if the script is unavailable.

---

## 1. Architecture

```
 user ──► Nile Portal (u1.nile-global.cloud) ──► Okta org behind Nile (SP)
                                                     │  SAML AuthnRequest
                                                     ▼
                         authentik  /application/saml/<tenant-slug>/   (IdP)
                                                     │  signed SAML assertion (HTTP-POST)
                                                     ▼
                         login.u1.nile-global.cloud/sso/saml2/<id>  (ACS)
```

* Nile Portal federates through **Okta**. The SP values Nile hands you are Okta values: the ACS is
  `https://login.u1.nile-global.cloud/sso/saml2/<id>` and the Audience/EntityID is
  `https://www.okta.com/saml2/service-provider/sp...`.
* Nile routes a login to a tenant by the **email domain** of the user. That domain must be
  added and verified in the tenant (Account Management > Domains).
* Nile decides the user's role from the SAML attribute **`memberOf`** (an array of group names),
  using that tenant's Group Rules.

### 1.1 Multi-tenant model

One authentik serves many Nile Portal tenants. Objects are either **shared** or **per tenant**:

| Object | Scope | Name |
|---|---|---|
| SAML property mappings (6) | shared | `Nile: firstName`, `Nile: lastName`, `Nile: mail`, `Nile: email`, `Nile: mobile`, `Nile: memberOf` |
| Signing keypair | shared | `Nile SAML Signing` (RSA, 10 years) |
| Group | per tenant | `<access_group>`, set per instance in the config (`tenant.access_group`), e.g. `pod-nile-workshop-1` |
| SAML provider | per tenant | `Provider for Nile Portal - <domain>` |
| Application | per tenant | `Nile Portal - <domain>`, slug `<domain with . → _>` |
| Policy binding | per tenant | application → `<access_group>` group |
| SCIM network groups | per tenant, optional | `[scim] groups`, e.g. `pod-nile-workshop-1-employee`, `pod-nile-workshop-1-contractor` |
| SCIM provider + hidden application | per tenant, optional | `SCIM for Nile Network - <domain>`, app slug `<slug>-network` (§3.8) |

**One group per tenant.** Each Nile Portal instance has exactly one authentik group, e.g.
`pod-nile-workshop-1`. That group does two jobs:

* *Access:* it is the only group bound to that tenant's application. A user from another tenant
  gets "access denied" in authentik before any assertion is sent.
* *Role:* its name is sent in `memberOf`. The tenant's Nile group rule maps it to
  **Administrator**.

So every member of `pod-nile-workshop-X` is an administrator of Nile Workshop X, and only of
that instance. There are no shared role groups. Giving someone a non-admin role would need a
second per-tenant group and a second Nile group rule, which this setup doesn't do.

Workshop instances on authentik.nile.global:

| Nile Portal instance | Domain | Portal admin group | SCIM network groups | App slug |
|---|---|---|---|---|
| Nile Workshop 1 | `nileworkshop-1.com` | `pod-nile-workshop-1` | `pod-nile-workshop-1-employee`, `pod-nile-workshop-1-contractor` (live) | `nileworkshop-1_com` |
| Nile Workshop 2 | `nileworkshop-2.com` (planned) | `pod-nile-workshop-2` | `pod-nile-workshop-2-employee`, `pod-nile-workshop-2-contractor` | `nileworkshop-2_com` |
| Nile Workshop 3 | *(tbd)* | `pod-nile-workshop-3` | `pod-nile-workshop-3-employee`, `-contractor` | |
| Nile Workshop 4 | *(tbd)* | `pod-nile-workshop-4` | `pod-nile-workshop-4-employee`, `-contractor` | |

**Slug.** Application slugs only allow `[-a-zA-Z0-9_]`. The tenant domain is turned into a slug
by replacing `.` with `_`, e.g. `nileworkshop-1.com` → `nileworkshop-1_com`. Hostnames cannot
contain `_`, so the slug is unique per domain and the domain can be read back from it. The slug
appears in every IdP URL.

---

## 2. Prerequisites

* An authentik instance reachable over HTTPS (here: behind a Cloudflare Tunnel).
  * Since 2026.8, authentik only trusts `X-Forwarded-Proto` from
    `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS`. If that is wrong, metadata contains `http://` URLs and
    Okta rejects the IdP. `verify` checks for this.
* An authentik **API token** for a superuser. Create a service account, add it to
  `authentik Admins`, then go to Directory > Tokens and App passwords > Create, with intent **API**
  and a short expiry. Delete the token after setup.
* Python 3.11+ on the machine running the script. No pip packages are needed.
* Nile Portal administrator access to the tenant.

---

## 3. authentik configuration (done by `nile_idp.py apply`)

Each step looks the object up by name (or slug) and creates it only if it is missing. Fields the
script owns are corrected if they drift. Nothing is ever deleted.

### 3.1 SAML property mappings (shared)

Customization > Property Mappings > Create > **SAML Provider Property Mapping**.
API: `POST /api/v3/propertymappings/provider/saml/`

| Name | SAML Attribute Name | Friendly Name | Expression |
|---|---|---|---|
| `Nile: firstName` | `firstName` | `firstName` | `return request.user.attributes.get("firstName") or (request.user.name.split(" ", 1)[0] if request.user.name else "")` |
| `Nile: lastName` | `lastName` | `lastName` | `return request.user.attributes.get("lastName") or (request.user.name.split(" ", 1)[1] if " " in request.user.name else "")` |
| `Nile: mail` | `mail` | `mail` | `return request.user.attributes.get("mail") or request.user.email` |
| `Nile: email` | `email` | `email` | `return request.user.attributes.get("mail") or request.user.email` |
| `Nile: mobile` | `mobile` | `mobile` | `return request.user.attributes.get("mobile", "")` |
| `Nile: memberOf` | `memberOf` | `memberOf` | `for group in request.user.groups.all():`<br>`    yield group.name` |

Differences from the PDF:

* `memberOf` uses `request.user.groups` because `ak_groups` was deprecated in authentik 2026.2.
  It still works, but logs a configuration warning event.
* Name and email fall back to the built-in user fields, so a user created without the custom
  attributes still produces a valid assertion. Okta needs a non-empty `firstName`/`lastName`.
* `email` is new. The SP metadata Nile generates (Okta) lists `firstName`, `lastName` and **`email`**
  as `isRequired="true"` and `mail`/`memberOf`/`mobile` as optional. The PDF only sent `mail`.
  Both are now sent.
* Names have a `Nile:` prefix. The unprefixed mappings `firstName`, `lastName`, `mail`, `mobile` and
  `memberOf` from the PDF already exist on this instance and are used by the older
  `andrettiauthentik` tenant. They are left untouched.

The NameID uses the built-in managed mapping **`authentik default SAML Mapping: Email`**
(`goauthentik.io/providers/saml/email`).

### 3.2 Group (per tenant)

Directory > Groups > Create. API: `POST /api/v3/core/groups/`

| Group | Superuser | Purpose |
|---|---|---|
| `<access_group>` (e.g. `pod-nile-workshop-1`) | no | may sign in to this tenant; Administrator in Nile via the group rule |

This group is not `authentik Admins`. The PDF bound the application to `authentik Admins`, which
would make every Nile admin a superuser in authentik.

### 3.3 Users

Directory > Users > Create. API: `POST /api/v3/core/users/`

| Field | Value |
|---|---|
| Username | the email address |
| Name | `first_name last_name` |
| Email | the email address |
| Type | Internal |
| Path | `users` |
| Attributes | `mail`, `firstName`, `lastName`, `mobile` (the same keys the PDF used) |

Then:

* Add group memberships with `POST /api/v3/core/groups/{uuid}/add_user/`. This only ever adds
  memberships, so it never removes the user from other tenants' groups.
  * `admin = true` → member of `<access_group>` (Portal sign-in as Administrator). The default is
    **false**, so a forgotten field never grants Portal admin.
  * `groups = [...]` → member of those SCIM network groups (§3.8). Each must be listed in
    `[scim] groups`.
* Password: if `password` is set in the config, it is applied on creation
  (`POST /api/v3/core/users/{id}/set_password/`). Otherwise set it in the UI: user > **Set password**.
  The script only resets passwords on existing users when run with `--set-passwords`.

Users on this instance: `shiv@nileworkshop-1.com` (admin; also in `pod-nile-workshop-1-employee`
as the SCIM test user).

### 3.4 Signing keypair (shared)

System > Certificates > Generate. API: `POST /api/v3/crypto/certificatekeypairs/generate/`
with `common_name = "Nile SAML Signing"`, `validity_days = 3650`, `alg = rsa`.

The built-in `authentik Self-signed Certificate` (the one the PDF uses) is only valid for
one year. On this instance it **expired on 2026-09-20**. The script refuses to use an expired
keypair. All Nile tenants share one keypair. Rotating it means uploading the new certificate in
every tenant (see §7.3).

| | |
|---|---|
| Subject | `CN=Nile SAML Signing, O=authentik, OU=Self-signed` |
| Valid | 2026-10-21 → 2036-10-19 |
| SHA-256 fingerprint | printed by `openssl x509 -in out/<domain>/idp-certificate.pem -noout -fingerprint -sha256` |

### 3.5 SAML provider (per tenant)

Applications > Providers > Create > SAML Provider. API: `POST /api/v3/providers/saml/`

| UI field | API field | Value | Note |
|---|---|---|---|
| Name | `name` | `Provider for Nile Portal - <domain>` | |
| Authorization flow | `authorization_flow` | `default-provider-authorization-explicit-consent` | users approve once, as in the PDF |
| Invalidation flow | `invalidation_flow` | `default-provider-invalidation-flow` | required since 2024.10 |
| ACS URL | `acs_url` | Nile/Okta `AssertionConsumerService Location` | `https://dummy.com` until §4 is done |
| Audience | `audience` | Nile/Okta `entityID` | empty until §4 is done |
| EntityID/Issuer override | `issuer_override` | *(empty)* | named "Issuer" before 2026.5. Empty means the per-tenant metadata URL is the issuer |
| Service Provider Binding | `sp_binding` | `post` | |
| Signing Certificate | `signing_kp` | `Nile SAML Signing` | |
| Sign assertions | `sign_assertion` | `true` | matches the working tenant |
| Sign responses | `sign_response` | `false` | matches the working tenant |
| Digest / Signature algorithm | | SHA-256 / RSA-SHA256 | |
| Property mappings | `property_mappings` | the six `Nile:` mappings only | the seven default mappings are *not* attached |
| NameID Property Mapping | `name_id_mapping` | `authentik default SAML Mapping: Email` | Nile/Okta matches users by email |
| Assertion valid not before / not on or after | | `minutes=-5` / `minutes=5` | authentik defaults |
| Session valid not on or after | | `minutes=86400` (60 days) | matches Nile SSO timeout of 60 days |

Issuer note: the PDF's provider used the issuer `authentik`. On 2026.8 the default issuer is the
tenant's metadata URL. Either works, as long as the **Nile "IdP Issuer URI" is exactly the
`entityID` in this provider's metadata**. The script reads it from the metadata so the two always
match.

### 3.6 Application and binding (per tenant)

Applications > Applications > Create. API: `POST /api/v3/core/applications/`

| Field | Value |
|---|---|
| Name | `Nile Portal - <domain>` |
| Slug | `<domain>` with `.` → `_` |
| Provider | the provider from §3.5 |
| Policy engine mode | `any` |
| Launch URL | optional (`tenant.launch_url`) |

Binding: Application > Policy / Group / User Bindings > Bind existing group >
`<access_group>`, order 0, enabled. API: `POST /api/v3/policies/bindings/`.

### 3.7 Values handed to the Nile Portal

The script writes these to `out/<domain>/`. It reads them from
`GET /api/v3/providers/saml/{id}/metadata/` and
`GET /api/v3/crypto/certificatekeypairs/{kp}/view_certificate/`:

| File | Content |
|---|---|
| `nile-portal-values.md` | every value for the Nile forms, ready to paste |
| `idp-metadata.xml` | the provider's IdP metadata |
| `idp-certificate.pem` | signing certificate (public) |

For `nileworkshop-1.com`:

| Nile field | Value |
|---|---|
| IdP Issuer URI | `https://authentik.nile.global/application/saml/nileworkshop-1_com/metadata/` |
| IdP SSO URL | `https://authentik.nile.global/application/saml/nileworkshop-1_com/` |
| Destination URL | same as IdP SSO URL |
| IdP Certificate | contents of `idp-certificate.pem` |

Since 2026.5, authentik serves SSO for every binding from one endpoint,
`/application/saml/<slug>/`. That is what the metadata advertises. The older
`/application/saml/<slug>/sso/binding/post/` URL (used in the PDF) still works and is listed in
`nile-portal-values.md` as a fallback.

### 3.8 SCIM provisioning of network groups (optional, per tenant)

Configured only when the tenant config has a `[scim]` section. Nile uses the pushed groups
(e.g. `pod-nile-workshop-1-employee`, `pod-nile-workshop-1-contractor`) to grant network access.

**Roles.** Nile is the SCIM server and authentik is the SCIM client. authentik pushes users and
groups to `https://u1.nile-global.cloud/api/v1/scim` with a static bearer token.

**Nile endpoint facts** (probed 2026-10-22):

| Endpoint | Result |
|---|---|
| `GET /api/v1/scim/Users`, `/Groups` | 200, `application/scim+json`, standard ListResponse |
| `GET /api/v1/scim/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` | not implemented (302 to login) |
| Key file `scim_api_key-<n>.json` | `{"api_token": <40 chars>, "name": "scim_api_key", "url": "https://u1.nile-global.cloud"}`. `url` is the Portal root, so the script appends `/api/v1/scim` |

There's no `ServiceProviderConfig`. authentik's default compatibility mode then logs a warning and
falls back to a minimal capability set: no PATCH, no filter, no bulk. Groups are sent with their
full member list via POST/PUT. This was checked in authentik's source
(`providers/scim/clients/base.py`, `schema.py`, version-2026.8).

**Why a separate application.** authentik provisions only the users who may access the
application the SCIM provider is attached to. Attaching SCIM to the Portal application would mean
binding the network groups to it, which would let network users sign in to the Nile Portal. So each
tenant gets a second, hidden application that exists only to carry SCIM.

| Object | Name | Settings |
|---|---|---|
| Groups | each name in `[scim] groups` | plain groups, no parent, not superuser |
| SCIM provider | `SCIM for Nile Network - <domain>` | URL; token (write-only in the API, so always re-sent); auth mode `token`; compatibility `default`; verify certificates; **exclude service accounts**; **discovery off** (never adopt users made by others in Nile); group filters = the `[scim]` groups; user mapping `authentik default SCIM Mapping: User`; group mapping `authentik default SCIM Mapping: Group`; `dry_run` from config (default **true**) |
| Application | `Nile Network - <domain>`, slug `<slug>-network` | no SSO provider; backchannel = the SCIM provider; hidden from the Application Dashboard (`meta_hide`) |
| Bindings | application → each `[scim]` group | |

API: `POST /api/v3/providers/scim/`, `POST /api/v3/core/applications/` with
`backchannel_providers`, `POST /api/v3/policies/bindings/`.

**Scope.**
- Users: members of any `[scim]` group, i.e. users who pass the hidden app's bindings.
- Groups: only the `[scim]` groups (group filter). Without the filter, authentik would push
  *every* group to every tenant.
- Existing Nile users created elsewhere (e.g. `alex.scott@nilenetwork.org`) are never touched,
  because discovery is off and authentik only manages objects it created.

**Payload** (default mappings, captured from a dry run):

```json
{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
 "userName": "shiv@nileworkshop-1.com", "displayName": "Shiv Mehra",
 "name": {"formatted": "Shiv Mehra", "givenName": "Shiv", "familyName": "Mehra"},
 "emails": [{"type": "other", "value": "shiv@nileworkshop-1.com", "primary": true}],
 "active": true, "externalId": "<hash>"}
{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
 "displayName": "pod-nile-workshop-1-employee", "externalId": "<group uuid>", "members": [...]}
```

**Timing.** Changes are pushed immediately: membership changes, user edits, deactivation. A full
sync also runs on the provider's schedule (`13 */4 * * *`, every 4 hours on this instance), and
whenever the provider is saved (which every `apply` does).

**Dry run.** With `dry_run = true`, authentik runs the whole sync but rejects every non-GET request
before it is sent. The rejected requests are logged on the sync tasks.
`verify` reads them through `/api/v3/tasks/schedules/` and `/api/v3/tasks/tasks/{id}/` (`logs`),
and prints "would send Users …" / "would send Groups …". Set `dry_run = false` and re-run
`apply` to go live.

**Deprovisioning.** A user removed from all `[scim]` groups, or deactivated, loses access to the
hidden application. The next sync deprovisions them in Nile.

---

## 4. Nile Portal configuration (manual)

Log in to the Nile Portal (`https://u1.nile-global.cloud/`) as a tenant administrator.

### 4.1 Add the identity provider

GLOBAL SETTINGS > Identity > **Providers** > **ADD A NEW PROVIDER**

| Field | Value (from `out/<domain>/nile-portal-values.md`) |
|---|---|
| Protocol | SAML2 |
| IdP Issuer URI | issuer (`entityID` from authentik metadata) |
| IdP SSO URL | SSO URL |
| Destination URL | SSO URL |
| IdP Certificate | PEM certificate. If rejected, paste the base64 body without BEGIN/END lines |
| SSO Timeout | 60 Days |

Click **SUBMIT**.

### 4.2 Hand the SP values back to authentik

1. On the new provider, click **METADATA** and save the XML, e.g. as
   `tenants/<domain>-nile-sp-metadata.xml`. The `tenants/` folder is gitignored.
2. In `tenants/<domain>.toml`, set `nile_sp.metadata_file` to that file. Alternatively, copy its
   `entityID` into `nile_sp.entity_id` and the `AssertionConsumerService Location` into
   `nile_sp.acs_url`.
3. Run `python3 scripts/nile_idp.py apply tenants/<domain>.toml`. The provider's ACS URL and
   Audience are updated (this replaces the PDF's manual "Edit the Provider" step).

### 4.3 Group mapping and rules

GLOBAL SETTINGS > Identity > **Group rules**

1. **ADD GROUP MAPPING**: Friendly name `memberOf`, External name `memberOf`, Type **ARRAY**. Click **SAVE**.
2. **ADD GROUP RULE**: Nile role **Administrator**, value = this tenant's group, e.g.
   `pod-nile-workshop-1` for Nile Workshop 1.
3. Click **INACTIVE** on the rule to switch it to **ACTIVE**.

The value must match `tenant.access_group` in the tenant config exactly (case-sensitive).
`out/<domain>/nile-portal-values.md` prints the exact rule.

### 4.4 Domain

Account Management > Domains > **Add Domain** > `<domain>` (e.g. `nileworkshop-1.com`) >
**Verify**. Users' email addresses must be in this domain.

### 4.5 SCIM key (only with `[scim]`)

GLOBAL SETTINGS > Identity > the authentik provider > **SCIM Configuration** > **ADD SCIM KEY**.
This section only appears after the SAML provider exists. Nile downloads
`scim_api_key-<n>.json`. Save it in `tenants/` (gitignored), `chmod 600` it, and set
`[scim] key_file`. Once the groups are synced, reference them in the tenant's network access
policies.

---

## 5. Verification

```
python3 scripts/nile_idp.py verify tenants/<domain>.toml
```

| Check | How |
|---|---|
| ACS URL and Audience set from Nile (not placeholder) | provider fields |
| Metadata URLs are `https://` | trusted-proxy configuration |
| Signing certificate not expired | `cert_expiry` |
| Application uses the provider | application `provider` |
| Each configured user may use the application | `GET core/applications/<slug>/check_access/?for_user=` |
| NameID is the user's email; `memberOf` contains `<access_group>`; first/last name and mail are non-empty (admin users) | `GET providers/saml/{id}/preview_user/?for_user=` (renders the real assertion attributes) |
| SCIM: hidden app carries the SCIM provider; each user with `groups` is in scope | application `backchannel_providers`; `check_access` on `<slug>-network` |
| SCIM: sync status, objects linked in Nile, and what the last run sent or would send | `providers/scim/{id}/sync/status/`, `providers/scim_users/`, `providers/scim_groups/`, task logs |

End-to-end test: open `https://u1.nile-global.cloud/` and enter the user's email. You should be
redirected to authentik, sign in, approve the consent screen (first time only), and land in the
Nile Portal as an administrator.

---

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| authentik: "Permission denied" / "access denied" | user is not in `<access_group>` |
| Okta/Nile: invalid issuer | Nile "IdP Issuer URI" ≠ `entityID` in authentik metadata (e.g. old value `authentik`) |
| Okta/Nile: signature invalid | certificate in Nile ≠ provider's signing keypair (keypair changed or rotated) |
| Okta/Nile: audience or recipient mismatch | `nile_sp` not filled in, or `apply` not re-run after filling it |
| Logged in without admin rights | Group mapping not `memberOf`/ARRAY, rule value ≠ `<access_group>`, or rule still INACTIVE |
| Nile doesn't redirect to authentik | email domain not added/verified in the tenant |
| Metadata shows `http://` URLs | `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS` doesn't include the tunnel/proxy |
| Users re-prompted for login more often since 2026.8 | authentik now honours the SP's `ForceAuthn` flag |
| SCIM: nothing appears in Nile | `dry_run` still true; user not in any `[scim]` group; or check `verify` for warnings |
| SCIM: 401/403 from Nile in task logs | wrong or revoked SCIM key: generate a new one in Nile and update `key_file` |
| SCIM: 409 / user already exists | the user was already created in Nile by another path. Discovery is off on purpose, so delete the Nile copy or enable discovery deliberately |
| Script: HTTP 403 from Cloudflare | Cloudflare blocks Python's default User-Agent. The script sends its own, so check WAF rules |

Events: authentik Admin > Events > Logs (filter by the application) shows each authorization and
the assertion that was sent.

---

## 7. Operations

### 7.1 Add another tenant

```
cp tenants/tenant.example.toml tenants/<new-domain>.toml && chmod 600 tenants/<new-domain>.toml
# edit: [authentik] url + token, [tenant] domain + access_group, [scim] groups, [[users]]
python3 scripts/nile_idp.py apply  tenants/<new-domain>.toml
# Nile: §4.1; save SP metadata -> [nile_sp] metadata_file; §4.5 SCIM key -> [scim] key_file
python3 scripts/nile_idp.py apply  tenants/<new-domain>.toml
# Nile: §4.3, §4.4
python3 scripts/nile_idp.py verify tenants/<new-domain>.toml
# SCIM: review "would send", then [scim] dry_run = false and apply again
```

The shared mappings and keypair are reused, not duplicated. A `[scim]` section without a key yet
is fine on the first run: the network groups and memberships are created in authentik, and the
SCIM provider and hidden application are created once `key_file` (or `token`) is set.

### 7.2 Add or change users

Add a `[[users]]` block and re-run `apply`. The script never removes memberships or users.
Offboard in authentik (deactivate the user, or remove them from `<access_group>`).

### 7.3 Rotate the signing certificate

1. Set `[signing] certificate` to a new name (e.g. `Nile SAML Signing 2036`) in every tenant
   config.
2. For each tenant: `apply`, then paste the new `idp-certificate.pem` into the Nile provider. Do
   this tenant by tenant, because a tenant fails to log in between the two steps.

### 7.4 Remove a tenant (manual)

Delete the application `<slug>`, the provider `Provider for Nile Portal - <domain>` and the group
`<access_group>` in authentik. Then delete the IdP in that Nile tenant. Leave the shared
objects alone.

---

## 8. Differences from `Authentik_Nile_Doc.pdf`

| PDF (2025.10.4) | Now (2026.8.5) | Why |
|---|---|---|
| `request.user.ak_groups.all()` | `request.user.groups.all()` | `ak_groups` deprecated in 2026.2 |
| Mappings named `firstName` … | `Nile: firstName` … | avoid changing mappings used by an existing tenant |
| 5 attributes (`mail` only) | 6 attributes, adds `email` | Nile SP metadata marks `email` required |
| Bind app to `authentik Admins` | bind to the tenant's group (`pod-nile-workshop-X`) | no authentik superuser rights for Nile users; tenant isolation |
| "Issuer" = `authentik` | Issuer override empty; issuer = per-tenant metadata URL | field renamed in 2026.5; default changed |
| SSO URL `/sso/binding/post/` | unified `/application/saml/<slug>/` | unified endpoint since 2026.5; old URL still works |
| `authentik Self-signed Certificate` | dedicated `Nile SAML Signing` keypair, 10 years | built-in cert valid 1 year; it expired 2026-09-20 |
| Slug = free text (`authentik`) | slug = tenant domain (`.` → `_`) | many tenants share one IdP |
| Manually edit provider with Nile entityID/Location | put Nile SP metadata in config, re-run `apply` | repeatable |
| "Two rules" (only one described) | one rule: Administrator → `pod-nile-workshop-X` | one group per tenant |
| Download metadata and cert from UI | written to `out/<domain>/` by the script | |

## 9. Existing state on authentik.nile.global (not managed by the script)

* Tenant `andrettiauthentik` (provider pk 10): built from the PDF. It uses the unprefixed
  mappings with `ak_groups`, binds `authentik Admins`, has issuer `authentik`, and signs with the
  **expired** `authentik Self-signed Certificate`. Consider migrating it to this model.
* Groups `NileAdmin`, `pod-nw3-access` and `pod-nw4-access` predate this setup and aren't used by
  it. Don't confuse them with the `pod-nile-workshop-N` groups.
