# nile-idp

Connect Nile Portal tenants to **authentik** as their identity provider:

* **SSO (SAML 2.0):** tenant administrators sign in to the Nile Portal with their authentik account.
* **SCIM (optional):** authentik pushes network groups (e.g. `NileWorkshop2Employee`,
  `NileWorkshop2Contractor`) and their members to Nile, which uses them to grant network
  access.

One authentik serves many Nile Portal tenants. Each tenant is described by **one parameters file**,
`tenants/<domain>.toml`. It holds the URLs, keys, group names and users. A script reads that file
and configures authentik. The Nile Portal side is a short manual checklist.

| | |
|---|---|
| Script | [scripts/nile_idp.py](scripts/nile_idp.py) (Python 3.11+, standard library only) |
| Parameters template | [tenants/tenant.example.toml](tenants/tenant.example.toml) |
| Specification (what is configured and why) | [docs/authentik-nile-saml-spec.md](docs/authentik-nile-saml-spec.md) |
| Tested with | authentik 2026.8.5, Nile Portal `u1.nile-global.cloud` |
| Original vendor guide (authentik 2025.10, outdated) | `Authentik_Nile_Doc.pdf` |

---

## What you need

* **Python 3.11 or newer.** Check with `python3 --version` (Windows: `py -3 --version`).
  Nothing to `pip install`.
* **Network access** from your PC to the authentik URL.
* **An authentik API token** for a superuser (see step 2).
* **Administrator access** to the Nile Portal tenant.

---

## Bring up a new tenant (example: Nile Workshop 2)

Overview: a first script run creates the authentik side, you then add the provider in Nile, and a
second run puts the Nile values back into authentik.

```
 1. clone            ─┐
 2. API token         │  once per PC
 3. parameters file  ─┘
 4. apply            → authentik: groups, users, SAML provider, app   → out/<domain>/nile-portal-values.md
 5. Nile: add IdP    ← values from out/…        → download Nile METADATA xml (+ SCIM key json)
 6. apply again      → authentik: ACS/Audience from Nile metadata, SCIM provider
 7. Nile: group rule, domain
 8. verify           → all PASS; test login
 9. SCIM go live     (optional) dry_run = false → apply → groups appear in Nile
```

### 1. Get the code

```bash
git clone <repo-url> nile-idp
cd nile-idp
```

### 2. Get an authentik API token

You can reuse a token you already have. Otherwise, in the authentik Admin interface:

1. **Directory > Users > Create Service account**, e.g. `nile-idp-automation`. Add it to the
   `authentik Admins` group.
2. **Directory > Tokens and App passwords > Create**: user = that account, intent **API**, short
   expiry. Copy the key.

Delete or expire the token when you're done.

### 3. Create the parameters file

```bash
cp tenants/tenant.example.toml tenants/nileworkshop-2.com.toml
chmod 600 tenants/nileworkshop-2.com.toml        # Windows: skip
```

Edit it. The template is already filled in for Workshop 2. Every field is explained in the file.

| Section | What to set now | Later |
|---|---|---|
| `[authentik]` | `url`, and `token` (or `token_file`) | |
| `[tenant]` | `domain` (e.g. `nileworkshop-2.com`), `access_group` (e.g. `NileWorkshop2Admin`). Group names must be CamelCase letters and digits: Nile rejects hyphens | |
| `[signing]` | leave as is | |
| `[nile_sp]` | leave empty | step 6: `metadata_file` |
| `[scim]` | `groups` (e.g. `NileWorkshop2Employee`, `NileWorkshop2Contractor`), `dry_run = true`. Delete the section if you don't want SCIM | step 6: `key_file` |
| `[[users]]` | one block per user. `admin = true` → Portal admin; `groups = [...]` → SCIM network groups | |

Everything else in `tenants/` is **gitignored**: your parameters file, the Nile metadata and the
SCIM key. They never get committed.

### 4. First run: configure authentik

```bash
python3 scripts/nile_idp.py apply tenants/nileworkshop-2.com.toml --dry-run   # preview, changes nothing
python3 scripts/nile_idp.py apply tenants/nileworkshop-2.com.toml
```

This creates:
* the tenant's groups and users
* the SAML provider, with a placeholder ACS URL for now
* the application, slug `nileworkshop-2_com`

The shared pieces (SAML mappings, signing certificate) already exist from Workshop 1 and are reused.
The output says "SCIM provider not created yet". That's expected.

The values for Nile are printed and saved to **`out/nileworkshop-2.com/nile-portal-values.md`**,
with `idp-certificate.pem` alongside.

If no password was given in the parameters file, set one for each user in authentik:
Directory > Users > user > **Set password**.

### 5. Nile Portal: add the identity provider

In the Workshop 2 Nile Portal, go to GLOBAL SETTINGS > Identity > Providers > **ADD A NEW PROVIDER**:

| Nile field | Value from `out/nileworkshop-2.com/nile-portal-values.md` |
|---|---|
| Protocol | SAML2 |
| IdP Issuer URI | IdP Issuer URI |
| IdP SSO URL | IdP SSO URL |
| Destination URL | IdP SSO URL |
| IdP Certificate | contents of `idp-certificate.pem` |
| SSO Timeout | 60 Days |

Click **SUBMIT**. Then:

* Click **METADATA** on the new provider and save the XML into `tenants/`.
* *(SCIM)* On the same provider: **SCIM Configuration > ADD SCIM KEY**, then save the downloaded
  `scim_api_key-<n>.json` into `tenants/` (`chmod 600` it).

### 6. Second run: give authentik the Nile values

In `tenants/nileworkshop-2.com.toml`:

```toml
[nile_sp]
metadata_file = "nile-idp-metadata-<...>.xml"

[scim]
key_file = "scim_api_key-<n>.json"
```

```bash
python3 scripts/nile_idp.py apply tenants/nileworkshop-2.com.toml
```

The SAML provider gets the real ACS URL and Audience. The SCIM provider is created, still in dry-run
mode.

### 7. Nile Portal: group rule and domain

GLOBAL SETTINGS > Identity > **Group rules**:

1. **ADD GROUP MAPPING**: Friendly name `memberOf`, External name `memberOf`, Type `ARRAY`. Click **SAVE**.
2. **ADD GROUP RULE**: Administrator, value `NileWorkshop2Admin` (your `access_group`).
3. Switch the rule from **INACTIVE** to **ACTIVE**.

Account Management > Domains > **Add Domain** `nileworkshop-2.com`, then click **Verify**.

### 8. Verify

```bash
python3 scripts/nile_idp.py verify tenants/nileworkshop-2.com.toml
```

Every check should print `PASS`. With SCIM in dry run, `verify` also lists what authentik
**would send** to Nile.

Then open `https://u1.nile-global.cloud/`, enter an admin user's email, sign in at authentik
(approve the consent screen the first time), and confirm you land in the Portal as Administrator.

### 9. SCIM: go live (optional)

Once the dry-run list looks right, set `dry_run = false` in `[scim]` and run `apply` again. Then
run `verify`. It shows the users and groups linked in Nile, and the groups appear in the Nile
Portal. Use them in your network access policies.

From then on, authentik pushes changes straight away: new members, removed members, deactivated
users, deleted groups. It also runs a full sync every 4 hours.

---

## Day-to-day

| Task | How |
|---|---|
| Add a Portal admin | `[[users]]` with `admin = true`, then `apply` |
| Add a network user | `[[users]]` with `admin = false`, `groups = ["NileWorkshop2Employee"]`, then `apply`. Users added to the group in the authentik UI are pushed too |
| Add a network group | append it to `[scim] groups`, then `apply`. It appears in Nile within seconds |
| Remove a network group | remove it from `[scim] groups` **and** delete the group in authentik. It disappears from Nile |
| Remove a user's access | remove them from the group, or deactivate them, in the authentik UI. SCIM deprovisions them in Nile. `apply` only ever *adds* memberships |
| Reset passwords from the file | `apply --set-passwords` |
| Reprint the Nile values | `show` |

## Commands

```
python3 scripts/nile_idp.py apply  <file> [--dry-run] [--set-passwords]
python3 scripts/nile_idp.py show   <file>
python3 scripts/nile_idp.py verify <file>
```

| Command | What it does |
|---|---|
| `apply` | Create or update everything in authentik for that tenant, then write `out/<domain>/`. Safe to re-run. `--dry-run` previews without changes. |
| `show` | Reprint and rewrite the Nile Portal values. Changes nothing. |
| `verify` | Check the SAML provider, certificate, admin access and the rendered assertion. With SCIM: scope, sync status, what's linked in Nile, and what the last sync sent or would send. Exits non-zero on failure. |

On Windows, use `py -3 scripts\nile_idp.py ...`.

## What gets created in authentik

| Object | Per | Name |
|---|---|---|
| SAML property mappings | shared | `Nile: firstName`, `lastName`, `mail`, `email`, `mobile`, `memberOf` |
| Signing keypair | shared | `Nile SAML Signing` (10 years) |
| Portal admin group | tenant | `access_group`, e.g. `NileWorkshop2Admin` |
| SAML provider + application | tenant | `Nile Portal - <domain>`, slug `<domain, . → _>` |
| SCIM network groups | tenant | `[scim] groups` |
| SCIM provider + hidden application | tenant | `SCIM for Nile Network - <domain>`, app `Nile Network - <domain>` |

Network users are provisioned through a separate hidden application, so they **can't** sign in to
the Nile Portal unless they also have `admin = true`. Details are in the
[specification](docs/authentik-nile-saml-spec.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ERROR: no API token` | set `[authentik] token` or `token_file` in the parameters file |
| `HTTP 403` on every call | token wrong, expired, or not a superuser |
| `tomllib` import error | Python is older than 3.11 |
| authentik says "access denied" at login | user not in `access_group` (`admin = true` missing) |
| Nile: invalid issuer / signature | Nile provider values don't match `out/<domain>/nile-portal-values.md` |
| Logged in without admin rights | group rule value ≠ `access_group`, or the rule is inactive |
| Groups not in Nile | `dry_run` still true, `key_file` not set, or check `verify` for warnings |

More is in the [specification](docs/authentik-nile-saml-spec.md), §6.

## Repository layout

```
README.md                          this file
docs/authentik-nile-saml-spec.md   detailed specification
scripts/nile_idp.py                the script (apply / show / verify)
tenants/tenant.example.toml        parameters template (the only committed file in tenants/)
tenants/<domain>.toml              your parameters files               (gitignored, secrets)
tenants/*.xml, *.json              Nile metadata and SCIM key files    (gitignored, secrets)
out/<domain>/                      generated Nile values and IdP cert  (gitignored)
Authentik_Nile_Doc.pdf             original vendor guide (outdated)
```

## Security

* Parameters files and SCIM key files are secrets. Keep them in `tenants/` (gitignored) and
  `chmod 600` them. On a shared machine, prefer `token_file` or `AUTHENTIK_TOKEN` over a token in the file.
* Nile users are never added to `authentik Admins`. Nile access gives no admin rights in authentik.
* Each tenant's Portal app is bound only to its own `access_group`, so users of one tenant can't
  get an assertion for another.
