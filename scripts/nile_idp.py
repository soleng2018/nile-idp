#!/usr/bin/env python3
"""Federate a Nile Portal tenant with authentik (SAML 2.0 SSO, optional SCIM provisioning).

Idempotent: every command can be re-run safely. Objects are looked up by name
(or slug) and only created when missing; managed fields are updated in place.

    python3 scripts/nile_idp.py apply  tenants/<domain>.toml [--dry-run] [--set-passwords]
    python3 scripts/nile_idp.py show   tenants/<domain>.toml
    python3 scripts/nile_idp.py verify tenants/<domain>.toml

Requires Python 3.11+ (tomllib). No third-party packages.
See docs/authentik-nile-saml-spec.md for what each step does and why.
"""
import argparse
import json
import os
import re
import stat
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

PLACEHOLDER_ACS = "https://dummy.com"
SCIM_USER_MANAGED = "goauthentik.io/providers/scim/user"
SCIM_GROUP_MANAGED = "goauthentik.io/providers/scim/group"
NILE_SCIM_PATH = "/api/v1/scim"
# Shared authorization flow for the Nile providers. No stages, so there is no consent screen, and
# no bindings: the stock default flows carry a deny policy for booking-created learners
# (path hol/learners), who must be able to sign in to Nile. Access is decided by each
# application's group binding alone, which verify insists on.
NILE_FLOW = {"name": "Nile authorization", "title": "Redirecting to %(app)s", "slug": "nile-authorization",
             "designation": "authorization", "authentication": "require_authenticated",
             "policy_engine_mode": "any"}
GROUP_FLAG = "hol_testbed_group"   # attribute stamped (as boolean true) on every predefined group
MD_NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
REPO_ROOT = Path(__file__).resolve().parent.parent

# Shared across all tenants. Prefixed so they never collide with hand-made mappings.
# ak_groups is deprecated since 2026.2; groups is the replacement.
MAPPINGS = [
    ("Nile: firstName", "firstName",
     'return request.user.attributes.get("firstName") or (request.user.name.split(" ", 1)[0] if request.user.name else "")'),
    ("Nile: lastName", "lastName",
     'return request.user.attributes.get("lastName") or (request.user.name.split(" ", 1)[1] if " " in request.user.name else "")'),
    ("Nile: mail", "mail",
     'return request.user.attributes.get("mail") or request.user.email'),
    # Nile's SP metadata marks "email" (not "mail") as a required attribute.
    ("Nile: email", "email",
     'return request.user.attributes.get("mail") or request.user.email'),
    ("Nile: mobile", "mobile",
     'return request.user.attributes.get("mobile", "")'),
    ("Nile: memberOf", "memberOf",
     "for group in request.user.groups.all():\n    yield group.name"),
]

# The provider's NameID mapping, not an attribute: Nile routes logins by the domain of the
# NameID, so it has to be the user's Nile login (attributes.mail, else the username), never the
# user.email field, which holds the learner's real address.
NAMEID_MAPPING = ("Nile: NameID login", "nameid",
                  'return request.user.attributes.get("mail") or request.user.username')


def log(msg=""):
    print(msg, flush=True)


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------- config

def world_readable(path):
    # POSIX permission bits are meaningless on Windows (NTFS ACLs), so only warn elsewhere.
    return os.name != "nt" and path.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH)


def load_config(path):
    path = Path(path)
    if not path.is_file():
        die(f"config not found: {path}")
    with path.open("rb") as f:
        cfg = tomllib.load(f)

    ak = cfg.get("authentik", {})
    token = ak.get("token") or os.environ.get("AUTHENTIK_TOKEN", "")
    if ak.get("token") and world_readable(path):
        log(f"WARNING: {path} contains a token and is readable by others; run: chmod 600 {path}")
    if not token and ak.get("token_file"):
        token = Path(ak["token_file"]).expanduser().read_text().strip()
    if not token:
        die("no API token: set authentik.token, authentik.token_file, or $AUTHENTIK_TOKEN")
    if not ak.get("url"):
        die("authentik.url is required")

    t = cfg.get("tenant", {})
    domain = t.get("domain", "").strip().lower()
    if not domain:
        die("tenant.domain is required")
    # Slugs only allow [-a-zA-Z0-9_]; hostnames never contain '_', so this is reversible.
    slug = t.get("slug") or domain.replace(".", "_")
    app_name = t.get("app_name") or f"Nile Portal - {domain}"

    flows = cfg.get("flows", {})
    sp = cfg.get("nile_sp", {})
    if sp.get("metadata_file"):
        mf = Path(sp["metadata_file"]).expanduser()
        if not mf.is_absolute():
            mf = path.parent / mf
        entity_id, acs = parse_sp_metadata(mf)
        sp["entity_id"] = sp.get("entity_id") or entity_id
        sp["acs_url"] = sp.get("acs_url") or acs

    scim = load_scim(cfg.get("scim"), path, domain, slug)
    users = cfg.get("users", [])
    for u in users:
        extra = [g for g in u.get("groups", []) if not scim or g not in scim["groups"]]
        if extra:
            die(f"user {u.get('email')}: groups {extra} are not listed in [scim] groups")

    access_group = t.get("access_group") or die(
        f"tenant.access_group is required in {path} (e.g. \"NileWorkshop1Admin\")")
    # Nile Portal rejects group names with hyphens or other punctuation; use CamelCase.
    for g in [access_group] + (scim["groups"] if scim else []):
        if not re.fullmatch(r"[A-Za-z0-9]+", g):
            die(f"group name {g!r} must be letters and digits only (CamelCase, e.g. \"NileWorkshop1Admin\")")

    return {
        "url": ak["url"].rstrip("/"),
        "token": token,
        "domain": domain,
        "slug": slug,
        "app_name": app_name,
        "provider_name": f"Provider for {app_name}",
        "access_group": access_group,
        "launch_url": t.get("launch_url", ""),
        "issuer_override": t.get("issuer_override", ""),
        "authorization_flow": flows.get("authorization", NILE_FLOW["slug"]),
        "invalidation_flow": flows.get("invalidation", "default-provider-invalidation-flow"),
        "signing_certificate": cfg.get("signing", {}).get("certificate", "Nile SAML Signing"),
        "signing_validity_days": int(cfg.get("signing", {}).get("validity_days", 3650)),
        "sp_entity_id": sp.get("entity_id", ""),
        "sp_acs_url": sp.get("acs_url", ""),
        "users": users,
        "scim": scim,
        "out_dir": REPO_ROOT / "out" / domain,
    }


def load_scim(scim, path, domain, slug):
    """[scim] section -> dict, or None when SCIM is not configured for this tenant."""
    if not scim:
        return None
    key = {}
    if scim.get("key_file"):
        kf = Path(scim["key_file"]).expanduser()
        if not kf.is_absolute():
            kf = path.parent / kf
        if not kf.is_file():
            die(f"scim.key_file not found: {kf}")
        if world_readable(kf):
            log(f"WARNING: {kf} holds the SCIM key and is readable by others; run: chmod 600 {kf}")
        key = json.loads(kf.read_text())
    token = scim.get("token") or key.get("api_token", "")
    # Nile's key file only has the portal root (e.g. https://u1.nile-global.cloud).
    url = scim.get("url") or (key["url"].rstrip("/") + NILE_SCIM_PATH if key.get("url") else "")
    groups = scim.get("groups", [])
    if not groups:
        die("[scim] groups must list at least one group, e.g. [\"NileWorkshop1Employee\"]")
    return {
        # Without a key yet, groups and memberships are still created; the provider waits.
        "ready": bool(token and url),
        "url": url,
        "token": token,
        "groups": groups,
        "dry_run": bool(scim.get("dry_run", True)),
        "app_name": f"Nile Network - {domain}",
        "app_slug": f"{slug}-network",
        "provider_name": f"SCIM for Nile Network - {domain}",
    }


def parse_sp_metadata(path):
    """Return (entityID, HTTP-POST ACS Location) from the Nile/Okta SP metadata XML."""
    if not path.is_file():
        die(f"nile_sp.metadata_file not found: {path}")
    root = ET.parse(path).getroot()
    entity_id = root.get("entityID", "")
    acs = ""
    for el in root.iterfind(".//md:AssertionConsumerService", MD_NS):
        if el.get("Binding", "").endswith("HTTP-POST"):
            acs = el.get("Location", "")
            break
    if not entity_id or not acs:
        die(f"could not find entityID / HTTP-POST AssertionConsumerService in {path}")
    return entity_id, acs


# --------------------------------------------------------------------------- API

class Api:
    def __init__(self, base, token, dry_run=False):
        self.base = f"{base}/api/v3/"
        self.token = token
        self.dry_run = dry_run

    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            # Cloudflare rejects the default Python-urllib User-Agent.
            "User-Agent": "nile-idp-setup/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 404 and method == "GET":
                return None
            die(f"{method} {path} -> HTTP {e.code}: {e.read().decode(errors='replace')[:800]}")

    def get(self, path):
        return self._req("GET", path)

    def list(self, path, **params):
        params.setdefault("page_size", 100)
        page, out = 1, []
        while True:
            q = urllib.parse.urlencode({**params, "page": page})
            res = self.get(f"{path}?{q}")
            out += res["results"]
            if not res["pagination"]["next"]:
                return out
            page += 1

    def write(self, method, path, body=None, what=""):
        if self.dry_run:
            log(f"  [dry-run] {method} {path} {what}")
            return {"pk": f"<dry-run:{what or path}>"}
        return self._req(method, path, body)


def find_one(items, key, value):
    return next((i for i in items if i.get(key) == value), None)


# --------------------------------------------------------------------------- steps

def ensure_mapping(api, existing, body):
    """Create or update one SAML property mapping, matched by name. Returns its pk."""
    name = body["name"]
    cur = find_one(existing, "name", name)
    if not cur:
        cur = api.write("POST", "propertymappings/provider/saml/", body, name)
        log(f"  created  {name}")
    elif any(cur.get(k) != v for k, v in body.items()):
        api.write("PATCH", f"propertymappings/provider/saml/{cur['pk']}/", body, name)
        log(f"  updated  {name}")
    else:
        log(f"  ok       {name}")
    return cur["pk"]


def ensure_mappings(api):
    log("== SAML property mappings (shared)")
    existing = api.list("propertymappings/provider/saml/")
    pks = [ensure_mapping(api, existing, {"name": name, "saml_name": saml_name,
                                          "friendly_name": saml_name, "expression": expr})
           for name, saml_name, expr in MAPPINGS]
    # No friendly_name: the NameID is not emitted as an attribute, so it has nothing to label.
    name, saml_name, expr = NAMEID_MAPPING
    nameid_pk = ensure_mapping(api, existing, {"name": name, "saml_name": saml_name,
                                               "friendly_name": None, "expression": expr})
    return pks, nameid_pk


def ensure_group(api, name):
    # Predefined groups are flat (no parent) and carry hol_testbed_group = true (a JSON boolean).
    cur = find_one(api.list("core/groups/", name=name, include_users="false"), "name", name)
    if not cur:
        log(f"  created  group {name}")
        return api.write("POST", "core/groups/", {"name": name, "is_superuser": False,
                                                  "attributes": {GROUP_FLAG: True}}, name)["pk"]
    patch = {}
    attrs = cur.get("attributes") or {}
    if attrs.get(GROUP_FLAG) is not True:
        patch["attributes"] = {**attrs, GROUP_FLAG: True}
    # Newer authentik has a "parents" list; older ones a single "parent".
    if cur.get("parents"):
        patch["parents"] = []
    if cur.get("parent"):
        patch["parent"] = None
    if patch:
        api.write("PATCH", f"core/groups/{cur['pk']}/", patch, name)
        log(f"  updated  group {name} ({', '.join(patch)})")
    else:
        log(f"  ok       group {name}")
    return cur["pk"]


def ensure_users(api, cfg, group_pks, set_passwords):
    log("== Users")
    for u in cfg["users"]:
        username = u.get("username") or u["email"]
        email = u.get("email") or username
        if not username.lower().endswith("@" + cfg["domain"]):
            log(f"  WARNING  {username} is not in tenant domain {cfg['domain']}; Nile routes logins by the NameID domain")
        first, last = u.get("first_name", ""), u.get("last_name", "")
        # mail is the Nile login, which the NameID mapping sends; email may be the real address.
        attrs = {"mail": username, "firstName": first, "lastName": last, "mobile": str(u.get("mobile", ""))}
        name = u.get("name") or " ".join(p for p in (first, last) if p) or username

        cur = find_one(api.list("core/users/", username=username), "username", username)
        created = False
        if not cur:
            cur = api.write("POST", "core/users/", {
                "username": username, "name": name, "email": email, "is_active": True,
                "type": "internal", "path": "users", "attributes": attrs,
            }, username)
            created = True
            log(f"  created  {username}")
        else:
            merged = {**cur.get("attributes", {}), **attrs}
            if cur["name"] != name or cur["email"] != email or cur.get("attributes") != merged:
                api.write("PATCH", f"core/users/{cur['pk']}/",
                          {"name": name, "email": email, "attributes": merged}, username)
                log(f"  updated  {username}")
            else:
                log(f"  ok       {username}")

        # Additive membership: never removes the user from other tenants' groups.
        wanted = ([cfg["access_group"]] if u.get("admin", False) else []) + u.get("groups", [])
        if not wanted:
            log(f"  WARNING  {username} has admin = false and no groups: it can't sign in or be provisioned")
        current = set(cur.get("groups", []))
        for g in wanted:
            if group_pks[g] not in current:
                api.write("POST", f"core/groups/{group_pks[g]}/add_user/", {"pk": cur["pk"]}, f"{username} -> {g}")
                log(f"           + member of {g}")

        if u.get("password") and (created or set_passwords):
            api.write("POST", f"core/users/{cur['pk']}/set_password/", {"password": u["password"]}, f"password {username}")
            log("           password set")
        elif created:
            log("           no password in config: set one in the UI (Directory > Users > Set password)")


def ensure_signing_kp(api, cfg):
    """Shared signing keypair; generated if missing. Refuses expired certificates."""
    log("== Signing certificate (shared)")
    name = cfg["signing_certificate"]
    kp = find_one(api.list("crypto/certificatekeypairs/", name=name), "name", name)
    if not kp:
        kp = api.write("POST", "crypto/certificatekeypairs/generate/",
                       {"common_name": name, "validity_days": cfg["signing_validity_days"], "alg": "rsa"}, name)
        log(f"  created  {name} (valid {cfg['signing_validity_days']} days)")
        return kp["pk"]
    expiry = kp.get("cert_expiry", "")
    if expiry and datetime.fromisoformat(expiry) <= datetime.now(timezone.utc):
        die(f"certificate {name!r} expired on {expiry}; pick another [signing] certificate or rotate it")
    log(f"  ok       {name} (expires {expiry[:10]})")
    return kp["pk"]


def ensure_flow(api, cfg):
    """The providers' authorization flow, found by slug. Only the Nile flow is created or updated;
    a flow named in a tenant's [flows] is looked up and left alone. Never touches bindings."""
    log("== Authorization flow (shared)")
    slug = cfg["authorization_flow"]
    cur = api.get(f"flows/instances/{slug}/")
    if slug != NILE_FLOW["slug"]:
        if not cur:
            die(f"flow {slug} not found")
        log(f"  ok       {slug} (set in [flows], not managed)")
        return cur["pk"]
    if not cur:
        cur = api.write("POST", "flows/instances/", NILE_FLOW, slug)
        log(f"  created  {NILE_FLOW['name']} ({slug})")
    elif any(cur.get(k) != v for k, v in NILE_FLOW.items()):
        api.write("PATCH", f"flows/instances/{slug}/", NILE_FLOW, slug)
        log(f"  updated  {NILE_FLOW['name']} ({slug})")
    else:
        log(f"  ok       {NILE_FLOW['name']} ({slug})")
    return cur["pk"]


def flow_bindings(api, flow_pk):
    """Labels for every policy/group/user binding and stage binding on a flow.
    policies/bindings/ rejects a flow pk in ?target=, so that list is filtered here."""
    out = []
    for b in api.list("policies/bindings/"):
        if b.get("target") == flow_pk:
            obj = b.get("policy_obj") or b.get("group_obj") or b.get("user_obj") or {}
            kind = "policy" if b.get("policy") else "group" if b.get("group") else "user"
            out.append(f"{kind} {obj.get('name') or obj.get('username') or b['pk']}")
    for b in api.list("flows/bindings/", target=flow_pk):
        out.append(f"stage {(b.get('stage_obj') or {}).get('name') or b['stage']}")
    return out


def ensure_provider(api, cfg, mapping_pks, nameid_pk, signing_kp_pk, auth_flow_pk):
    log("== SAML provider")
    flow = lambda slug: (api.get(f"flows/instances/{slug}/") or die(f"flow {slug} not found"))["pk"]

    acs = cfg["sp_acs_url"] or PLACEHOLDER_ACS
    body = {
        "name": cfg["provider_name"],
        # Passed in rather than looked up here: in a dry run the Nile flow does not exist yet.
        "authorization_flow": auth_flow_pk,
        "invalidation_flow": flow(cfg["invalidation_flow"]),
        "acs_url": acs,
        "audience": cfg["sp_entity_id"],
        "issuer_override": cfg["issuer_override"],
        "sp_binding": "post",
        "signing_kp": signing_kp_pk,
        "sign_assertion": True,
        "sign_response": False,
        "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "name_id_mapping": nameid_pk,
        "property_mappings": mapping_pks,
        "assertion_valid_not_before": "minutes=-5",
        "assertion_valid_not_on_or_after": "minutes=5",
        "session_valid_not_on_or_after": "minutes=86400",
    }
    cur = find_one(api.list("providers/saml/", name=cfg["provider_name"]), "name", cfg["provider_name"])
    if not cur:
        cur = api.write("POST", "providers/saml/", body, cfg["provider_name"])
        log(f"  created  {cfg['provider_name']}")
    else:
        diff = [k for k, v in body.items()
                if (sorted(cur.get(k) or []) != sorted(v) if isinstance(v, list) else cur.get(k) != v)]
        if diff:
            api.write("PATCH", f"providers/saml/{cur['pk']}/", body, cfg["provider_name"])
            log(f"  updated  {cfg['provider_name']} ({', '.join(diff)})")
        else:
            log(f"  ok       {cfg['provider_name']}")
    if acs == PLACEHOLDER_ACS:
        log(f"  NOTE     ACS URL is the placeholder {PLACEHOLDER_ACS}; fill [nile_sp] after the Nile Portal step and re-run")
    return cur["pk"]


def ensure_application(api, cfg, provider_pk, access_group_pk):
    log("== Application")
    body = {"name": cfg["app_name"], "slug": cfg["slug"], "provider": provider_pk,
            "policy_engine_mode": "any", "meta_launch_url": cfg["launch_url"],
            "meta_description": f"Nile Portal tenant {cfg['domain']}"}
    cur = api.get(f"core/applications/{cfg['slug']}/")
    if not cur:
        cur = api.write("POST", "core/applications/", body, cfg["slug"])
        log(f"  created  {cfg['app_name']} (slug {cfg['slug']})")
    elif any(cur.get(k) != v for k, v in body.items()):
        api.write("PATCH", f"core/applications/{cfg['slug']}/", body, cfg["slug"])
        log(f"  updated  {cfg['app_name']}")
    else:
        log(f"  ok       {cfg['app_name']} (slug {cfg['slug']})")

    if api.dry_run and str(cur["pk"]).startswith("<dry-run"):
        log(f"  [dry-run] bind group {cfg['access_group']}")
        return
    bindings = api.list("policies/bindings/", target=cur["pk"])
    if any(b.get("group") == access_group_pk for b in bindings):
        log(f"  ok       bound to group {cfg['access_group']}")
    else:
        api.write("POST", "policies/bindings/", {"target": cur["pk"], "group": access_group_pk, "order": 0,
                                                 "enabled": True, "negate": False, "timeout": 30},
                  f"bind {cfg['access_group']}")
        log(f"  created  binding to group {cfg['access_group']}")


def ensure_bindings(api, app_pk, group_pks, names):
    if api.dry_run and str(app_pk).startswith("<dry-run"):
        log(f"  [dry-run] bind groups {', '.join(names)}")
        return
    bound = {b.get("group") for b in api.list("policies/bindings/", target=app_pk)}
    for order, name in enumerate(names):
        if group_pks[name] in bound:
            log(f"  ok       bound to group {name}")
        else:
            api.write("POST", "policies/bindings/", {"target": app_pk, "group": group_pks[name], "order": order,
                                                     "enabled": True, "negate": False, "timeout": 30},
                      f"bind {name}")
            log(f"  created  binding to group {name}")


def ensure_scim(api, cfg, group_pks):
    """SCIM provider pushing the network groups and their members to Nile.

    authentik only syncs users bound to the SCIM provider's application, so SCIM gets its own
    hidden application bound to the network groups. Binding them to the Portal app instead would
    also let those users sign in to the Nile Portal.
    """
    scim = cfg["scim"]
    log("== SCIM provider")
    cur = find_one(api.list("providers/scim/", name=scim["provider_name"]), "name", scim["provider_name"])
    # An existing provider keeps its token, so updating it only needs the url.
    if not scim["ready"] and not (cur and scim["url"]):
        log("  NOTE     [scim] has no key_file/token (and url) yet: groups are created, the SCIM provider is not.")
        log("           Add the Nile SCIM key file to [scim] key_file and re-run apply.")
        return None
    token = {"token": scim["token"]} if scim["token"] else {}
    mappings = api.list("propertymappings/provider/scim/")
    user_map = find_one(mappings, "managed", SCIM_USER_MANAGED) or die(f"{SCIM_USER_MANAGED} not found")
    group_map = find_one(mappings, "managed", SCIM_GROUP_MANAGED) or die(f"{SCIM_GROUP_MANAGED} not found")
    body = {
        "name": scim["provider_name"],
        "url": scim["url"],
        "auth_mode": "token",
        # Nile has no /ServiceProviderConfig; authentik then falls back to no PATCH/filter/bulk.
        "compatibility_mode": "default",
        "verify_certificates": True,
        "exclude_users_service_account": True,
        # Only touch objects authentik created; leave users made by other IdPs alone.
        "discovery_enabled": False,
        "group_filters": [group_pks[g] for g in scim["groups"]],
        "property_mappings": [user_map["pk"]],
        "property_mappings_group": [group_map["pk"]],
        "dry_run": scim["dry_run"],
    }
    # The token is write-only in the API, so it is sent whenever known and can't be diffed.
    if not cur:
        cur = api.write("POST", "providers/scim/", {**body, **token}, scim["provider_name"])
        log(f"  created  {scim['provider_name']}")
    else:
        diff = [k for k, v in body.items()
                if (sorted(cur.get(k) or []) != sorted(v) if isinstance(v, list) else cur.get(k) != v)]
        api.write("PATCH", f"providers/scim/{cur['pk']}/", {**body, **token}, scim["provider_name"])
        log(f"  {'updated ' if diff else 'ok      '} {scim['provider_name']}" + (f" ({', '.join(diff)})" if diff else ""))
    log(f"  NOTE     dry_run = {scim['dry_run']}" + (": nothing is written to Nile" if scim["dry_run"] else ": LIVE, writes to Nile"))

    log("== SCIM application")
    app_body = {"name": scim["app_name"], "slug": scim["app_slug"], "provider": None,
                "backchannel_providers": [cur["pk"]], "policy_engine_mode": "any", "meta_hide": True,
                "meta_description": f"SCIM provisioning of network groups to Nile tenant {cfg['domain']}"}
    app = api.get(f"core/applications/{scim['app_slug']}/")
    if not app:
        app = api.write("POST", "core/applications/", app_body, scim["app_slug"])
        log(f"  created  {scim['app_name']} (slug {scim['app_slug']}, hidden)")
    elif any(app.get(k) != v for k, v in app_body.items()):
        api.write("PATCH", f"core/applications/{scim['app_slug']}/", app_body, scim["app_slug"])
        log(f"  updated  {scim['app_name']}")
    else:
        log(f"  ok       {scim['app_name']} (slug {scim['app_slug']}, hidden)")
    ensure_bindings(api, app["pk"], group_pks, scim["groups"])
    return cur["pk"]


# --------------------------------------------------------------------------- outputs

def nile_values(api, cfg):
    """Fetch the values the Nile Portal 'Add a new provider' form needs, write them to out/<domain>/."""
    prov = find_one(api.list("providers/saml/", name=cfg["provider_name"]), "name", cfg["provider_name"])
    if not prov:
        die(f"provider {cfg['provider_name']!r} does not exist yet; run 'apply' first")
    xml = api.get(f"providers/saml/{prov['pk']}/metadata/")["metadata"]
    root = ET.fromstring(xml)
    issuer = root.get("entityID")
    sso = next((e.get("Location") for e in root.iterfind(".//md:SingleSignOnService", MD_NS)
                if e.get("Binding", "").endswith("HTTP-POST")), "")
    pem = api.get(f"crypto/certificatekeypairs/{prov['signing_kp']}/view_certificate/")["data"].strip()
    body = "".join(l for l in pem.splitlines() if "CERTIFICATE" not in l)

    out = cfg["out_dir"]
    out.mkdir(parents=True, exist_ok=True)
    (out / "idp-metadata.xml").write_text(xml)
    (out / "idp-certificate.pem").write_text(pem + "\n")
    summary = f"""# Nile Portal values for {cfg['domain']}

GLOBAL SETTINGS -> Identity -> Providers -> ADD A NEW PROVIDER

| Nile field       | Value |
|------------------|-------|
| Protocol         | SAML2 |
| IdP Issuer URI   | {issuer} |
| IdP SSO URL      | {sso} |
| Destination URL  | {sso} |
| IdP Certificate  | contents of idp-certificate.pem (below) |
| SSO Timeout      | 60 Days |

Legacy SSO URL (equivalent; use only if the one above is rejected):
{prov['url_sso_post']}

## IdP Certificate (PEM)

{pem}

## IdP Certificate (base64 body only, if the field rejects the BEGIN/END lines)

{body}

## Group rules (GLOBAL SETTINGS -> Identity -> Group rules)

Group mapping: Friendly name = memberOf, External name = memberOf, Type = ARRAY
Rule: Nile Administrator <- memberOf contains "{cfg['access_group']}"

## authentik side (for reference)

Application slug : {cfg['slug']}
Access group     : {cfg['access_group']}
ACS URL          : {prov['acs_url']}
Audience         : {prov['audience'] or '(empty - fill [nile_sp] and re-run apply)'}
Metadata URL     : {prov['url_download_metadata']}
"""
    (out / "nile-portal-values.md").write_text(summary)
    return summary, prov


def cmd_apply(api, cfg, args):
    log(f"Tenant {cfg['domain']}  ->  {cfg['url']}  (app slug {cfg['slug']})" + ("  [DRY RUN]" if args.dry_run else ""))
    mapping_pks, nameid_pk = ensure_mappings(api)
    log("== Groups")
    names = [cfg["access_group"]] + (cfg["scim"]["groups"] if cfg["scim"] else [])
    group_pks = {g: ensure_group(api, g) for g in names}
    ensure_users(api, cfg, group_pks, args.set_passwords)
    signing_kp_pk = ensure_signing_kp(api, cfg)
    auth_flow_pk = ensure_flow(api, cfg)
    provider_pk = ensure_provider(api, cfg, mapping_pks, nameid_pk, signing_kp_pk, auth_flow_pk)
    ensure_application(api, cfg, provider_pk, group_pks[cfg["access_group"]])
    if cfg["scim"]:
        ensure_scim(api, cfg, group_pks)
    if args.dry_run:
        return
    summary, _ = nile_values(api, cfg)
    log("")
    log(summary)
    log(f"Written to {cfg['out_dir']}/")


def cmd_show(api, cfg, args):
    summary, _ = nile_values(api, cfg)
    log(summary)


def cmd_verify(api, cfg, args):
    _, prov = nile_values(api, cfg)
    ok = True
    def check(cond, msg):
        nonlocal ok
        ok &= bool(cond)
        log(f"  [{'PASS' if cond else 'FAIL'}] {msg}")

    log(f"== Verify {cfg['domain']}")
    check(prov["acs_url"] != PLACEHOLDER_ACS, f"ACS URL set from Nile ({prov['acs_url']})")
    check(prov["audience"], f"Audience set from Nile ({prov['audience'] or 'empty'})")
    # A provider left pointing at another tenant's Nile provider passes the two checks above,
    # so compare it with [nile_sp] as well: it catches a stale run and a mixed-up metadata file.
    if cfg["sp_acs_url"]:
        check(prov["acs_url"] == cfg["sp_acs_url"],
              "ACS URL matches [nile_sp]" + ("" if prov["acs_url"] == cfg["sp_acs_url"]
                                             else f" (config has {cfg['sp_acs_url']}; re-run apply)"))
        check(prov["audience"] == cfg["sp_entity_id"],
              "Audience matches [nile_sp]" + ("" if prov["audience"] == cfg["sp_entity_id"]
                                              else f" (config has {cfg['sp_entity_id']}; re-run apply)"))
    check(prov["url_download_metadata"].startswith("https://"), "metadata URLs are https (trusted proxy config OK)")
    kp = api.get(f"crypto/certificatekeypairs/{prov['signing_kp']}/")
    expiry = kp.get("cert_expiry", "")
    check(expiry and datetime.fromisoformat(expiry) > datetime.now(timezone.utc),
          f"signing certificate {kp['name']!r} not expired (expires {expiry[:10]})")
    app = api.get(f"core/applications/{cfg['slug']}/")
    check(app and app.get("provider") == prov["pk"], f"application {cfg['slug']} uses this provider")

    flow = find_one(api.list("flows/instances/"), "pk", prov["authorization_flow"]) or {}
    check(flow.get("slug") == cfg["authorization_flow"],
          f"authorization flow is {cfg['authorization_flow']}"
          + ("" if flow.get("slug") == cfg["authorization_flow"] else f" (provider has {flow.get('slug')}; re-run apply)"))
    if flow.get("slug") == NILE_FLOW["slug"]:
        # The flow lets every authenticated user through, so it must stay empty, and the
        # application's own binding is the only thing keeping other users (e.g. learners) out.
        extra = flow_bindings(api, flow["pk"])
        check(not extra, f"flow {flow['slug']} has no bindings" + (f" (found: {', '.join(extra)})" if extra else ""))
        gates = [b for b in api.list("policies/bindings/", target=app["pk"]) if b["enabled"] and not b["negate"]] if app else []
        check(gates, f"application {cfg['slug']} has an enabled, non-negated policy or group binding")

    for u in cfg["users"]:
        username = u.get("username") or u["email"]
        user = find_one(api.list("core/users/", username=username), "username", username)
        if not user:
            check(False, f"user {username} exists")
            continue
        if not u.get("admin", False):
            continue
        access = api.get(f"core/applications/{cfg['slug']}/check_access/?for_user={user['pk']}")
        check(access and access.get("passing"), f"{username} is allowed to use the application")
        preview = api.get(f"providers/saml/{prov['pk']}/preview_user/?for_user={user['pk']}")
        preview = (preview or {}).get("preview", {})
        attrs = {a["Name"]: a["Value"] for a in preview.get("attributes", [])}
        log(f"         NameID  = {preview.get('nameID')}")
        for k, v in attrs.items():
            log(f"         {k:<8}= {v}")
        check(preview.get("nameID", "").lower() == username.lower(), "NameID is the user's Nile login")
        check(cfg["access_group"] in attrs.get("memberOf", []), f"memberOf contains {cfg['access_group']}")
        for a in ("firstName", "lastName", "email", "mail"):
            check(any(attrs.get(a, [])), f"{a} is non-empty")
    if cfg["scim"]:
        verify_scim(api, cfg, check)
    log("")
    log("All checks passed." if ok else "Some checks FAILED.")
    sys.exit(0 if ok else 1)


def verify_scim(api, cfg, check):
    scim = cfg["scim"]
    log(f"== Verify SCIM ({scim['url'] or 'no url'})")
    prov = find_one(api.list("providers/scim/", name=scim["provider_name"]), "name", scim["provider_name"])
    if not scim["ready"] and not prov:
        log("         SCIM not configured yet ([scim] key_file/token missing); skipped")
        return
    if not prov:
        check(False, f"SCIM provider {scim['provider_name']!r} exists")
        return
    app = api.get(f"core/applications/{scim['app_slug']}/")
    check(app and prov["pk"] in app.get("backchannel_providers", []),
          f"{scim['app_slug']} carries the SCIM provider as backchannel")
    for u in cfg["users"]:
        if not u.get("groups"):
            continue
        username = u.get("username") or u["email"]
        user = find_one(api.list("core/users/", username=username), "username", username)
        if user:
            access = api.get(f"core/applications/{scim['app_slug']}/check_access/?for_user={user['pk']}")
            check(access and access.get("passing"), f"{username} is in SCIM scope ({', '.join(u['groups'])})")
    status = api.get(f"providers/scim/{prov['pk']}/sync/status/") or {}
    log(f"         sync: running={status.get('is_running')} last_status={status.get('last_sync_status')} "
        f"last_success={status.get('last_successful_sync')}")
    synced_users = api.list("providers/scim_users/", provider__id=prov["pk"])
    synced_groups = api.list("providers/scim_groups/", provider__id=prov["pk"])
    log(f"         objects linked in Nile: {len(synced_users)} users, {len(synced_groups)} groups")
    if prov["dry_run"]:
        log("         dry_run is on: authentik computed the sync but wrote nothing to Nile")
    scim_sync_report(api, prov)


def scim_sync_report(api, prov):
    """Print what the most recent sync run did (or would do, in dry run), from authentik's task logs."""
    sched = api.list("tasks/schedules/", rel_obj_id=str(prov["pk"]), rel_obj_content_type__model="scimprovider")
    if not sched:
        return
    tasks = api.get(f"tasks/tasks/?ordering=-mtime&page_size=20&rel_obj_id={sched[0]['id']}")["results"]
    # A full sync is one scim_sync task plus the scim_sync_objects pages it queues. The parent
    # finishes last, so newest-first it comes first; stop at the previous run's parent.
    run = []
    for t in tasks:
        if t["actor_name"].endswith(".scim_sync") and any(r["actor_name"].endswith(".scim_sync") for r in run):
            break
        run.append(t)
    log(f"         last sync run ({len(run)} task(s), full sync schedule: {sched[0].get('crontab')}):")
    for t in reversed(run):
        for m in api.get(f"tasks/tasks/{t['message_id']}/").get("logs", []):
            a = m.get("attributes", {})
            if "dry run" in m["event"]:
                obj = a.get("obj", {})
                body = a.get("body") or {}
                what = body.get("userName") or body.get("displayName") or obj.get("name") or obj.get("username")
                n = len(body.get("members", [])) if "members" in body else None
                log(f"           would send  {a.get('url', '').rsplit('/', 1)[-1]:<6} {what}" + (f" ({n} members)" if n is not None else ""))
            elif m.get("log_level") in ("warning", "error"):
                log(f"           {m['log_level'].upper():<11} {m['event']} {json.dumps(a)[:300]}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["apply", "show", "verify"])
    p.add_argument("config", help="tenant TOML file, e.g. tenants/example.com.toml")
    p.add_argument("--dry-run", action="store_true", help="apply: print changes without making them")
    p.add_argument("--set-passwords", action="store_true",
                   help="apply: (re)set passwords for existing users from config (default: only on creation)")
    args = p.parse_args()
    cfg = load_config(args.config)
    api = Api(cfg["url"], cfg["token"], dry_run=args.dry_run)
    {"apply": cmd_apply, "show": cmd_show, "verify": cmd_verify}[args.command](api, cfg, args)


if __name__ == "__main__":
    main()
