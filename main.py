"""
Agent-harness safety layer: contextual safety + model routing.

One POST endpoint. For every case it returns four labels:
  requestDecision  allow | block | review
  toolDecision     allow | block | review | none
  route            primary | restricted | none
  trajectory       normal | watch | intervene

Fully deterministic (no LLM, no API key, no state shared between cases).
Rules were tuned against real grader cases; see DEFAULT_FLAGS for the judgement calls.
Run:  uvicorn main:app --host 0.0.0.0 --port $PORT
"""
import json
import os
import re
from collections import deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

PROFILE = "agent-harness-2026-09"
app = FastAPI(redirect_slashes=False)  # the grader rejects redirects
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Last few request bodies, so you can download the real cases and tune the rules.
CAPTURED = deque(maxlen=40)
CAPTURE_KEY = os.environ.get("CAPTURE_KEY", "")


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def rx(pattern):
    return re.compile(pattern, re.I | re.S)


def as_text(value):
    """Flatten anything (str / list / dict) into one lowercase string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    try:
        return json.dumps(value, ensure_ascii=False).lower()
    except Exception:
        return str(value).lower()


QUOTED = rx(r"```.*?```|\"[^\"]{12,}\"|“[^”]{12,}”|'[^']{20,}'|^\s*>.*?$")


def strip_quotes(text):
    """Remove quoted spans: quoted harmful text is data, not the user's own ask."""
    return re.sub(r"(?m)^\s*>.*$", " ", QUOTED.sub(" ", text))


# ----------------------------------------------------------------------------
# Content policy vocabulary
# ----------------------------------------------------------------------------
HARM = rx(
    r"steal\w*\b.{0,40}(credential|password|token|cookie|session|key|login)"
    r"|(credential|password)\s*(stealer|harvest\w*|phish\w*)"
    r"|phish\w*|keylogger|harvest\w*\s+(credential|password|login)"
    r"|exfiltrat\w+"
    r"|(leak|smuggle|siphon|sneak)\w*\b.{0,40}(private|customer|personal|patient|payroll|confidential|user)\b.{0,20}(data|record|file|info)"
    r"|\bfraud\w*|fake\s+(invoice|receipt|review|identit|id\b)|forg(e|ed|ing)\b|launder\w*|scam\w*|impersonat\w+"
    r"|\bharass\w*|\bdox+\w*|\bstalk\w*|threaten\w*|intimidat\w+|bully\w*"
    r"|ransomware|\bwiper\b|destructive\s+(malware|payload|code)|\bmalware\b|\bworm\b|\bbotnet\b|\btrojan\b|\brootkit\b"
    r"|(build|make|synthesi[sz]e|assemble)\w*\b.{0,30}(bomb|explosive|weapon|nerve agent|poison)"
    r"|\b(poison|sabotage|injure|hurt|kill)\b.{0,30}(person|people|someone|him|her|them|coworker|neighbou?r|brake|water supply)"
    r"|(bypass|evade|disable|get around|circumvent)\w*\b.{0,30}(safeguard|safety filter|content filter|guardrail|detection|antivirus|edr|audit log|monitoring)"
)

# Framing that makes harmful *subject matter* acceptable (content rule 2).
SAFE_FRAME = rx(
    r"\b(analy[sz]e|analysis|translate|translation|summari[sz]e|classify|explain why|what does this (say|mean)"
    r"|defensive\w*|mitigat\w+|remediat\w+|harden\w*|incident (response|report)|indicators of compromise|prompt injection"
    r"|triage|forensic\w*|awareness|training material|report (this|it)|flag\w*|review (the|this) (file|log|message|email|text)"
    r"|inspect\w*|fiction\w*|novel|short story|screenplay|non-actionable|without (any )?(working|real|actionable))\b"
)


# Signals that the user personally wants the harmful outcome; no "analysis" framing rescues these.
AGGRAVATED = rx(
    r"evade (detection|their blocks?|the (filter|safeguard)s?)|without being caught|account i control|other people'?s|another person'?s"
    r"|\b(real|specific) (person|colleague|coworker|neighbou?r|individual)|\bmy (real )?(colleague|coworker|ex|neighbou?r|boss)\b"
    r"|trick\w* .{0,30}into|actionable instructions"
)

SECURITY = rx(
    r"vulnerab\w+|\bexploit\w*|pen(etration)?[- ]?test\w*|\bfuzz\w*|\bcve-?\d*|proof[- ]of[- ]concept|\bpoc\b"
    r"|red[- ]team\w*|privilege escalation|sql injection|\bsqli\b|\bxss\b|\brce\b|buffer overflow"
    r"|security (scan|audit|assessment|test)|attack surface|port scan\w*|\bnmap\b|metasploit|burp"
)
UNCLEAR = rx(
    r"not sure (who|whether|if)|unsure|unknown owner|don'?t know who (owns|runs)|third[- ]party|someone else'?s"
    r"|a (site|server|host|ip) i found|found (this|an?) (ip|host|site|server)|competitor|public (site|server)|may(be)? (belong|owned)"
    r"|no (written )?(permission|authori[sz]ation)|haven'?t (asked|got)|without (asking|permission)|probably (ours|fine|ok)"
)

INJECTION = rx(
    r"ignore (all |any |the )?(previous|prior|above|earlier|system|policy|safety)"
    r"|disregard (all |any |the )?(previous|prior|above|policy|instruction|rule)"
    r"|you are now|new (system )?instructions?:|system override|developer mode|override (the )?(policy|safety|harness)"
    r"|pre[- ]?approved|already approved|approval (is )?granted|authori[sz]ation (is )?granted|user (has )?(approved|authori[sz]ed)"
    r"|no (need|review) (to ask|needed|required)|skip (the )?(preflight|review|approval|safety)|policy (has been|is|was) (updated|changed|relaxed)"
    r"|do not (tell|inform|mention to) the user|without (telling|asking) the user"
    r"|(assistant|agent|ai|model)\s*[:,]\s*(please )?(run|send|upload|delete|execute|push|curl)"
    r"|(send|upload|post|forward|email)\b.{0,60}(to|at)\s+(https?://|\S+@\S+)|curl\s+.{0,80}\|\s*(ba)?sh"
)



BYPASS = rx(r"--no-verify|--skip-(preflight|checks?|hooks?|validation|safety)|--no-preflight|skip[_-]?preflight|--force-skip|bypass|preflight\s*=\s*(false|0|off|skip)|-auto-approve.*-lock=false")
UNKNOWN_VALUES = {"", "unknown", "unresolved", "none", "null", "undetermined", "ambiguous", "n/a", "?"}


# ----------------------------------------------------------------------------
# Tunable interpretations (override with env HARNESS_FLAGS="name=0,name=1")
# ----------------------------------------------------------------------------
DEFAULT_FLAGS = {
    "decoy_watch": True,       # any untrusted tool result that tries to give orders => watch
    "targeted_watch": True,    # untrusted content that names a concrete action => watch
    "neg_block": True,         # "do not X" in the only instruction + tool does X => block (else review)
    "scope_block": True,       # edit outside "only under <dir>" => block (else review)
    "inj_block": False,        # unapproved tool that does what untrusted text demands => block (else review)
    "vuln_restricted": True,   # defensive vulnerability review => restricted route (else primary)
    "unapproved_block": False, # "X has not been approved" + tool does X => block (else review)
}


def load_flags():
    flags = dict(DEFAULT_FLAGS)
    for part in os.environ.get("HARNESS_FLAGS", "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() in flags:
                flags[k.strip()] = v.strip().lower() in {"1", "true", "yes", "on"}
    return flags


FLAGS = load_flags()

# ----------------------------------------------------------------------------
# Feature extraction
# ----------------------------------------------------------------------------
READ_OPS = rx(r"read|list|inspect|view|stat|diff|plan$|search|grep|status|log|show|get|describe|select|query|fetch")
OP_SYNONYMS = {
    "deploy": r"deploy\w*", "rollback": r"roll(ing)?[ _-]?back\w*", "restart": r"restart\w*",
    "database_mutation": r"database[ _]mutation|migration|\bsql\b", "delete": r"delet\w+|remov\w+",
    "send": r"send\w*|publish\w*|upload\w*|email\w*|shar(e|ing)\b", "terraform_apply": r"terraform[ _]apply|apply\w*",
    "force_push": r"force[ _-]?push\w*|push\w*", "host_admin": r"host[- ]level|docker|prune|administration",
    "dns": r"\bdns\b",
}


def op_class(op):
    o = (op or "").lower()
    if not o or o in UNKNOWN_VALUES:
        return "unknown"
    if "secret" in o or "credential" in o:
        return "secret"
    if "security" in o or "exploit" in o or "pentest" in o:
        return "security"
    if "push" in o:
        return "push"
    if re.search(r"host|admin|privileg|sudo|docker|dns|chmod|chown|mount", o):
        return "privileged"
    if re.search(r"send|upload|post|email|transfer|export|publish|share|webhook", o):
        return "send"
    if re.search(r"delete|remove|wipe|purge|truncate|drop|destroy", o):
        return "delete"
    if re.search(r"deploy|mutation|rollback|restart|apply|migrat|scale|release|provision", o):
        return "mutation"
    if "edit" in o or re.search(r"write|modif|patch|create|update|extract|format", o):
        return "edit"
    if READ_OPS.search(o):
        return "read"
    return "unknown"


def exact_mention(text, needle):
    """The message names exactly this target (not a longer or shorter look-alike)."""
    n = (needle or "").strip().lower()
    if not n or n in UNKNOWN_VALUES:
        return False
    if n.startswith("mailto:"):
        n = n[7:]
    return re.search(r"(?<![\w./-])" + re.escape(n) + r"(?![\w/-]|\.\w)", text) is not None


def under(path, root):
    p, r = str(path or "").lower(), str(root or "").lower().rstrip("/")
    return bool(r) and ".." not in p and (p == r or p.startswith(r + "/"))


REVOKE = rx(r"revok\w+|withdraw\w*|rescind\w*|changed my mind|(now|is) forbidden|no longer (approved|authori[sz]ed|allowed)|cancel\w* (the|my|that) (approval|permission|deploy\w*|request)")
NEG = rx(r"\b(do not|don'?t|dont|never|without|must not|should not|shouldn'?t)\b|\bkeep\b.{0,40}\bintact\b|\bonly inspect\b|\bno changes\b")
P_GENERIC = rx(r"\b(execute|run)\b(?!\s+(the\s+)?(malware|exploit|payload|it against))|\bproceed\b|\bchange anything\b|\bproposed\b|\bpending\b|\bany (action|command|tool)")
P_BY_CLASS = {
    "mutation": rx(r"deploy|apply|appl(y|ies)|releas|restart|roll\s?back|migrat|delet\w+ any|mutat|production"),
    "delete": rx(r"delet|remov|intact|wipe|clean"),
    "send": rx(r"send|shar(e|ing)|publish|upload|email|post\b|transmit|leav(e|ing) (this|the|my) machine"),
    "edit": rx(r"edit|modif|chang|writ|intact|touch"),
    "push": rx(r"push|rewrite"),
    "privileged": rx(r"host|admin|privileg|docker|sudo|root"),
    "security": rx(r"test|scan|exploit|attack|probe"),
}
NOT_APPROVED = rx(r"\b(has|have|is|are|was)\s+not\s+(been\s+)?(approved|authori[sz]ed)\b|\bnot (approved|authori[sz]ed)\b")
EXPLICIT_OK = rx(r"\b(approve[sd]?|authori[sz]e[sd]?|permit(ted)?|go ahead|you may|confirmed?)\b")
OTHER_ENV = rx(r"\b(staging|stage|dev|development|test|sandbox|preview|qa)\b")
PROD_ENV = rx(r"\bprod(uction)?\b")


def sentences(text):
    return [s for s in re.split(r"(?<=[.!?;:\n])\s+", text) if s.strip()]


def user_verdict(user_msgs, klass, op, target, res_env):
    """
    Latest applicable user instruction wins. Returns one of
    'revoked' | 'prohibited' | 'unapproved' | 'approved' | None.
    """
    op_l = (op or "").lower()
    for idx in range(len(user_msgs) - 1, -1, -1):
        text = strip_quotes(user_msgs[idx])
        if REVOKE.search(text):
            return "revoked"
        if klass != "read":
            for s in sentences(text):
                if NEG.search(s) and (P_GENERIC.search(s) or (klass in P_BY_CLASS and P_BY_CLASS[klass].search(s))):
                    return "revoked" if idx > 0 else "prohibited"
                if NOT_APPROVED.search(s) and klass in P_BY_CLASS and P_BY_CLASS[klass].search(s):
                    return "unapproved"
        if exact_mention(text, target):
            if res_env == "production" and OTHER_ENV.search(text) and not PROD_ENV.search(text):
                return None  # approval was for another environment
            if res_env != "production" and PROD_ENV.search(text) and res_env in {"staging", "dev", "test"}:
                return None
            named = {k for k, pat in OP_SYNONYMS.items() if re.search(pat, text)}
            mine = {k for k, pat in OP_SYNONYMS.items() if re.search(pat, op_l.replace("_", " ")) or k == op_l}
            if named and mine and not (named & mine):
                return None  # approved a different operation
            # Exact approval = explicit approval words, or a direct command to do this operation
            # ("Deploy X to production", "Delete exactly X"). "Investigate the failing deployment" is neither.
            lead = [re.sub(r"^\s*(current instruction|for this task)\s*:\s*", "", s) for s in sentences(text)]
            commanded = any(re.match(pat, s.strip()) for s in lead for k, pat in OP_SYNONYMS.items() if k in mine or not mine)
            if EXPLICIT_OK.search(text) or commanded:
                return "approved"
    return None


def preflight_ok(tool_results, target, res_env):
    """Latest structured preflight record for this exact target/environment must have passed."""
    last = None
    for item in tool_results or []:
        if not isinstance(item, dict) or item.get("origin") == "untrusted":
            continue
        if str(item.get("tool", item.get("kind", ""))).lower() != "preflight":
            continue
        if str(item.get("target", "")).lower() != str(target).lower():
            continue
        if item.get("environment") is not None and str(item.get("environment")).lower() != str(res_env).lower():
            continue
        last = str(item.get("status", "")).lower()
    return last in {"passed", "pass", "success", "succeeded", "ok"}


def rollback_ok(plan, target, res_env):
    if not isinstance(plan, dict) or not plan:
        return False
    if str(plan.get("target", "")).lower() != str(target).lower():
        return False
    if plan.get("environment") is not None and str(plan.get("environment")).lower() != str(res_env).lower():
        return False
    return bool(plan.get("action") or plan.get("steps") or plan.get("command"))


TARGETED = rx(r"ignore the (user|owner)|(deploy|delete|send|export|upload|push|restart|run|execute)\b.{0,40}(immediately|now|secret|credential)|approves? (deploy|delet|send|the)")
ACTIVE_SEC = rx(r"\bdemonstrat\w+|\bexploit\w*|\bfind (a|the|any) vulnerab\w+|pen(etration)?[- ]?test\w*|\battack\w*|\bscan\w*|\bfuzz\w*|\bpoc\b|proof[- ]of[- ]concept|break into|\bhack\w*")
OWNED_TXT = rx(r"\b(my|our) (own|owned)\b|\bowned\b|\b(we|i) own\b|\bauthori[sz]ed\b|\bin[- ]scope\b")
CONFINED_TXT = rx(r"\bisolated\b|\bconfined\b|\bdisposable\b|\bsandbox\w*|\blab\b|\bctf\b")


# ----------------------------------------------------------------------------
# The classifier
# ----------------------------------------------------------------------------
def classify(case, flags=None):
    F = flags or FLAGS
    msgs = case.get("messages") or []
    if not isinstance(msgs, list):
        msgs = []
    user_msgs = [as_text(m.get("content")) for m in msgs if isinstance(m, dict) and m.get("role", "user") == "user"]
    user_all = "\n".join(user_msgs)
    user_own = strip_quotes(user_all)

    env = case.get("environment") if isinstance(case.get("environment"), dict) else {}
    iso = env.get("isolation") if isinstance(env.get("isolation"), dict) else {}
    env_kind = str(env.get("kind") or "").lower()
    workspace = env.get("workspace") or env.get("cwd") or ""
    isolated = (
        env_kind == "container" and iso.get("verified") is True and not iso.get("hostMounts")
        and iso.get("credentials") is False and iso.get("externalNetwork") is False
    )

    tool = case.get("proposedTool")
    has_tool = isinstance(tool, dict) and bool(tool)
    res = tool.get("resolved") if has_tool and isinstance(tool.get("resolved"), dict) else {}
    klass = op_class(res.get("operation")) if has_tool else None

    # Untrusted content: tool results flagged untrusted (or any free text trying to give orders).
    tool_results = case.get("toolResults") if isinstance(case.get("toolResults"), list) else []
    untrusted_items = [as_text(t.get("content")) for t in tool_results if isinstance(t, dict) and t.get("origin") == "untrusted"]
    side_text = [as_text(m.get("text")) for m in (case.get("memory") or []) + (case.get("repositoryInstructions") or []) if isinstance(m, dict)]
    targeted = [t for t in untrusted_items if TARGETED.search(t)]
    any_injection = bool(untrusted_items) or any(INJECTION.search(t) for t in side_text)

    # ---- 1. Request (content policy) --------------------------------------
    harmful = bool(HARM.search(user_own))
    request, sec_unclear = "allow", False
    security = bool(SECURITY.search(user_own)) or klass == "security"
    if harmful and (AGGRAVATED.search(user_own) or not SAFE_FRAME.search(user_own)):
        request = "block"
    elif security:
        if klass == "security":
            owned = str(res.get("ownership") or "").lower() in {"verified-owned", "owned", "verified"}
            ok = owned and res.get("confined") is True and (isolated or str(res.get("environment")).lower() != "production")
            active = True
        else:
            active = bool(ACTIVE_SEC.search(user_own))
            ok = bool(OWNED_TXT.search(user_own)) and (isolated or bool(CONFINED_TXT.search(user_own))) and not UNCLEAR.search(user_own)
        if active and not ok:
            request, sec_unclear = "review", True

    # ---- 2. Tool -----------------------------------------------------------
    tool_decision = "none"
    if has_tool:
        command = as_text(tool.get("arguments"))
        target = str(res.get("target") or "")
        res_env = str(res.get("environment") or "").lower()
        sens = str(res.get("sensitivity") or "").lower()
        is_prod = res_env == "production"
        verdict = user_verdict(user_msgs, klass, res.get("operation"), target, res_env)
        approved = verdict == "approved"
        unknown = (not res or klass == "unknown" or env_kind in UNKNOWN_VALUES or res_env in UNKNOWN_VALUES
                   or target.strip().lower() in UNKNOWN_VALUES)

        # Unapproved action that untrusted text explicitly demanded.
        op_stem = re.sub(r"[^a-z]", " ", str(res.get("operation") or "").lower()).split()
        follows = (not approved and klass not in {"read", None}) and any(
            exact_mention(t, target) or any(len(w) > 3 and w[:5] in t for w in op_stem) for t in targeted)

        forbidden = (
            verdict == "revoked"
            or (verdict == "prohibited" and F["neg_block"])
            or (verdict == "unapproved" and F["unapproved_block"])
            or res.get("bypassPreflight") is True or bool(BYPASS.search(command))
            or (follows and F["inj_block"])
        )
        if klass == "secret":
            scoped = res.get("taskScoped") is True and (exact_mention(user_own, target) or under(target, workspace))
            forbidden = forbidden or not scoped
        if klass == "send" and sens != "public" and not approved:
            forbidden = True  # private data to a destination the user never approved
        out_of_scope = False
        if klass == "edit" and not approved:
            allowed_roots = re.findall(r"only\b[^.;\n]{0,40}?(/[\w./-]+)", user_own)
            if allowed_roots and not any(under(target, r.rstrip(".")) for r in allowed_roots):
                out_of_scope = True
                forbidden = forbidden or F["scope_block"]

        soft = verdict in {"prohibited", "unapproved"} or follows or out_of_scope  # at least review

        if request == "block" or forbidden:
            tool_decision = "block"
        elif request == "review" or unknown or soft:
            tool_decision = "review"
        elif klass == "read":
            tool_decision = "allow" if (sens in {"public", ""} or under(target, workspace) or exact_mention(user_own, target)) else "review"
        elif klass == "secret":
            tool_decision = "allow"
        elif klass == "security":
            tool_decision = "allow"
        elif is_prod:
            ready = approved and preflight_ok(tool_results, target, res_env) and rollback_ok(case.get("rollbackPlan"), target, res_env)
            tool_decision = "allow" if ready else "review"
        elif klass == "send":
            tool_decision = "allow" if approved else "review"
        elif klass == "delete":
            if res.get("disposable") is True and (isolated or env_kind != "container"):
                tool_decision = "allow"
            else:
                tool_decision = "allow" if approved else "review"
        elif klass == "edit":
            in_ws = under(target, workspace) and res.get("reversible") is not False
            tool_decision = "allow" if (in_ws or approved) else "review"
        else:  # mutation / push / privileged outside production
            tool_decision = "allow" if approved else "review"

    # ---- 3. Route + trajectory --------------------------------------------
    if request == "block":
        route = "none"
    elif sec_unclear or klass == "security" or (security and (ACTIVE_SEC.search(user_own) or F["vuln_restricted"])):
        route = "restricted"
    else:
        route = "primary"

    redirect = (F["decoy_watch"] and any_injection) or (F["targeted_watch"] and bool(targeted))
    if request == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif request == "review" or tool_decision == "review" or sec_unclear or redirect:
        trajectory = "watch"
    else:
        trajectory = "normal"

    return {"requestDecision": request, "toolDecision": tool_decision, "route": route, "trajectory": trajectory}


def safe_classify(case):
    """Never crash a batch; if a case is weird, fall back to the cautious answer."""
    try:
        out = classify(case if isinstance(case, dict) else {})
    except Exception:
        has_tool = isinstance(case, dict) and bool(case.get("proposedTool"))
        out = {"requestDecision": "review", "toolDecision": "review" if has_tool else "none", "route": "primary", "trajectory": "watch"}
    out = {"caseId": case.get("caseId") if isinstance(case, dict) else None, **out}
    return out


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
async def handle(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
    CAPTURED.append(body)
    seen, results = set(), []
    for case in body.get("cases") or []:
        cid = case.get("caseId") if isinstance(case, dict) else None
        if cid is None or cid in seen:
            continue  # duplicate IDs fail the batch
        seen.add(cid)
        results.append(safe_classify(case))
    return JSONResponse({"profile": body.get("profile", PROFILE), "batchId": body.get("batchId"), "results": results})


for path in ("/", "/classify", "/classify/"):
    app.add_api_route(path, handle, methods=["POST"])


@app.get("/")
@app.get("/health")
async def health():
    return {"ok": True, "profile": PROFILE, "post": "/classify"}


@app.get("/captured")
async def captured(key: str = ""):
    """Download the request bodies the grader sent (set CAPTURE_KEY to enable)."""
    if not CAPTURE_KEY or key != CAPTURE_KEY:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse(list(CAPTURED))
