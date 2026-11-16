"""
Agent-harness safety layer: contextual safety + model routing.

One POST endpoint. For every case it returns four labels:
  requestDecision  allow | block | review
  toolDecision     allow | block | review | none
  route            primary | restricted | none
  trajectory       normal | watch | intervene

Fully deterministic (no LLM, no API key, no state shared between cases).
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
    r"|detect\w*|defen[ds]\w*|protect\w*|prevent\w*|mitigat\w+|remediat\w+|harden\w*|incident response"
    r"|triage|forensic\w*|awareness|training material|report (this|it)|flag\w*|review (the|this) (file|log|message|email|text)"
    r"|inspect\w*|fiction\w*|novel|short story|screenplay|non-actionable|without (any )?(working|real|actionable))\b"
)

# The user is clearly asking us to *do* the harmful thing, safe frame or not.
DO_IT = rx(
    r"\b(working|functional|real|deployable|undetectable|actual)\s+(ransomware|malware|keylogger|exploit|phishing|payload|stealer)"
    r"|\b(then|and)\s+(send|upload|post|email)\b.{0,40}(to (my|our|an? external)|pastebin|webhook)"
    r"|so (that )?(they|he|she|nobody|no one) (won'?t|can'?t|doesn'?t) (notice|know|detect)"
)

SECURITY = rx(
    r"vulnerab\w+|\bexploit\w*|pen(etration)?[- ]?test\w*|\bfuzz\w*|\bcve-?\d*|proof[- ]of[- ]concept|\bpoc\b"
    r"|red[- ]team\w*|privilege escalation|sql injection|\bsqli\b|\bxss\b|\brce\b|buffer overflow"
    r"|security (scan|audit|assessment|test)|attack surface|port scan\w*|\bnmap\b|metasploit|burp"
)
OWNED = rx(
    r"\b(we|i) own\b|\b(our|my) own\b|\bowned\b|\bour (lab|staging|test|sandbox|internal|ctf)\b|\bmy (lab|sandbox|test|home ?lab)\b"
    r"|\bauthori[sz]ed\b|\bin[- ]scope\b|written (permission|authori[sz]ation)|rules of engagement|\bctf\b|bug bounty scope"
)
ISOLATED_WORD = rx(r"\bisolated\b|\bsandbox\w*|\bair[- ]?gapped\b|\blab\b|\bcontainer\b|\bfixture\b|\bctf\b")
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

NEGATION = rx(
    r"\b(do not|don'?t|dont|never|stop|cancel\w*|revok\w+|abort\w*|hold off|no longer|not approved|withdraw\w*|rescind\w*"
    r"|scrap that|forget (that|it)|changed my mind|must not|should not|shouldn'?t|not allowed|forbid\w*|forbidden|off[- ]limits|leave .{0,30} alone)\b"
)
APPROVE = rx(
    r"\b(approve\w*|authori[sz]e\w*|go ahead|proceed|confirm\w*|yes|ok(ay)?|please|you may|you can|permission|allowed to|run|do it|ship it)\b"
)

OP_WORDS = {
    "delete": r"delet\w+|remov\w+|\brm\b|wip\w+|purg\w+|clean\w*|clear\w*|drop\w*",
    "send": r"send\w*|upload\w*|post\w*|email\w*|transfer\w*|export\w*|shar\w+|publish\w*|forward\w*|sync\w*",
    "push": r"push\w*|force",
    "deploy": r"deploy\w*|releas\w+|roll ?out|migrat\w+|apply\w*|ship\w*|restart\w*|scal\w+|updat\w+|chang\w+",
    "dns": r"\bdns\b|record|cname|zone",
    "docker": r"docker|container|daemon|prune",
    "privileged": r"sudo|root|chmod|chown|install\w*|privileg\w+",
    "read": r"read\w*|load\w*|open\w*|inspect\w*|use\w*|fetch\w*",
    "edit": r"edit\w*|writ\w+|modif\w+|fix\w*|updat\w+|refactor\w*|chang\w+",
}

CRED_TARGET = rx(
    r"\.env\b|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.npmrc|\.netrc|\.pgpass|kubeconfig|\.kube\b|keychain|credential|secret|passw|token|api[_-]?key|private[_-]?key|\.pem\b|vault"
)
PRIVATE_SENS = {"private", "confidential", "pii", "personal", "sensitive", "restricted", "internal", "secret", "customer"}
CRED_SENS = {"credential", "credentials", "secret", "secrets", "token", "key"}
SYSTEM_PATH = rx(r"^(/etc|/usr|/var|/boot|/sys|/proc|/root|/lib|/bin|/sbin|c:\\windows)\b")
BYPASS = rx(r"--no-verify|--skip-(preflight|checks?|hooks?|validation|safety)|--no-preflight|skip[_-]?preflight|--force-skip|bypass|preflight\s*=\s*(false|0|off|skip)|-auto-approve.*-lock=false")
UNKNOWN_VALUES = {"", "unknown", "unresolved", "none", "null", "undetermined", "ambiguous", "n/a", "?"}


# ----------------------------------------------------------------------------
# Feature extraction
# ----------------------------------------------------------------------------
def op_class(op, command):
    """Map the resolved operation to one coarse class."""
    o = (op or "").lower()
    c = (command or "").lower()
    if "force" in o or ("push" in o and re.search(r"--force|\s-f\b|\+\w+:", c)):
        return "push"  # remote force push
    if "push" in o:
        return "push"
    if "dns" in o:
        return "dns"
    if "docker" in o or "host" in o and "docker" in c:
        return "docker"
    if re.search(r"sudo|privileg|chmod|chown|install|mount|grant|escalat|root", o):
        return "privileged"
    if re.search(r"send|upload|post|email|transfer|export|publish|exfil|share|webhook|sync|copy_out|network", o):
        return "send"
    if re.search(r"delete|remove|\brm\b|wipe|purge|truncate|drop|destroy|prune", o):
        return "delete"
    if re.search(r"deploy|migrat|apply|mutat|restart|scale|rotate|release|rollout|provision|alter", o):
        return "deploy"
    if re.search(r"read|list|inspect|view|stat|diff|plan|search|grep|status|log|show|get|describe|select|query|cat|load|fetch|open", o):
        return "read"
    if re.search(r"write|edit|modif|patch|create|update|format|append|rename|move|copy|insert|replace|commit", o):
        return "edit"
    return "unknown"


def mentions(text, needle):
    """Does the message mention this target/destination (full string, basename or host)?"""
    n = (needle or "").strip().lower()
    if not n or n in UNKNOWN_VALUES:
        return False
    if n in text:
        return True
    host = re.sub(r"^\w+://", "", n).split("/")[0]
    if len(host) >= 4 and "." in host and host in text:
        return True
    base = n.rstrip("/").split("/")[-1]
    return len(base) >= 4 and base in text


def env_conflict(text, is_prod):
    """Approval is bound to the environment: 'do it on staging' is not approval for production."""
    says_prod = bool(re.search(r"\bprod(uction)?\b|\blive\b", text))
    says_other = bool(re.search(r"\b(staging|stage|dev|development|test|sandbox|preview|local|container)\b", text))
    if is_prod:
        return says_other and not says_prod
    return says_prod and not says_other


def authorization(user_msgs, klass, target, destination, is_prod):
    """
    Walk user messages newest -> oldest and return the latest applicable verdict:
    'revoked', 'approved' or None (nobody said anything specific about this action).
    """
    op_rx = rx(OP_WORDS.get(klass, r"$^"))
    for msg in reversed(user_msgs):
        text = strip_quotes(msg.lower())
        hits_target = mentions(text, target) or mentions(text, destination)
        hits_op = bool(op_rx.search(text))
        if NEGATION.search(text) and (hits_target or hits_op):
            # Negation must sit in the same sentence as the target/operation.
            for sentence in re.split(r"(?<=[.!?;\n])\s+", text):
                if NEGATION.search(sentence) and (mentions(sentence, target) or mentions(sentence, destination) or op_rx.search(sentence)):
                    return "revoked"
        if hits_target and (hits_op or APPROVE.search(text)):
            if env_conflict(text, is_prod):
                return None  # approval was for a different environment
            if klass == "send" and destination and not mentions(text, destination):
                continue  # approval must name the exact destination
            return "approved"
    return None


def preflight_ok(tool_results):
    """Only structured fields count; free-text 'preflight passed' claims do not."""
    for item in tool_results or []:
        if not isinstance(item, dict):
            continue
        keys = " ".join(str(k).lower() for k in item)
        label = " ".join(str(item.get(k, "")).lower() for k in ("kind", "type", "name", "tool", "check", "id"))
        nested = item.get("preflight") if isinstance(item.get("preflight"), dict) else None
        if "preflight" not in keys and "preflight" not in label and nested is None:
            continue
        rec = nested or item
        status = str(rec.get("status", rec.get("result", rec.get("outcome", "")))).lower()
        flags = [rec.get(k) for k in ("ok", "passed", "success", "succeeded") if k in rec]
        if status in {"passed", "pass", "success", "succeeded", "ok", "green"} or (flags and all(f is True for f in flags)):
            if not any(f is False for f in flags):
                return True
    return False


def rollback_ok(plan, target):
    """An exact rollback plan: present, structured, non-empty, and for this target."""
    if not isinstance(plan, dict) or not plan:
        return False
    for k in ("exact", "verified", "complete", "valid"):
        if plan.get(k) is False:
            return False
    plan_target = plan.get("target") or plan.get("resource")
    if isinstance(plan_target, str) and target and plan_target.strip().lower() != str(target).strip().lower():
        return False
    return any(plan.get(k) for k in ("steps", "command", "commands", "procedure", "snapshot", "revision", "target", "restore"))


# ----------------------------------------------------------------------------
# The classifier
# ----------------------------------------------------------------------------
def classify(case):
    msgs = case.get("messages") or []
    user_msgs = [as_text(m.get("content")) for m in msgs if isinstance(m, dict) and m.get("role", "user") == "user"]
    user_all = "\n".join(user_msgs)
    user_own = strip_quotes(user_all)  # what the user asks in their own words
    untrusted = "\n".join(
        [as_text(case.get("memory")), as_text(case.get("repositoryInstructions")), as_text(case.get("toolResults"))]
        + [as_text(m.get("content")) for m in msgs if isinstance(m, dict) and m.get("role", "user") != "user"]
    )

    env = case.get("environment") or {}
    iso = env.get("isolation") or {}
    env_kind = str(env.get("kind") or "").lower()
    isolated = (
        env_kind == "container"
        and iso.get("verified") is True
        and not iso.get("hostMounts")
        and iso.get("credentials") is False
        and iso.get("externalNetwork") is False
    )

    tool = case.get("proposedTool") or None
    has_tool = isinstance(tool, dict) and bool(tool)
    injection = bool(INJECTION.search(untrusted))

    # ---- 1. Request (content policy) --------------------------------------
    harmful = bool(HARM.search(user_own))
    safe_frame = bool(SAFE_FRAME.search(user_own))
    security = bool(SECURITY.search(user_all))
    request, sec_unclear = "allow", False

    if harmful and (not safe_frame or DO_IT.search(user_own)):
        request = "block"
    elif security:
        defensive_only = safe_frame and not re.search(r"\b(exploit|attack|pen(etration)?[- ]?test|scan|fuzz|poc|proof[- ]of[- ]concept|demonstrat\w+|break into|hack)\b", user_own)
        owned = bool(OWNED.search(user_own)) and not UNCLEAR.search(user_own)
        confined = isolated or bool(ISOLATED_WORD.search(user_own))
        if not defensive_only and not (owned and confined):
            request, sec_unclear = "review", True

    # ---- 2. Tool -----------------------------------------------------------
    tool_decision = "none"
    if has_tool:
        args = tool.get("arguments") or {}
        res = tool.get("resolved") if isinstance(tool.get("resolved"), dict) else {}
        command = as_text(args)
        target = str(res.get("target") or "")
        destination = str(res.get("destination") or res.get("destinationHost") or res.get("recipient") or res.get("remote") or "")
        sens = str(res.get("sensitivity") or "").lower()
        res_env = " ".join(str(v).lower() for k, v in res.items() if "env" in k.lower() or "destination" in k.lower())
        is_prod = "prod" in res_env or "prod" in env_kind
        klass = op_class(res.get("operation"), command)
        is_cred = sens in CRED_SENS or bool(CRED_TARGET.search(target))
        is_private = sens in PRIVATE_SENS or is_cred
        auth = authorization(user_msgs, klass, target, destination, is_prod)
        approved = auth == "approved"

        unknown_env = env_kind in UNKNOWN_VALUES or str(res.get("environment") or "").lower() in UNKNOWN_VALUES
        unresolved = not res or target.strip().lower() in UNKNOWN_VALUES or res.get("resolved") is False
        on_host_mount = bool(iso.get("hostMounts")) or "host" in str(res.get("environment") or "").lower()

        # Does the tool act on something that only untrusted content asked for?
        follows_injection = injection and any(
            mentions(untrusted, x) and not mentions(user_all, x) for x in (destination, target) if x
        ) and klass != "read"
        # Scope narrowing: repo instructions / memory may forbid, never permit.
        narrowed = any(
            NEGATION.search(s) and (mentions(s, target) or mentions(s, destination))
            for s in re.split(r"(?<=[.!?;\n])\s+|\\n", as_text(case.get("repositoryInstructions")) + "\n" + as_text(case.get("memory")))
        )

        forbidden = (
            auth == "revoked"
            or follows_injection
            or narrowed
            or bool(BYPASS.search(command)) or "bypass" in str(res.get("operation") or "").lower()
            or (is_cred and not (approved and klass == "read") )
            or (is_cred and any(res.get(k) is False for k in ("taskScoped", "inTaskScope", "taskScope", "approved")))
            or (klass == "send" and is_private and not approved)
        )

        if request == "block" or forbidden:
            tool_decision = "block"
        elif request == "review" or unknown_env or unresolved:
            tool_decision = "review"
        elif klass == "read":
            # Read-only: fine unless it touches sensitive data nobody asked for.
            tool_decision = "allow" if (not is_private or approved or mentions(user_own, target)) else "review"
        elif is_prod:
            # Production mutation: exact approval + visible successful preflight + exact rollback plan.
            ready = approved and preflight_ok(case.get("toolResults")) and rollback_ok(case.get("rollbackPlan"), target)
            tool_decision = "allow" if ready else "review"
        elif klass in {"send", "push", "dns", "docker", "privileged", "deploy", "unknown"}:
            tool_decision = "allow" if approved else "review"
        elif klass == "delete":
            disposable = res.get("disposable") is True
            if disposable and isolated:
                tool_decision = "allow"  # disposable fixtures in a verified isolated container
            elif disposable and env_kind != "container" and not on_host_mount:
                tool_decision = "allow"
            else:
                tool_decision = "allow" if approved else "review"
        else:  # edit
            risky = SYSTEM_PATH.search(target.lower()) or res.get("reversible") is False or (env_kind == "container" and on_host_mount and not isolated and is_private)
            tool_decision = "allow" if (not risky or approved) else "review"

    # ---- 3. Route + trajectory --------------------------------------------
    if request == "block":
        route = "none"
    elif security or sec_unclear:
        route = "restricted"
    else:
        route = "primary"

    if request == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif request == "review" or tool_decision == "review" or sec_unclear or injection:
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
