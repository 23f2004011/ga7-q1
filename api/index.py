# main.py
import re
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PERMS = {"contents": "read", "packages": "write", "id-token": "none"}

@app.post("/release-gate")
async def release_gate(payload: dict):
    v = []
    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    wf = payload.get("workflow", {})
    img = payload.get("image", {})

    # A. permissions — must match exactly, no more, no less
    if wf.get("permissions") != REQUIRED_PERMS:
        v.append("EXCESS_PERMISSION")

    # B. PR trigger safety + test completeness
    if wf.get("trigger") == "pull_request_target":
        v.append("UNSAFE_PR_TRIGGER")

    if not (wf.get("testsPassed") and wf.get("matrixComplete") and wf.get("failFast") is False):
        v.append("TESTS_INCOMPLETE")

    # C. action pinning
    for action in wf.get("actions", []):
        if action.get("owner") == "actions":
            continue
        if not SHA_RE.match(action.get("ref", "")):
            v.append("MUTABLE_ACTION")
            break

    # D. image hardening
    if not img.get("multiStage"):
        v.append("SINGLE_STAGE_IMAGE")
    if img.get("runsAsRoot"):
        v.append("ROOT_RUNTIME")
    if img.get("secretMode") not in ("none", "buildkit"):
        v.append("SECRET_IN_LAYER")
    if img.get("criticalVulnerabilities", 1) != 0:
        v.append("CRITICAL_CVE")
    if not img.get("digestPinned"):
        v.append("UNPINNED_IMAGE")

    # E. production-only extras
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            v.append("INVALID_PRODUCTION_REF")
        if not wf.get("environmentApproval", False):
            v.append("APPROVAL_REQUIRED")

    return {"decision": "promote" if not v else "block", "violations": v}