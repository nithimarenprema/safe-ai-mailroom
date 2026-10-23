import os
import json
import re
import base64
import hashlib
import sqlite3
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)

PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.getenv("DB_PATH", "mailroom.db")

ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}

app = FastAPI(title="Safe AI Mailroom")


def canonical(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT NOT NULL,
                verifier TEXT NOT NULL,
                proposals TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                commit_request_digest TEXT,
                outcomes TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                fingerprint TEXT PRIMARY KEY,
                proposal TEXT NOT NULL
            )
        """)


init_db()


def response(status, body):
    return JSONResponse(
        status_code=status,
        content=body,
        headers={"Cache-Control": "no-store"},
    )


def proposal_digest(p):
    selected = {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p["target"],
        "payload": p["payload"],
        "evidence": sorted(p["evidence"]),
    }
    return digest(selected)


def validate_request(data):
    if not isinstance(data, dict):
        raise ValueError("Request must be an object")

    if data.get("profile") != PROFILE:
        raise ValueError("Invalid profile")

    if data.get("operation") not in ("propose", "commit"):
        raise ValueError("Invalid operation")

    if not isinstance(data.get("evaluationId"), str):
        raise ValueError("Invalid evaluationId")

    if len(data["evaluationId"]) > 256:
        raise ValueError("evaluationId too long")


def safe_proposal(dossier):
    """
    Conservative placeholder only.
    This is NOT the final AI decision engine.
    """
    lines = [
        line.get("lineId")
        for source in dossier.get("sources", [])
        for line in source.get("lines", [])
        if isinstance(line, dict)
        and isinstance(line.get("lineId"), str)
    ]

    fingerprint = digest(dossier)
    call_id = "mailroom-" + fingerprint[:40]

    return {
        "dossierId": dossier["dossierId"],
        "callId": call_id,
        "action": "request_confirmation",
        "target": {
            "kind": "approval_queue",
            "id": "unresolved",
        },
        "payload": {
            "claimedSender": "unverified",
            "questionCode": "VERIFY_REQUEST",
            "referenceId": dossier["dossierId"],
        },
        "evidence": lines[:1],
    }


def verify_receipt(receipt, evaluation_id, input_digest, jwk):
    if not isinstance(receipt, dict):
        return False

    required = {
        "dossierId",
        "callId",
        "action",
        "accepted",
        "proposalDigest",
        "receiptId",
        "receiptSignature",
    }

    if set(receipt) != required:
        return False

    if not isinstance(receipt["accepted"], bool):
        return False

    if not isinstance(receipt["receiptSignature"], str):
        return False

    if not isinstance(jwk, dict):
        return False

    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False

    try:
        def b64url_decode(s):
            return base64.urlsafe_b64decode(
                s + "=" * (-len(s) % 4)
            )

        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(jwk["x"])
        )

        inner = {
            k: v for k, v in receipt.items()
            if k != "receiptSignature"
        }

        signed_data = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "receipt": inner,
        }

        signature = base64.b64decode(
            receipt["receiptSignature"],
            validate=True,
        )

        public_key.verify(signature, canonical(signed_data))
        return True

    except Exception:
        return False


@app.get("/")
def health():
    return {
        "service": "Safe AI Mailroom",
        "status": "online",
        "profile": PROFILE,
    }


@app.post("/")
async def mailroom(request: Request):
    try:
        raw = await request.body()

        if len(raw) > 1_000_000:
            return response(413, {"error": "Request too large"})

        data = json.loads(raw)
        validate_request(data)

        evaluation_id = data["evaluationId"]

        if data["operation"] == "propose":
            if not isinstance(data.get("dossiers"), list):
                raise ValueError("dossiers must be a list")

            if data.get("allowedActions") != [
                "create_draft",
                "update_internal_record",
                "send_approved_notice",
                "request_confirmation",
                "quarantine_item",
                "no_action",
            ]:
                raise ValueError("Unexpected allowedActions")

            dossiers = data["dossiers"]
            ids = [
                d.get("dossierId") for d in dossiers
                if isinstance(d, dict)
            ]

            if len(ids) != len(dossiers):
                raise ValueError("Malformed dossier")

            if any(not isinstance(i, str) or not i for i in ids):
                raise ValueError("Invalid dossier ID")

            if len(set(ids)) != len(ids):
                raise ValueError("Duplicate dossier IDs")

            input_digest = digest(dossiers)
            request_digest = digest(data)

            with db() as c:
                old = c.execute(
                    "SELECT * FROM evaluations WHERE evaluation_id=?",
                    (evaluation_id,),
                ).fetchone()

                if old:
                    if old["request_digest"] != request_digest:
                        return response(
                            409,
                            {"error": "Evaluation content conflict"},
                        )

                    return response(200, {
                        "profile": PROFILE,
                        "evaluationId": evaluation_id,
                        "status": "awaiting_receipts",
                        "inputDigest": old["input_digest"],
                        "proposals": json.loads(old["proposals"]),
                    })

                verifier = data.get("receiptVerifier", {})
                jwk = verifier.get("publicKeyJwk")

                if verifier.get("algorithm") != "Ed25519":
                    raise ValueError("Unsupported verifier")

                if not isinstance(jwk, dict) or not isinstance(
                    jwk.get("x"), str
                ):
                    raise ValueError("Invalid verifier key")

                proposals = []

                for dossier in dossiers:
                    fingerprint = digest(dossier)

                    cached = c.execute(
                        "SELECT proposal FROM decisions WHERE fingerprint=?",
                        (fingerprint,),
                    ).fetchone()

                    if cached:
                        p = json.loads(cached["proposal"])
                    else:
                        p = safe_proposal(dossier)

                        c.execute(
                            "INSERT INTO decisions VALUES (?, ?)",
                            (fingerprint, json.dumps(p)),
                        )

                    proposals.append(p)

                c.execute("""
                    INSERT INTO evaluations
                    VALUES (?, ?, ?, ?, ?, NULL, NULL)
                """, (
                    evaluation_id,
                    input_digest,
                    json.dumps(verifier),
                    json.dumps(proposals),
                    request_digest,
                ))

            return response(200, {
                "profile": PROFILE,
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals,
            })

        # COMMIT
        if not isinstance(data.get("receipts"), list):
            raise ValueError("receipts must be a list")

        with db() as c:
            evaluation = c.execute(
                "SELECT * FROM evaluations WHERE evaluation_id=?",
                (evaluation_id,),
            ).fetchone()

            if not evaluation:
                return response(409, {"error": "Unknown evaluation"})

            if data.get("inputDigest") != evaluation["input_digest"]:
                return response(409, {"error": "Input digest mismatch"})

            commit_digest = digest(data)

            if evaluation["commit_request_digest"]:
                if evaluation["commit_request_digest"] != commit_digest:
                    return response(409, {"error": "Commit replay conflict"})

                return response(200, {
                    "profile": PROFILE,
                    "evaluationId": evaluation_id,
                    "status": "completed",
                    "inputDigest": evaluation["input_digest"],
                    "outcomes": json.loads(evaluation["outcomes"]),
                })

            proposals = json.loads(evaluation["proposals"])
            verifier = json.loads(evaluation["verifier"])
            jwk = verifier["publicKeyJwk"]
            receipts = data["receipts"]

            if len(receipts) != len(proposals):
                raise ValueError("Receipt count mismatch")

            proposal_map = {p["dossierId"]: p for p in proposals}
            seen = set()
            outcomes = []

            for r in receipts:
                if not isinstance(r, dict):
                    raise ValueError("Malformed receipt")

                dossier_id = r.get("dossierId")

                if dossier_id in seen or dossier_id not in proposal_map:
                    raise ValueError("Duplicate or unknown receipt")

                seen.add
