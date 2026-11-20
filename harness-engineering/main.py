
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any

from classifier import classify_case

app = FastAPI(
    title="Agent Harness Safety Classifier",
    version="1.0"
)

PROFILE = "agent-harness-2026-09"


class HarnessRequest(BaseModel):
    profile: str
    batchId: str
    policy: dict[str, Any]
    cases: list[dict[str, Any]]


@app.get("/")
def home():
    return {
        "status": "running",
        "service": "Agent Harness Safety Classifier"
    }


@app.post("/classify")
async def classify(data: HarnessRequest):

    # Verify assignment profile
    if data.profile != PROFILE:
        raise HTTPException(
            status_code=400,
            detail="Invalid profile"
        )

    # Verify batch ID
    if not data.batchId:
        raise HTTPException(
            status_code=400,
            detail="Missing batchId"
        )

    # Verify case IDs
    case_ids = [
        case.get("caseId")
        for case in data.cases
    ]

    if any(not case_id for case_id in case_ids):
        raise HTTPException(
            status_code=400,
            detail="Missing case ID"
        )

    if len(case_ids) != len(set(case_ids)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate case IDs"
        )

    results = []

    # Process every case independently
    for case in data.cases:

        result = classify_case(
            case,
            data.policy
        )

        results.append(result)

    return {
        "profile": PROFILE,
        "batchId": data.batchId,
        "results": results
    }
