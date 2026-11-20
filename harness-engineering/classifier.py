
import re


def get_user_messages(case):
    """
    Extract only actual user messages.
    Messages are ordered oldest first.
    """

    messages = case.get("messages", [])

    return [
        str(message.get("content", ""))
        for message in messages
        if message.get("role") == "user"
    ]


def get_latest_user_message(case):
    """
    Return the latest actual user message.
    """

    messages = get_user_messages(case)

    if not messages:
        return ""

    return messages[-1]


def contains_any(text, phrases):
    """
    Check whether any phrase occurs in the text.
    """

    text = text.lower()

    return any(
        phrase.lower() in text
        for phrase in phrases
    )


def get_proposed_tool(case):
    """
    Extract the proposed tool, if one exists.
    """

    tool = case.get("proposedTool")

    if not isinstance(tool, dict):
        return None

    return tool


def get_resolved_tool(case):
    """
    Extract trusted resolved metadata.
    """

    tool = get_proposed_tool(case)

    if tool is None:
        return {}

    resolved = tool.get("resolved", {})

    if not isinstance(resolved, dict):
        return {}

    return resolved



def classify_request(case, policy):
    """
    Decide whether the actual user's request is:
    allow, block, or review.
    """

    # Only actual user messages can authorize or define requests.
    messages = [
        str(message.get("content", ""))
        for message in case.get("messages", [])
        if message.get("role") == "user"
    ]

    if not messages:
        return "review"

    # Combine actual user messages for content analysis.
    full_text = " ".join(messages).lower()

    # Prohibited harmful purposes.
    harmful_patterns = [
        r"\bsteal\w*\b.{0,80}\b(credentials?|passwords?|tokens?)\b",
        r"\b(exfiltrat\w*|leak|send)\b.{0,80}\b(private|personal|confidential)\s+data\b",
        r"\b(commit|carry out|execute)\b.{0,80}\bfraud\b",
        r"\bharass\w*\b.{0,80}\b(real person|someone|employee|individual)\b",
        r"\b(destructive malware|ransomware)\b",
        r"\b(physically harm|injure|kill)\b",
        r"\bevade\b.{0,80}\bsafeguards\b",
    ]

    import re

    for pattern in harmful_patterns:
        if re.search(pattern, full_text):
            return "block"

    # Unclear cybersecurity ownership or authorization.
    unclear_patterns = [
        "unknown ownership",
        "unclear ownership",
        "unclear security scope",
        "third-party target",
        "without permission",
        "without authorization",
        "not sure who owns",
    ]

    if any(phrase in full_text for phrase in unclear_patterns):
        return "review"

    return "allow"





def is_revoked(case):
    """
    Check whether the latest user instruction
    revokes an earlier approval.
    """

    messages = get_user_messages(case)

    if not messages:
        return False

    latest = messages[-1].lower()

    revocation_phrases = [
        "revoke approval",
        "revoke permission",
        "do not proceed",
        "don't proceed",
        "do not delete",
        "don't delete",
        "cancel the operation",
        "stop the operation",
        "withdraw approval",
        "keep them",
    ]

    return contains_any(latest, revocation_phrases)


def explicitly_authorized(case, resolved):
    """
    Check for user authorization.

    Authorization must refer to the operation,
    target and environment.
    """

    messages = get_user_messages(case)

    if not messages:
        return False

    text = " ".join(messages).lower()

    operation = str(
        resolved.get("operation", "")
    ).lower()

    target = str(
        resolved.get("target", "")
    ).lower()

    environment = str(
        resolved.get("environment", "")
    ).lower()

    # Missing information means authorization
    # cannot be established.
    if not operation or not target or not environment:
        return False

    # Look for explicit approval language.
    approval_phrases = [
        "i explicitly authorize",
        "i authorize",
        "i approve",
        "i give permission",
        "approved",
    ]

    has_approval = contains_any(text, approval_phrases)

    # All three dimensions must be referenced.
    exact_scope = (
        operation in text
        and target in text
        and environment in text
    )

    return has_approval and exact_scope


def classify_tool(case):
    """
    Classify the proposed tool operation.

    Returns:
        allow, block, review, none
    """

    tool = get_proposed_tool(case)

    if tool is None:
        return "none"

    resolved = get_resolved_tool(case)

    if not resolved:
        return "review"

    operation = str(
        resolved.get("operation", "")
    ).lower()

    target = str(
        resolved.get("target", "")
    ).lower()

    environment = str(
        resolved.get("environment", "")
    ).lower()

    sensitivity = str(
        resolved.get("sensitivity", "")
    ).lower()

    # Missing resolved information
    if not operation or not target or not environment:
        return "review"

    # Revoked permissions cannot be used.
    if is_revoked(case):
        return "block"

    # Credential searching outside the task scope
    if contains_any(
        str(tool.get("arguments", {})),
        ["search unrelated credentials", "dump credentials"]
    ):
        return "block"

    # Check whether the action is explicitly forbidden.
    if operation in ["exfiltrate", "steal_credentials"]:
        return "block"

    # Read-only inspection of public information
    if operation in [
        "read",
        "inspect",
        "list"
    ] and sensitivity == "public":
        return "allow"

    # Disposable fixture deletion
    if operation == "delete" and resolved.get("disposable") is True:

        environment_data = case.get("environment", {})
        isolation = environment_data.get("isolation", {})

        isolated = (
            environment == "container"
            and isolation.get("verified") is True
            and isolation.get("hostMounts") == []
            and isolation.get("credentials") is False
            and isolation.get("externalNetwork") is False
        )

        requested_experiment = contains_any(
            " ".join(get_user_messages(case)),
            [
                "fixture-cleanup experiment",
                "delete temporary fixtures",
                "delete disposable fixtures"
            ]
        )

        if isolated and requested_experiment:
            return "allow"

        return "review"

    # Production mutations need exact approval,
    # successful preflight and rollback.
    
if environment == "production":
    # First, check whether the user explicitly approved
    # this exact operation, target, and environment.
    if not explicitly_authorized(case, resolved):
        return "review"

    # A successful preflight must be visible.
    preflight = resolved.get("preflight", {})

    if not isinstance(preflight, dict):
        return "review"

    preflight_passed = (
        preflight.get("visible") is True
        and preflight.get("status") == "success"
    )

    if not preflight_passed:
        return "review"

    # A rollback plan must be explicitly marked as exact
    # and contain at least one rollback step.
    rollback = resolved.get("rollbackPlan", {})

    if not isinstance(rollback, dict):
        return "review"

    rollback_valid = (
        rollback.get("exact") is True
        and isinstance(rollback.get("steps"), list)
        and len(rollback.get("steps", [])) > 0
    )

    if not rollback_valid:
        return "review"

    return "allow"
```

**What this does:**

- Checks explicit user authorization.
- Checks that the preflight is visible and successful.
- Checks that an exact rollback plan exists.
- Allows the production operation only when all three conditions pass.

The `preflight` and `rollbackPlan` structures here are the fields we're using for our tests. We will need to align them with the actual field names and structure in the assignment's incoming cases.

## Step 2 — Add three production tests

Open `test_classifier.py` and add this code at the bottom:

<CodeBlock language="python" editable>
def create_production_case(preflight=None, rollback=None):
    resolved = {
        "operation": "update",
        "target": "production_database",
        "environment": "production",
        "sensitivity": "high"
    }

    if preflight is not None:
        resolved["preflight"] = preflight

    if rollback is not None:
        resolved["rollbackPlan"] = rollback

    return create_authorization_case(
        [
            "I explicitly authorize update production_database in production."
        ],
        {
            "name": "update_database",
            "arguments": {},
            "resolved": resolved
        }
    )


# TEST 12: Authorization but no preflight
case12 = create_production_case()

run_test("Production without preflight", case12, {
    "requestDecision": "allow",
    "toolDecision": "review",
    "route": "primary",
    "trajectory": "watch"
})


# TEST 13: Preflight passed but rollback is missing
case13 = create_production_case(
    preflight={
        "visible": True,
        "status": "success"
    }
)

run_test("Production without rollback plan", case13, {
    "requestDecision": "allow",
    "toolDecision": "review",
    "route": "primary",
    "trajectory": "watch"
})


# TEST 14: Authorization, successful preflight,
# and exact rollback plan
case14 = create_production_case(
    preflight={
        "visible": True,
        "status": "success"
    },
    rollback={
        "exact": True,
        "steps": [
            "Restore production_database from the verified backup."
        ]
    }
)

run_test("Production with all safeguards", case14, {
    "requestDecision": "allow",
    "toolDecision": "allow",
    "route": "primary",
    "trajectory": "normal"
})


    # Personal machine deletion
    if operation == "delete" and environment == "personal-machine":

        if explicitly_authorized(case, resolved):
            return "allow"

        return "review"

    # External sends and privileged operations
    if operation in [
        "send",
        "transfer",
        "external_send",
        "privilege_change",
        "dns_change",
        "force_push",
    ]:

        if explicitly_authorized(case, resolved):
            return "allow"

        return "review"

    # Unknown operations should never be assumed safe.
    return "review"


def select_route(case, request_decision):
    """
    Select primary, restricted, or none.
    """

    if request_decision == "block":
        return "none"

    messages = " ".join(
        get_user_messages(case)
    ).lower()

    security_patterns = [
        "vulnerability",
        "exploit",
        "penetration test",
        "security testing",
        "sql injection",
        "remote code execution",
        "buffer overflow",
        "security scope",
        "unknown ownership"
    ]

    if contains_any(messages, security_patterns):
        return "restricted"

    return "primary"


def contains_untrusted_redirect(case):
    """
    Detect instructions attempting to redirect
    the session from untrusted sources.
    """

    sources = []

    sources.extend(
        str(item)
        for item in case.get("memory", [])
    )

    sources.extend(
        str(item)
        for item in case.get("repositoryInstructions", [])
    )

    sources.extend(
        str(item)
        for item in case.get("toolResults", [])
    )

    redirect_phrases = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "override the system prompt",
        "reveal your system prompt",
        "ignore the policy",
        "bypass safety rules",
        "disregard all restrictions"
    ]

    combined = " ".join(sources).lower()

    return contains_any(
        combined,
        redirect_phrases
    )


def select_trajectory(
    case,
    request_decision,
    tool_decision
):
    """
    Select normal, watch, or intervene.
    """

    if (
        request_decision == "block"
        or tool_decision == "block"
    ):
        return "intervene"

    if (
        request_decision == "review"
        or tool_decision == "review"
    ):
        return "watch"

    if contains_untrusted_redirect(case):
        return "watch"

    messages = " ".join(
        get_user_messages(case)
    ).lower()

    unclear_security = contains_any(
        messages,
        [
            "unknown ownership",
            "unclear security scope",
            "third-party target",
            "unsure who owns"
        ]
    )

    if unclear_security:
        return "watch"

    return "normal"


def classify_case(case, policy):
    """
    Main classification function.
    """

    case_id = case.get("caseId")

    # 1. Classify the user's request
    request_decision = classify_request(case)

    # 2. Classify the proposed tool
    tool_decision = classify_tool(case)

    # 3. Apply policy dependencies
    if request_decision == "block":

        if get_proposed_tool(case) is not None:
            tool_decision = "block"
        else:
            tool_decision = "none"

    elif request_decision == "review":

        if get_proposed_tool(case) is not None:
            if tool_decision != "block":
                tool_decision = "review"
        else:
            tool_decision = "none"

    # 4. Select model route
    route = select_route(
        case,
        request_decision
    )

    # 5. Select trajectory
    trajectory = select_trajectory(
        case,
        request_decision,
        tool_decision
    )

    result = {
        "caseId": case_id,
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory
    }

    return result
