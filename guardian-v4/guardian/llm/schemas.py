"""Schemas that lock every LLM output. A tiny validator, no extra library."""
import json

FLAGS = ["runs_network_command", "downloads_and_executes", "reads_env_or_credentials",
         "obfuscated", "mentions_instructions_to_ai", "benign_build_step"]
RISKS = ["low", "medium", "high", "critical", "needs-review"]

STR, INT, BOOL = {"t": "string"}, {"t": "integer"}, {"t": "boolean"}
IDS = {"t": "array", "of": STR, "max": 30}


def obj(**fields):
    return {"t": "object", "fields": fields}


def arr(of, mx=20):
    return {"t": "array", "of": of, "max": mx}


READER = obj(items=arr(obj(id=STR, **{f: BOOL for f in FLAGS}), 15))
ANALYST = obj(findings=arr(obj(id=STR, priority_rank=INT, explanation=STR,
                               evidence_ids_used=IDS), 10))
SKEPTIC = obj(opinions=arr(obj(id=STR, risk_opinion={"t": "enum", "values": RISKS},
                               evidence_ids_used=IDS), 5))
REMEDIATOR = obj(choices=arr(obj(finding_id=STR, option_id=STR, explanation=STR,
                                 evidence_ids_used=IDS), 10))


def validate(value, schema, path="$"):
    """Return None if OK, else an exact error string (used for the one retry)."""
    t = schema["t"]
    if t == "object":
        if not isinstance(value, dict):
            return f"{path} must be an object"
        for k, sub in schema["fields"].items():
            if k not in value:
                return f"{path}.{k} is missing"
            err = validate(value[k], sub, f"{path}.{k}")
            if err:
                return err
        extra = set(value) - set(schema["fields"])
        return f"{path} has unexpected keys {sorted(extra)}" if extra else None
    if t == "array":
        if not isinstance(value, list) or len(value) > schema["max"]:
            return f"{path} must be a list of at most {schema['max']} items"
        for i, v in enumerate(value):
            err = validate(v, schema["of"], f"{path}[{i}]")
            if err:
                return err
        return None
    if t == "string":
        return None if isinstance(value, str) and len(value) <= 1500 else f"{path} must be a short string"
    if t == "integer":
        return None if isinstance(value, int) and not isinstance(value, bool) else f"{path} must be an integer"
    if t == "boolean":
        return None if isinstance(value, bool) else f"{path} must be true or false"
    if t == "enum":
        return None if value in schema["values"] else f"{path} must be one of {schema['values']}"
    return f"{path}: unknown schema type"


def extract_json(text):
    """Pull the first JSON object out of a model reply. Raises ValueError if none."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object found")
    return json.loads(text[start:end + 1])
