"""Optional server-side AI provider adapter.

The application remains fully usable without an external AI provider. If
AI_API_URL and AI_API_KEY are configured, this adapter can call an
OpenAI-compatible chat endpoint using only the minimized payload supplied by
the caller. Credentials never reach the browser.
"""
import json, os, urllib.request, urllib.error


def configured():
    return bool(os.environ.get("AI_API_URL") and os.environ.get("AI_API_KEY"))


def generate(system_prompt, user_prompt, *, max_tokens=700):
    if not configured():
        return None, "AI provider is not configured. The local School Results AI tools remain available."
    url=os.environ["AI_API_URL"].strip()
    payload={
        "model": os.environ.get("AI_MODEL", ""),
        "messages":[
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": max_tokens,
    }
    req=urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers={
        "Content-Type":"application/json",
        "Authorization":"Bearer "+os.environ["AI_API_KEY"],
    })
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data=json.loads(resp.read().decode("utf-8"))
        text=(data.get("choices") or [{}])[0].get("message",{}).get("content")
        return (text.strip() if text else None), None
    except Exception as exc:
        return None, f"AI provider request failed: {exc.__class__.__name__}"
