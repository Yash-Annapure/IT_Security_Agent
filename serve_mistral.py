# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "torch>=2.4",
#   "transformers>=4.44",
#   "accelerate>=0.33",
#   "fastapi>=0.115",
#   "uvicorn[standard]>=0.30",
#   "sentencepiece>=0.2",
# ]
# ///
"""Self-contained Mistral-7B-Instruct host - no vLLM, no flash-attn.

    uv run serve_mistral.py

`uv run` reads the dependency block above and installs everything into an
isolated env automatically (separate from this repo's own uv.lock) - nothing
to `pip install` by hand. First run downloads the model from Hugging Face
(~15GB) and caches it; later runs just load from cache.

Serves the same OpenAI-compatible `/v1/chat/completions` surface vLLM did,
on the same default host:port, using plain `transformers` generation with
PyTorch's built-in SDPA attention - no compiled CUDA extension involved, so
none of the flash-attn/torch ABI breakage `vllm serve` was hitting. Trades
away vLLM's throughput (continuous batching, paged attention) for something
that Just Runs; fine for a single Cline session talking to one model.

Env vars: MODEL_ID (default mistralai/Mistral-7B-Instruct-v0.3), HOST
(default 0.0.0.0), PORT (default 8000, matching the README's vLLM instructions
so no Cline config change is needed), HF_TOKEN (only if the model needs auth).
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
import uuid
from threading import Lock

import torch
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.requests import Request
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_ID = os.environ.get("MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.3")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
TOOL_CALL_TOKEN = "[TOOL_CALLS]"

generate_lock = Lock()


def _detect_reachable_host() -> str | None:
    """Best-effort guess at this machine's LAN-reachable IP (same trick as mcp_server.py)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def startup_banner() -> str:
    public_host = _detect_reachable_host() if HOST == "0.0.0.0" else HOST
    lines = ["=" * 70, f"Mistral host (transformers): {MODEL_ID}", "=" * 70, f"Listening on {HOST}:{PORT}", ""]
    if public_host is None:
        lines += ["Could not auto-detect this machine's reachable IP - use whatever",
                   "address/hostname other machines on your network use to reach it."]
        public_host = "<this-machine>"
    lines += [
        "In Cline -> Settings -> API Provider -> \"OpenAI Compatible\":",
        f"  Base URL: http://{public_host}:{PORT}/v1",
        "  API Key: any non-empty placeholder",
        f"  Model ID: {MODEL_ID}",
        "",
        "No built-in auth - only expose this on a private/trusted network.",
        "=" * 70,
    ]
    return "\n".join(lines)


print(f"Loading {MODEL_ID} ...", flush=True)
dtype = torch.bfloat16 if torch.cuda.is_available() else torch.float32
if not torch.cuda.is_available():
    print("WARNING: no CUDA GPU detected - running a 7B model on CPU will be very slow.", flush=True)

tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    torch_dtype=dtype,
    device_map="auto",
    attn_implementation="sdpa",
    low_cpu_mem_usage=True,
)
model.eval()
print("Model loaded.", flush=True)

app = FastAPI()


@app.middleware("http")
async def normalize_path(request: Request, call_next):
    # Some OpenAI-compatible clients build the request path by string-joining a
    # Base URL that already ends in "/" with a leading-"/" path segment, producing
    # "//models" etc. Collapse repeated slashes before routing so a trailing slash
    # left in a client's Base URL field doesn't hard-404.
    path = request.scope["path"]
    collapsed = re.sub(r"/{2,}", "/", path)
    if collapsed != path:
        request.scope["path"] = collapsed
    return await call_next(request)


def parse_tool_calls(text: str) -> tuple[str, list[dict] | None]:
    """Split Mistral's `[TOOL_CALLS][...]` output into (leading text, OpenAI-style tool_calls)."""
    if TOOL_CALL_TOKEN not in text:
        return text.strip(), None
    before, _, after = text.partition(TOOL_CALL_TOKEN)
    after = after.strip()
    try:
        calls_raw, _ = json.JSONDecoder().raw_decode(after)
    except json.JSONDecodeError:
        return text.strip(), None
    tool_calls = [
        {
            "id": f"call_{uuid.uuid4().hex[:24]}",
            "type": "function",
            "function": {
                "name": call["name"],
                "arguments": json.dumps(call.get("arguments", {})),
            },
        }
        for call in calls_raw
    ]
    return before.strip(), tool_calls


def _flatten_content(content):
    # Some OpenAI clients (Cline included) send `content` as a list of parts -
    # [{"type": "text", "text": "..."}] - even for plain text messages, not just
    # multimodal ones. Mistral's chat template assumes a plain string and does
    # `content + "..."`, which TypeErrors on a list. Flatten to text; non-text
    # parts (e.g. images) are silently dropped since this is a text-only model.
    if not isinstance(content, list):
        return content
    parts = []
    for part in content:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, dict) and isinstance(part.get("text"), str):
            parts.append(part["text"])
    return "".join(parts)


def _normalize_messages(messages: list[dict]) -> list[dict]:
    normalized = []
    for m in messages:
        m = dict(m)
        if "content" in m:
            m["content"] = _flatten_content(m["content"])
        normalized.append(m)
    return normalized


DEBUG_PROMPT = os.environ.get("DEBUG_PROMPT", "0") == "1"


def run_generate(messages: list[dict], tools: list[dict] | None, max_new_tokens: int, temperature: float, top_p: float) -> str:
    normalized = _normalize_messages(messages)

    # Always-on, cheap sanity log: proves whether Cline's system message (which
    # carries .clinerules + its own tool-use instructions + MCP tool schemas)
    # actually arrived, and roughly how big it is. If "system" never shows up
    # here, the model genuinely never saw any of that - it's not ignoring
    # instructions, it never received them.
    roles_summary = ", ".join(f"{m.get('role')}={len(str(m.get('content') or ''))}chars" for m in normalized)
    print(f"[chat] {len(normalized)} messages: {roles_summary}  tools={len(tools) if tools else 0}", flush=True)

    inputs = tokenizer.apply_chat_template(
        normalized,
        tools=tools or None,
        add_generation_prompt=True,
        tokenize=True,
        return_tensors="pt",
        return_dict=True,
    ).to(model.device)

    if DEBUG_PROMPT:
        rendered = tokenizer.decode(inputs["input_ids"][0])
        print(f"----- RENDERED PROMPT ({len(rendered)} chars) -----", flush=True)
        print(rendered, flush=True)
        print("----- END RENDERED PROMPT -----", flush=True)

    gen_kwargs: dict = dict(**inputs, max_new_tokens=max_new_tokens, pad_token_id=tokenizer.eos_token_id)
    if temperature and temperature > 0:
        gen_kwargs.update(do_sample=True, temperature=temperature, top_p=top_p)
    else:
        gen_kwargs.update(do_sample=False)

    with generate_lock, torch.no_grad():
        output_ids = model.generate(**gen_kwargs)

    new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True)


@app.get("/")
@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_ID}


# Registered at both "/v1/..." (the OpenAI-standard path, what the README/Cline
# setup expects) and bare "/..." (some OpenAI-compatible clients strip or never
# add the "/v1" prefix depending on how their Base URL field is filled in) - so
# this doesn't hard-fail on a client-side path quirk either way.
@app.get("/v1/models")
@app.get("/models")
def list_models():
    return {"object": "list", "data": [{"id": MODEL_ID, "object": "model", "owned_by": "local"}]}


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    messages = body["messages"]
    tools = body.get("tools")
    if body.get("tool_choice") == "none":
        tools = None
    max_new_tokens = body.get("max_tokens") or 1024
    temperature = body.get("temperature", 0.7)
    top_p = body.get("top_p", 1.0)
    stream = body.get("stream", False)

    content_text = run_generate(messages, tools, max_new_tokens, temperature, top_p)
    content, tool_calls = parse_tool_calls(content_text)

    message = {"role": "assistant", "content": content or None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    finish_reason = "tool_calls" if tool_calls else "stop"

    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    response = {
        "id": completion_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": MODEL_ID,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }

    if not stream:
        return JSONResponse(response)

    # Not real token-level streaming (generation already ran above) - just SSE-framed
    # so streaming clients get one delta chunk instead of a raw JSON body they'd reject.
    chunk = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": response["created"],
        "model": MODEL_ID,
        "choices": [{"index": 0, "delta": message, "finish_reason": finish_reason}],
    }

    def sse():
        yield f"data: {json.dumps(chunk)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(sse(), media_type="text/event-stream")


if __name__ == "__main__":
    print(startup_banner(), flush=True)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
