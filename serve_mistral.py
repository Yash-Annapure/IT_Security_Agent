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
"""Self-contained local-model host - no vLLM, no flash-attn.

    uv run serve_mistral.py

`uv run` reads the dependency block above and installs everything into an
isolated env automatically (separate from this repo's own uv.lock) - nothing
to `pip install` by hand. First run downloads the model from Hugging Face and
caches it; later runs just load from cache.

Serves the same OpenAI-compatible `/v1/chat/completions` surface vLLM did,
on the same default host:port, using plain `transformers` generation with
PyTorch's built-in SDPA attention - no compiled CUDA extension involved, so
none of the flash-attn/torch ABI breakage `vllm serve` was hitting. Trades
away vLLM's throughput (continuous batching, paged attention) for something
that Just Runs; fine for a single Cline session talking to one model.

Defaults to Qwen/Qwen2.5-7B-Instruct, swapped in for Mistral-7B-Instruct-v0.3
because Qwen2.5 already ships a tool-aware chat template in its own
tokenizer_config.json (hermes-style `<tool_call>{...}</tool_call>` blocks) -
no custom template override needed, unlike the MISTRAL_TOOL_CHAT_TEMPLATE
hack this file used to carry. `parse_tool_calls()` below parses that
Qwen/hermes format specifically; swapping MODEL_ID to a model with a
different tool-call syntax (e.g. back to a Mistral model) needs that
function changed too, not just the env var.

Env vars: MODEL_ID (default Qwen/Qwen2.5-7B-Instruct), HOST (default
0.0.0.0), PORT (default 8000, matching the README's vLLM instructions so no
Cline config change is needed), HF_TOKEN (only if the model needs auth).
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
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.requests import Request
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_ID = os.environ.get("MODEL_ID", "Qwen/Qwen2.5-7B-Instruct")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# Qwen2.5-7B-Instruct's real trained context is 32768 tokens - not the tokenizer's much
# higher default model_max_length sanity-check value, which only catches truly absurd
# inputs and does nothing to stop a prompt that overshoots the model's actual positional
# embeddings. This project hit that directly: a 176,548-character raw uv.lock pushed one
# request to ~135,000 tokens, which both exceeded the model's real limit *and* OOM'd the
# GPU allocating KV-cache space for it. Reject oversized prompts before model.generate()
# ever runs instead of finding out via a CUDA crash. Leave headroom below 32768 for
# max_new_tokens plus the templating overhead apply_chat_template adds.
MAX_INPUT_TOKENS = int(os.environ.get("MAX_INPUT_TOKENS", "28000"))
TOOL_CALL_START = "<tool_call>"
TOOL_CALL_END = "</tool_call>"

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
    lines = ["=" * 70, f"Local model host (transformers): {MODEL_ID}", "=" * 70, f"Listening on {HOST}:{PORT}", ""]
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


@app.exception_handler(HTTPException)
async def openai_style_http_exception_handler(request: Request, exc: HTTPException):
    # FastAPI's default HTTPException body is {"detail": "..."} - OpenAI-compatible
    # clients (Cline included) expect {"error": {"message": ...}} and otherwise show
    # a bare "413 status code (no body)" with the actual reason nowhere in sight. This
    # is what makes the MAX_INPUT_TOKENS guard's message actually reach the caller.
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": exc.detail, "type": "invalid_request_error", "code": None}},
    )


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
    """Split Qwen/hermes-style `<tool_call>{...}</tool_call>` blocks out of raw
    generated text into (leading text, OpenAI-style tool_calls).

    Qwen2.5 can emit more than one `<tool_call>` block in a single turn (unlike
    Mistral's one `[TOOL_CALLS] [...]` JSON array) - each block holds its own
    JSON object, so they're parsed independently and a malformed block is
    skipped rather than failing the whole response.
    """
    if TOOL_CALL_START not in text:
        return text.strip(), None
    leading = text.split(TOOL_CALL_START, 1)[0].strip()
    pattern = re.escape(TOOL_CALL_START) + r"(.*?)" + re.escape(TOOL_CALL_END)
    tool_calls = []
    for block in re.findall(pattern, text, re.DOTALL):
        try:
            call = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        tool_calls.append({
            "id": f"call_{uuid.uuid4().hex[:24]}",
            "type": "function",
            "function": {
                "name": call["name"],
                "arguments": json.dumps(call.get("arguments", {})),
            },
        })
    if not tool_calls:
        return text.strip(), None
    return leading, tool_calls


def _flatten_content(content):
    # Some OpenAI clients (Cline included) send `content` as a list of parts -
    # [{"type": "text", "text": "..."}] - even for plain text messages, not just
    # multimodal ones. The tokenizer's chat template assumes a plain string and
    # does `content + "..."`, which TypeErrors on a list. Flatten to text;
    # non-text parts (e.g. images) are silently dropped since this is a
    # text-only model.
    if not isinstance(content, list):
        return content
    parts = []
    for part in content:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, dict) and isinstance(part.get("text"), str):
            parts.append(part["text"])
    return "".join(parts)


# Small instruct models default to "just ask the human" even when told not to and
# even when the answer is already sitting in the conversation - that's the loop this
# repo kept hitting (Cline asking the same lockfile question after being answered).
# This is appended to whatever system prompt Cline sends (which already carries
# .clinerules) as a last, blunt reinforcement targeted at that exact failure mode.
AGENT_REINFORCEMENT = (
    "\n\nCRITICAL AUTONOMY RULE: Before asking the user anything, check two things "
    "first: (1) can you get this yourself with one of your own tools (e.g. read a file "
    "directly instead of asking where it is or what it contains), and (2) did the user "
    "already answer this earlier in this conversation. If either is true, act on it "
    "immediately - call the tool - instead of asking. Never ask the same question twice "
    "in one conversation; if you already asked something and the user replied, use that "
    "reply now, do not ask again."
)


def _normalize_messages(messages: list[dict]) -> list[dict]:
    normalized = []
    for m in messages:
        m = dict(m)
        if "content" in m:
            m["content"] = _flatten_content(m["content"])
        normalized.append(m)
    if normalized and normalized[0].get("role") == "system" and isinstance(normalized[0].get("content"), str):
        normalized[0]["content"] += AGENT_REINFORCEMENT
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

    input_len = inputs["input_ids"].shape[1]
    if input_len > MAX_INPUT_TOKENS:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Prompt is {input_len} tokens, over this server's {MAX_INPUT_TOKENS}-token "
                f"limit (kept safely under the model's real 32768-token context, leaving "
                f"room to actually generate a response). This almost always means a full "
                f"raw lockfile ended up in the conversation instead of a condensed one - "
                f"run condense_lockfile.py on it first (see README.md and "
                f".clinerules/scan-repo.md) rather than reading the raw file directly."
            ),
        )

    if DEBUG_PROMPT:
        rendered = tokenizer.decode(inputs["input_ids"][0])
        print(f"----- RENDERED PROMPT ({len(rendered)} chars) -----", flush=True)
        print(rendered, flush=True)
        print("----- END RENDERED PROMPT -----", flush=True)

    # Agent tool-use wants the single most-likely continuation, not variety - sampling
    # at any real temperature is what lets a small model wander into "safe" fallbacks
    # like re-asking a question it already has the answer to instead of committing to
    # a tool call. Cline's own requested temperature is ignored here on purpose; cap it
    # instead of respecting it if you ever want some sampling back. MAX_TEMPERATURE=1
    # env var restores respecting the client's value, for comparison/debugging.
    max_temperature = float(os.environ.get("MAX_TEMPERATURE", "0"))
    effective_temperature = min(temperature or 0, max_temperature)
    gen_kwargs: dict = dict(**inputs, max_new_tokens=max_new_tokens, pad_token_id=tokenizer.eos_token_id)
    if effective_temperature > 0:
        gen_kwargs.update(do_sample=True, temperature=effective_temperature, top_p=top_p)
    else:
        gen_kwargs.update(do_sample=False)

    try:
        with generate_lock, torch.no_grad():
            output_ids = model.generate(**gen_kwargs)
    finally:
        # Plain transformers .generate() (unlike vLLM's paged attention) doesn't reclaim
        # its KV-cache allocations on its own between requests - on a long-running server
        # process, cached-but-unused CUDA blocks pile up across calls and shrink the free
        # VRAM available to the next one. Release them back to the allocator every call,
        # success or failure, so a long session doesn't slowly starve itself of headroom.
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

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
