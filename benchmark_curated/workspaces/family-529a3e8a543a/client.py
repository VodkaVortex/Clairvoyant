"""OpenAI-compatible JSON action transport, with bounded retries and full public trace."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


class Trace:
    def __init__(self, path: Path, secret=""):
        self.path, self.secret = path, secret

    def log(self, event: str, **values):
        record = {"time": datetime.now(timezone.utc).isoformat(), "event": event, **values}
        text = json.dumps(record, ensure_ascii=False)
        if self.secret:
            text = text.replace(self.secret, "[REDACTED]")
        with self.path.open("a") as handle:
            handle.write(text + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def parse_action(content):
    if not isinstance(content, str):
        raise ValueError("assistant content must be a string")
    text = content.strip()
    if text.startswith("```") and text.endswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    value = json.loads(text)
    if not isinstance(value, dict) or value.get("action") not in {"list", "search", "read", "report", "finish"}:
        raise ValueError("expected one JSON object with a supported action")
    return value


class ModelClient:
    def __init__(self, config, trace: Trace):
        self.config, self.trace = config, trace
        self.key = os.environ.get(config["api_key_env"], "")
        if not self.key:
            raise ValueError(f"missing environment variable: {config['api_key_env']}")

    def action(self, messages, step):
        cfg = self.config
        payload = {"model": cfg["model"], "messages": messages, "temperature": 0,
                   "max_tokens": cfg["max_tokens"], "response_format": {"type": "json_object"},
                   "chat_template_kwargs": {"enable_thinking": False}}
        for attempt in range(1, cfg["retries"] + 1):
            self.trace.log("api_request", step=step, attempt=attempt,
                           endpoint=cfg["base_url"].rstrip("/") + "/chat/completions", payload=payload)
            request = urllib.request.Request(cfg["base_url"].rstrip("/") + "/chat/completions",
                data=json.dumps(payload).encode(), method="POST",
                headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
            try:
                # Match the original project's direct connection behavior.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request, timeout=cfg["timeout"]) as response:
                    raw = response.read(4_000_001)
                if len(raw) > 4_000_000:
                    raise ValueError("API response exceeds 4 MB")
                body = raw.decode("utf-8")
                self.trace.log("api_response", step=step, attempt=attempt, raw_body=body)
                envelope = json.loads(body)
                choice = envelope["choices"][0]
                if choice.get("finish_reason") == "length":
                    raise ValueError("model response truncated; increase max_tokens")
                content = choice["message"]["content"]
                action = parse_action(content)
                return content, action
            except urllib.error.HTTPError as exc:
                raw_error = exc.read(16000).decode("utf-8", errors="replace")
                self.trace.log("api_error", step=step, attempt=attempt, status=exc.code, body=raw_error)
                if exc.code not in {408, 409, 429} and exc.code < 500:
                    raise RuntimeError(f"API HTTP {exc.code}; see trace.jsonl") from exc
                last = RuntimeError(f"API HTTP {exc.code}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                self.trace.log("api_error", step=step, attempt=attempt, error=str(exc))
                last = exc
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                self.trace.log("format_error", step=step, attempt=attempt, error=str(exc))
                last = exc
                payload["messages"] = messages + [{"role": "user", "content":
                    "Your last response was invalid: " + str(exc) +
                    ". Return ONE concise JSON action matching the tool schema. Do not include a long narrative."}]
            if attempt < cfg["retries"]:
                time.sleep(min(8, 2 ** (attempt - 1)))
        raise RuntimeError(f"model request failed after {cfg['retries']} attempts: {last}")
