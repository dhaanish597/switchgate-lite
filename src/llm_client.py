"""Live LLM client adapter (supporting Sarvam AI, OpenAI, and NVIDIA Build) and JSONL telemetry logger."""
import json
import os
import pathlib
import re
import time
from typing import Any, Callable, Dict, Optional, Tuple
import urllib.error
import urllib.request

from src.env_loader import load_local_env
from src.models import utc_now_iso

load_local_env()

DEFAULT_SARVAM_MODEL = "sarvam-105b-conversations"
DEFAULT_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"


class TelemetryLogger:
    """Appends model invocation telemetry to JSONL."""

    def __init__(self, log_dir: str = "./logs") -> None:
        self.log_dir = pathlib.Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.log_dir / "telemetry.jsonl"

    def record_call(
        self,
        agent_id: str,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        live_mode: bool,
    ) -> Dict[str, Any]:
        """Writes a single LLM telemetry entry to logs/telemetry.jsonl."""
        entry = {
            "timestamp": utc_now_iso(),
            "agent_id": agent_id,
            "provider": provider,
            "model": model,
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "total_tokens": int(prompt_tokens) + int(completion_tokens),
            "latency_ms": round(float(latency_ms), 2),
            "live_mode": bool(live_mode),
        }
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry


class LiveLLMClient:
    """Invokes live chat completions API (Sarvam AI / OpenAI / NVIDIA) or injected transport."""

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        telemetry: Optional[TelemetryLogger] = None,
        transport_fn: Optional[Callable[[str, str, Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        prov = (provider or os.environ.get("LLM_PROVIDER", "")).lower()
        if not prov:
            prov = "sarvam" if os.environ.get("SARVAM_API_KEY") else "nvidia"
        self.provider = prov
        if self.provider == "nvidia":
            self.model = model or os.environ.get("NVIDIA_MODEL") or DEFAULT_NVIDIA_MODEL
        elif self.provider == "sarvam":
            self.model = model or os.environ.get("SARVAM_MODEL") or os.environ.get("LLM_MODEL") or DEFAULT_SARVAM_MODEL
        else:
            self.model = model or os.environ.get("LLM_MODEL") or DEFAULT_NVIDIA_MODEL
        default_base = DEFAULT_NVIDIA_BASE_URL if self.provider == "nvidia" else ""
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL") or os.environ.get("NVIDIA_BASE_URL") or default_base).rstrip("/")
        self.telemetry = telemetry or TelemetryLogger()
        self.transport_fn = transport_fn

    def is_configured(self) -> bool:
        """Checks whether supported provider API keys or injected transport are available."""
        if self.transport_fn is not None:
            return True
        if self.provider == "nvidia":
            return bool(os.environ.get("NVIDIA_API_KEY", "").strip())
        if self.provider == "sarvam":
            return bool(os.environ.get("SARVAM_API_KEY", "").strip())
        for key_name in ("SARVAM_API_KEY", "OPENAI_API_KEY", "NVIDIA_API_KEY", "GEMINI_API_KEY"):
            if os.environ.get(key_name, "").strip():
                return True
        return False

    def generate_json(
        self, agent_id: str, system_prompt: str, user_prompt: str
    ) -> Dict[str, Any]:
        """Invokes the configured LLM and returns a validated JSON dictionary."""
        if not self.is_configured():
            raise RuntimeError(
                f"No API key configured for provider='{self.provider}' (model='{self.model}'). "
                "Export SARVAM_API_KEY, OPENAI_API_KEY, or NVIDIA_API_KEY."
            )
        start = time.time()
        if self.transport_fn is not None:
            result = self.transport_fn(system_prompt, user_prompt, {"model": self.model})
            latency = (time.time() - start) * 1000.0
            self.telemetry.record_call(
                agent_id=agent_id, provider=self.provider, model=self.model,
                prompt_tokens=len(system_prompt.split()) + len(user_prompt.split()),
                completion_tokens=len(json.dumps(result).split()),
                latency_ms=latency, live_mode=False,
            )
            return result

        raw_text, p_tok, c_tok = self._call_live_api(system_prompt, user_prompt)
        latency = (time.time() - start) * 1000.0
        self.telemetry.record_call(
            agent_id=agent_id, provider=self.provider, model=self.model,
            prompt_tokens=p_tok, completion_tokens=c_tok,
            latency_ms=latency, live_mode=True,
        )
        return self._extract_json_dict(raw_text)

    def _call_live_api(self, system_prompt: str, user_prompt: str) -> Tuple[str, int, int]:
        if self.provider == "sarvam" or (os.environ.get("SARVAM_API_KEY") and self.provider != "openai"):
            self.provider = "sarvam"
            if not self.model or "llama" in self.model:
                self.model = DEFAULT_SARVAM_MODEL
            return self._call_sarvam(system_prompt, user_prompt)
        return self._call_openai_compatible(system_prompt, user_prompt)

    def _call_sarvam(self, system_prompt: str, user_prompt: str) -> Tuple[str, int, int]:
        key = os.environ.get("SARVAM_API_KEY", "").strip()
        url = "https://api.sarvam.ai/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        headers = {"Content-Type": "application/json", "api-subscription-key": key}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = str(data["choices"][0]["message"]["content"])
        usage = data.get("usage") or {}
        return text, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))

    def _call_openai_compatible(self, system_prompt: str, user_prompt: str) -> Tuple[str, int, int]:
        api_key = (os.environ.get("OPENAI_API_KEY") or os.environ.get("NVIDIA_API_KEY") or "").strip()
        base = self.base_url or ("https://api.openai.com/v1" if os.environ.get("OPENAI_API_KEY") else DEFAULT_NVIDIA_BASE_URL)
        url = f"{base}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = str(data["choices"][0]["message"]["content"])
        usage = data.get("usage") or {}
        return text, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))

    @staticmethod
    def _extract_json_dict(raw_text: str) -> Dict[str, Any]:
        """Extracts and validates a JSON object from raw model output."""
        cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
        if cleaned.startswith("```"):
            lines = [ln for ln in cleaned.splitlines() if not ln.strip().startswith("```")]
            cleaned = "\n".join(lines).strip()
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        start_idx = cleaned.find("{")
        end_idx = cleaned.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            parsed = json.loads(cleaned[start_idx : end_idx + 1])
            if isinstance(parsed, dict):
                return parsed
        raise ValueError(f"Model output did not contain a valid JSON object: {raw_text[:200]}")
