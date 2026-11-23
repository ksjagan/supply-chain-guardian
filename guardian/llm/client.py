"""
Unified LLM Client.
Supports Google Gemini, Anthropic Claude, and OpenAI via direct HTTP (requests).
Features SHA-256 prompt response caching, multi-model fallback, and automatic schema parsing.
"""
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from guardian.config import (
    CACHE_DIR,
    get_active_provider,
)


class LLMClient:
    """
    Unified client for calling Gemini, Anthropic, or OpenAI.
    Stores and reads responses from cache/llm_cache.json.
    """

    def __init__(self, api_key: Optional[str] = None, provider: Optional[str] = None):
        detected_prov, detected_key, detected_model = get_active_provider()
        self.provider = provider or detected_prov
        self.api_key = api_key or detected_key
        self.model = detected_model
        self.cache_file = CACHE_DIR / "llm_cache.json"
        self._cache: Dict[str, str] = {}
        self._load_cache()

    def is_available(self) -> bool:
        return bool(self.provider != "none" and self.api_key)

    def _load_cache(self) -> None:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self) -> None:
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def _cache_key(self, system_prompt: str, user_prompt: str) -> str:
        raw = f"{self.provider}:{self.model}:{system_prompt}:{user_prompt}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        """
        Sends prompt to the configured LLM and returns the raw string response.
        Uses cached responses if available.
        """
        if not self.is_available():
            raise RuntimeError("No LLM API key configured. Provide GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY.")

        ckey = self._cache_key(system_prompt, user_prompt)
        if ckey in self._cache:
            return self._cache[ckey]

        response_text = ""
        if self.provider == "gemini":
            response_text = self._call_gemini(system_prompt, user_prompt, temperature)
        elif self.provider == "anthropic":
            response_text = self._call_anthropic(system_prompt, user_prompt, temperature)
        elif self.provider == "openai":
            response_text = self._call_openai(system_prompt, user_prompt, temperature)
        else:
            raise RuntimeError(f"Unsupported provider: {self.provider}")

        self._cache[ckey] = response_text
        self._save_cache()
        return response_text

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        Calls LLM and parses the result as JSON.
        Handles markdown ```json ... ``` blocks gracefully.
        """
        system = system_prompt + "\nIMPORTANT: Return ONLY valid, raw JSON. Do not wrap in markdown or backticks."
        raw = self.complete(system, user_prompt)

        clean = raw.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        elif clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        clean = clean.strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError as exc:
            start = clean.find("{")
            end = clean.rfind("}")
            if start != -1 and end != -1:
                return json.loads(clean[start : end + 1])
            raise ValueError(f"Failed to parse LLM response as JSON: {exc}\nRaw: {raw}")

    # ── Providers ─────────────────────────────────────────────────────────────

    def _call_gemini(self, system: str, user: str, temp: float) -> str:
        # Fallback list of models in order of preference
        models_to_try = [
            self.model,
            "gemini-3.5-flash",
            "gemma-4-26b-a4b-it",
            "gemini-3.8-flash",
            "gemini-2.5-flash",
        ]
        # remove duplicates while preserving order
        seen = set()
        models = [m for m in models_to_try if m and not (m in seen or seen.add(m))]

        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system}\n\nTask:\n{user}"}]}
            ],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": 4096,
            }
        }

        last_error = None
        for m in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={self.api_key}"
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=25)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        text = "".join(p.get("text", "") for p in parts).strip()
                        if text:
                            self.model = m  # stick with working model
                            return text
                last_error = f"Model {m} returned HTTP {resp.status_code}"
            except Exception as e:
                last_error = str(e)

        raise RuntimeError(f"All Gemini models failed. Last error: {last_error}")

    def _call_anthropic(self, system: str, user: str, temp: float) -> str:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "temperature": temp,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        content = data.get("content", [])
        return "".join(c.get("text", "") for c in content if c.get("type") == "text")

    def _call_openai(self, system: str, user: str, temp: float) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temp,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError(f"OpenAI returned no choices: {data}")
        return choices[0].get("message", {}).get("content", "")
