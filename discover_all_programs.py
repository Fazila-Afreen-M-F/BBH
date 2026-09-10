#!/usr/bin/env python3
"""
discover_all_programs.py

Monthly full-discovery + auto-vetting across HackerOne, Intigriti, YesWeHack,
and Bugcrowd. Pulls every public program, applies safety/scope conditions,
and writes clean, scan-ready domain lists.
"""

import argparse
import base64
import csv
import json
import os
import shutil
import sys
from datetime import datetime, timezone
import re
import hashlib
import socket
import time
import urllib.error
import urllib.request
import tldextract

HOME = os.path.expanduser("~")
MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR") or os.path.join(HOME, "bug-bounty-hunter")
MAPPING_PATH = os.environ.get("MAPPING_CSV_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domain_program_map.csv")
EXCLUDED_OUTPUT_PATH = os.environ.get("EXCLUDED_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "excluded_domains.txt")

MIN_RATE_LIMIT = 5
DOMAINS_TXT_PATH = os.environ.get("DOMAINS_TXT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domains.txt")

MIN_ABSOLUTE_DOMAINS_PER_PLATFORM = int(os.environ.get("MIN_ABSOLUTE_DOMAINS_PER_PLATFORM") or 0)
MIN_ABSOLUTE_DOMAINS_TOTAL = int(os.environ.get("MIN_ABSOLUTE_DOMAINS_TOTAL") or 0)
CANDIDATE_DOMAINS_REVIEW_CAP = int(os.environ.get("CANDIDATE_DOMAINS_REVIEW_CAP") or 100)

FETCH_EXCEPTIONS = (
    urllib.error.HTTPError,
    urllib.error.URLError,
    json.JSONDecodeError,
    KeyError,
    TypeError,
    socket.timeout,
)

AUTOMATION_BAN_PATTERNS = [
    r"do not use automat\w*",
    r"no automated (?:scan\w*|tool\w*|test)",
    r"not permitted to use automat\w*",
    r"prohibited from using automat\w*",
    r"automated tools? (?:is|are) not (?:allowed|permitted)",
    r"do not use scanners",
]

# Condition #3 requires EXPLICIT permission for automated scanning - silence
# is not permission. These patterns are the converse of AUTOMATION_BAN_PATTERNS:
# they catch explicit grants, not the mere absence of a ban.
AUTOMATION_ALLOW_PATTERNS = [
    r"automated (?:scan\w*|tool\w*|test\w*) (?:is|are) (?:allowed|permitted|welcome)",
    r"(?:you )?(?:may|can) use automated (?:scan\w*|tool\w*)",
    r"we allow automated (?:scan\w*|tool\w*|test\w*)",
    r"automated (?:scanning|testing|tools?) (?:is|are) (?:permitted|allowed|welcome)",
    r"manual and automated (?:test\w*|scan\w*) (?:is|are) (?:both )?(?:allowed|permitted|welcome)",
    r"automated (?:scan\w*|tool\w*) (?:is|are) permitted (?:as long as|provided|if)",
]

SAFE_HARBOR_PATTERNS = [
    r"safe harbor",
    r"good faith security research",
    r"will not (?:pursue|initiate|bring) legal action",
    r"authoriz\w+ under (?:this|our) polic",
    r"we will not (?:sue|prosecute)",
    r"legal safe harbor",
    r"exempt(?:ion)? from (?:legal action|prosecution)",
]
SAFE_HARBOR_PATTERN = re.compile("|".join(SAFE_HARBOR_PATTERNS), re.I)

RATE_LIMIT_PATTERN = re.compile(
    r"(?P<value>\d+(?:\.\d+)?)\s*(?:"
    r"rps\b"
    r"|(?:requests?|reqs?)?\s*(?:per|/)\s*(?P<unit>second|sec|s|minute|min|m|hour|hr|h|day|d)\b"
    r")",
    re.I,
)

ID_VERIFICATION_PATTERNS = [
    r"government[- ]issued id",
    r"proof of identity",
    r"\bkyc\b",
    r"know your customer",
    r"identity verification",
    r"verify your identity",
    r"upload (?:a )?(?:copy of )?(?:your )?(?:passport|id\b|national id|driver)",
    r"background check",
    r"social security number",
    r"\bssn\b",
]
ID_VERIFICATION_PATTERN = re.compile("|".join(ID_VERIFICATION_PATTERNS), re.I)


def log(msg):
    print(msg, flush=True)


def fetch_json(url, headers=None, timeout=40, max_retries=5):
    req = urllib.request.Request(url, headers=headers or {})
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode()
            data = json.loads(body)
            return data, None
        except urllib.error.HTTPError as e:
            retryable = e.code in (403, 429) or e.code >= 500
            if retryable and attempt < max_retries - 1:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                wait = float(retry_after) if retry_after else (2 ** attempt)
                log(f"[RATE LIMIT] {url} -> {e.code}, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            return None, f"HTTPError {e.code}"
        except (urllib.error.URLError, socket.timeout) as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                log(f"[NETWORK] {url} -> {type(e).__name__}: {e}, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            return None, f"{type(e).__name__}: {e}"
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return None, f"{type(e).__name__}: {e}"


def fetch_text(url, headers=None, timeout=40, max_retries=5):
    req = urllib.request.Request(url, headers=headers or {})
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode(), None
        except urllib.error.HTTPError as e:
            retryable = e.code in (403, 429) or e.code >= 500
            if retryable and attempt < max_retries - 1:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                wait = float(retry_after) if retry_after else (2 ** attempt)
                log(f"[RATE LIMIT] {url} -> {e.code}, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            return None, f"HTTPError {e.code}"
        except (urllib.error.URLError, socket.timeout) as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                log(f"[NETWORK] {url} -> {type(e).__name__}: {e}, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            return None, f"{type(e).__name__}: {e}"
    return None, "max_retries_exceeded"


def check_automation_ban(text):
    if not text:
        return False, None
    for pat in AUTOMATION_BAN_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            start = max(0, m.start() - 100)
            end = min(len(text), m.end() + 100)
            cleaned = re.sub(r"\s+", " ", text[start:end]).strip()
            return True, cleaned
    return False, None


def check_automation_allow(text):
    """Fast regex sweep of the FULL text (not chunked - regex has no context
    window limit) for explicit language granting permission to use automated
    scanners/tools. This is the only thing that can turn condition #3's
    'silent' default into a keep."""
    if not text:
        return False, None
    for pat in AUTOMATION_ALLOW_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            start = max(0, m.start() - 100)
            end = min(len(text), m.end() + 100)
            cleaned = re.sub(r"\s+", " ", text[start:end]).strip()
            return True, cleaned
    return False, None


def check_safe_harbor(text):
    if not text:
        return False, None
    m = SAFE_HARBOR_PATTERN.search(text)
    if m:
        start = max(0, m.start() - 100)
        end = min(len(text), m.end() + 400)
        cleaned = re.sub(r"\s+", " ", text[start:end]).strip()
        return True, cleaned
    return False, None


def mistral_check_safe_harbor(text, program_name):
    if not text:
        return None
    cache_key = hashlib.sha256(("safeharbor:" + text[:8000]).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, text[:200], cached.get("has_safe_harbor"), cached["reason"] + " [CACHED]", error=None)
        return cached.get("has_safe_harbor")
    if not MISTRAL_API_KEY:
        return None
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL, _MISTRAL_CALLS_SINCE_SAVE
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return None
    _mistral_pace()
    prompt = (
        "You are reviewing policy text from a bug bounty program. Answer "
        "ONLY with valid JSON, no other text, in this exact format: "
        '{"has_safe_harbor": true or false, "reason": "one short sentence"}.'
        "\n\n"
        "Question: Does this policy text explicitly grant researchers legal "
        "safe harbor - i.e. a promise that the company will not pursue legal "
        "action or law enforcement referral against researchers who follow "
        "the program's rules in good faith? Look for phrases like 'safe "
        "harbor', 'good faith research', 'will not pursue legal action', "
        "'authorized under this policy'. Answer false if the policy is "
        "silent on legal protection, vague, or only discusses rewards/scope "
        "without any legal-action promise.\n\n"
        f"Text:\n{text[:8000]}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "User-Agent": "bug-bounty-hunter-vet/1.0",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            text_resp = data["choices"][0]["message"]["content"].strip()
            text_resp = text_resp.strip("`")
            if text_resp.startswith("json"):
                text_resp = text_resp[4:].strip()
            m = re.search(r'"has_safe_harbor"\s*:\s*(true|false)', text_resp, re.IGNORECASE)
            if not m:
                raise ValueError(f"could not find has_safe_harbor in response: {text_resp[:150]}")
            has_sh = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text_resp, re.DOTALL)
            reason = rm.group(1) if rm else text_resp[:150]
            log_mistral_call(program_name, text[:200], has_sh, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"has_safe_harbor": has_sh, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return has_sh
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, text[:200], None, None, error=str(last_err))
    return None


MAX_FULLTEXT_FALLBACK_CHUNKS = 5

def _chunk_text(text, max_len=7500):
    """Split text into chunks up to max_len chars, breaking on paragraph
    boundaries where possible so a real clause is never sliced in half."""
    if len(text) <= max_len:
        return [text]
    paras = text.split("\n\n")
    chunks = []
    current = ""
    for p in paras:
        candidate = (current + "\n\n" + p) if current else p
        if len(candidate) > max_len and current:
            chunks.append(current)
            current = p
        else:
            current = candidate
    if current:
        chunks.append(current)
    final = []
    for c in chunks:
        if len(c) <= max_len:
            final.append(c)
        else:
            for i in range(0, len(c), max_len):
                final.append(c[i:i + max_len])
    return final

def mistral_check_implied_safe(text, program_name):
    if not text:
        return None
    cache_key = hashlib.sha256(("impliedsafe:" + text[:8000]).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, text[:200], cached.get("implied_safe"), cached["reason"] + " [CACHED]", error=None)
        return cached.get("implied_safe")
    if not MISTRAL_API_KEY:
        return None
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL, _MISTRAL_CALLS_SINCE_SAVE
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return None
    _mistral_pace()
    prompt = (
        "You are reviewing policy text from a bug bounty program. Answer "
        "ONLY with valid JSON: " +
        chr(123) + '"implied_safe": true or false, "reason": "one short sentence"' + chr(125) + "." +
        "\n\n"
        "This program has NO explicit legal safe-harbor promise. Question: "
        "does the text still genuinely welcome security research - active "
        "public program, defined scope, rewards/thanks for valid reports, "
        "inviting language ('we welcome', 'responsible disclosure') - AND "
        "contain no hostile or threatening language ('do not test', 'we "
        "will pursue legal action', 'unauthorized access is a crime')? "
        "Answer true only if welcoming AND not hostile. Answer false if "
        "either hostile language is present, or the text is too thin/vague "
        "to judge either way.\n\n"
        f"Text:\n{text[:8000]}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {MISTRAL_API_KEY}",
                 "User-Agent": "bug-bounty-hunter-vet/1.0"},
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            text_resp = data["choices"][0]["message"]["content"].strip().strip("`")
            if text_resp.startswith("json"):
                text_resp = text_resp[4:].strip()
            m = re.search(r'"implied_safe"\s*:\s*(true|false)', text_resp, re.IGNORECASE)
            if not m:
                raise ValueError(f"could not find implied_safe in response: {text_resp[:150]}")
            is_safe = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text_resp, re.DOTALL)
            reason = rm.group(1) if rm else text_resp[:150]
            log_mistral_call(program_name, text[:200], is_safe, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"implied_safe": is_safe, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return is_safe
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, text[:200], None, None, error=str(last_err))
    return None


def check_safe_harbor_two_layer(text, program_name):
    found, snippet = check_safe_harbor(text)
    if found:
        result = mistral_check_safe_harbor(snippet, program_name)
        if result is None:
            return "review", f"[Mistral call failed — queued for retry] {snippet[:80]}", "explicit"
        if result:
            return True, f"[Mistral-confirmed safe harbor] {snippet[:80]}", "explicit"
    else:
        if not text:
            return False, None, "none"
        any_review = False
        for chunk in _chunk_text(text)[:MAX_FULLTEXT_FALLBACK_CHUNKS]:
            result = mistral_check_safe_harbor(chunk, program_name)
            if result is None:
                any_review = True
                continue
            if result:
                return True, "[Mistral-confirmed safe harbor, no regex match]", "explicit"
        if any_review:
            return "review", "[Mistral call failed on full-text check — queued for retry]", "explicit"

    implied = mistral_check_implied_safe(text, program_name)
    if implied is None:
        return "review", "[Mistral call failed on implied-safe check — queued for retry]", "implied"
    if implied:
        return True, "[Mistral-confirmed implied-safe: welcoming, no hostile language]", "implied"
    return False, None, "none"


def check_id_verification_required(text):
    if not text:
        return False, None
    m = ID_VERIFICATION_PATTERN.search(text)
    if m:
        start = max(0, m.start() - 100)
        end = min(len(text), m.end() + 100)
        cleaned = re.sub(r"\s+", " ", text[start:end]).strip()
        return True, cleaned
    return False, None

def mistral_check_id_verification(snippet, program_name):
    global _MISTRAL_CALLS_SINCE_SAVE
    cache_key = hashlib.sha256(("idcheck:" + snippet).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, snippet, cached["is_ban"], cached["reason"] + " [CACHED]", error=None)
        return cached["is_ban"]
    if not MISTRAL_API_KEY:
        return None
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return None
    _mistral_pace()
    prompt = (
        "You are reviewing policy text from a bug bounty program. Answer "
        "ONLY with valid JSON, no other text, in this exact format: "
        '{"is_ban": true or false, "reason": "one short sentence"}.\n\n'
        "Question: Does this text require a researcher to submit personal "
        "identity documents or undergo identity verification (e.g. "
        "government ID, passport, KYC, background check, SSN) before they "
        "are allowed to participate or get paid?\n\n"
        "Answer true only if real personal identity verification is "
        "required. Answer false for unrelated mentions (e.g. verifying "
        "the identity of a vulnerability, or account/session identifiers "
        "that are not personal ID documents).\n\n"
        f"Text:\n{snippet}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "User-Agent": "bug-bounty-hunter-vet/1.0",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            text = data["choices"][0]["message"]["content"].strip().strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
            m = re.search(r'"is_ban"\s*:\s*(true|false)', text, re.IGNORECASE)
            if not m:
                raise ValueError(f"could not find is_ban in response: {text[:150]}")
            is_ban = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text, re.DOTALL)
            reason = rm.group(1) if rm else text[:150]
            log_mistral_call(program_name, snippet, is_ban, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"is_ban": is_ban, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return is_ban
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    body = e.read().decode()
                except Exception:
                    body = "<could not read body>"
                retry_after = e.headers.get("Retry-After") if e.headers else None
                with open(os.path.join(OUTPUT_DIR, "mistral_429_debug.log"), "a") as df:
                    df.write(f"--- {program_name} ---\n")
                    df.write(f"retry_after: {retry_after}\n")
                    df.write(f"body: {body}\n\n")
                try:
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                wait = 5 * (attempt + 1)
                if e.code == 429:
                    try:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        if ra is not None:
                            wait = max(wait, min(int(float(ra)) + 1, 90))
                    except (TypeError, ValueError):
                        pass
                time.sleep(wait)
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, snippet, None, None, error=str(last_err))
    return None

def mistral_check_implied_id_required(text, program_name):
    if not text:
        return None
    cache_key = hashlib.sha256(("impliedid:" + text[:8000]).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, text[:200], cached.get("implied_id_required"), cached["reason"] + " [CACHED]", error=None)
        return cached.get("implied_id_required")
    if not MISTRAL_API_KEY:
        return None
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL, _MISTRAL_CALLS_SINCE_SAVE
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return None
    _mistral_pace()
    prompt = (
        "You are reviewing policy text from a bug bounty program. Answer "
        "ONLY with valid JSON: "
        + chr(123) + '"implied_id_required": true or false, "reason": "one short sentence"' + chr(125) + "."
        + "\n\n"
        "This program has NO explicit ID-verification requirement phrase. "
        "Question: does the text still genuinely imply researchers must "
        "prove their real-world identity to participate - even without "
        "exact words like 'KYC' or 'government ID' - e.g. requiring legal "
        "name registration, background checks, signed contracts tied to "
        "identity, or account verification steps that reveal who you are? "
        "Answer true only if identity verification is clearly implied. "
        "Answer false if the text is silent, vague, or only mentions "
        "unrelated account signup.\n\n"
        f"Text:\n{text[:8000]}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL, data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {MISTRAL_API_KEY}", "User-Agent": "bug-bounty-hunter-vet/1.0"},
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            text_resp = data["choices"][0]["message"]["content"].strip().strip("`")
            if text_resp.startswith("json"):
                text_resp = text_resp[4:].strip()
            m = re.search(r'"implied_id_required"\s*:\s*(true|false)', text_resp, re.IGNORECASE)
            if not m:
                raise ValueError(f"could not find implied_id_required in response: {text_resp[:150]}")
            is_required = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text_resp, re.DOTALL)
            reason = rm.group(1) if rm else text_resp[:150]
            log_mistral_call(program_name, text[:200], is_required, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"implied_id_required": is_required, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return is_required
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, text[:200], None, None, error=str(last_err))
    return None


def check_id_verification_two_layer(text, program_name, id_verification_override=None):
    if id_verification_override is not None:
        if id_verification_override:
            return True, "[structured API kyc_required=true]", "structured"
        return False, "[structured API kyc_required=false]", "structured"
    matched, snippet = check_id_verification_required(text)
    if matched:
        result = mistral_check_id_verification(snippet, program_name)
        if result is None:
            return "review", f"[Mistral call failed — queued for retry] {snippet[:80]}", "explicit"
        if result:
            return True, f"[Mistral-confirmed ID requirement] {snippet[:80]}", "explicit"
    else:
        if not text:
            return False, None, "none"
        any_review = False
        for chunk in _chunk_text(text)[:MAX_FULLTEXT_FALLBACK_CHUNKS]:
            result = mistral_check_id_verification(chunk, program_name)
            if result is None:
                any_review = True
                continue
            if result:
                return True, "[Mistral-confirmed ID requirement, no regex match]", "explicit"
        if any_review:
            return "review", "[Mistral call failed on full-text check — queued for retry]", "explicit"
    implied = mistral_check_implied_id_required(text, program_name)
    if implied is None:
        return "review", "[Mistral call failed on implied check — queued for retry]", "implied"
    if implied:
        return True, "[Mistral-implied ID requirement, no explicit language]", "implied"
    return False, None, "none"


def check_rate_limit(text):
    if not text:
        return None, None
    m = RATE_LIMIT_PATTERN.search(text)
    if not m:
        return None, None
    value = float(m.group("value"))
    unit = (m.group("unit") or "s").lower()  # no unit group -> matched bare "rps" -> per-second
    if unit in ("minute", "min", "m"):
        value = value / 60
    elif unit in ("hour", "hr", "h"):
        value = value / 3600
    elif unit in ("day", "d"):
        value = value / 86400
    start = max(0, m.start() - 100)
    end = min(len(text), m.end() + 100)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    return value, snippet


def mistral_check_rate_limit(text, program_name):
    global _MISTRAL_CALLS_SINCE_SAVE
    if not text:
        return None
    cache_key = hashlib.sha256(("ratecheck:" + text[:8000]).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, text[:200], cached.get("rate"), cached["reason"] + " [CACHED]", error=None)
        return cached.get("rate")
    if not MISTRAL_API_KEY:
        return "error"
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return "error"
    _mistral_pace()
    prompt = (
        "You are reviewing policy text from a bug bounty program. Answer "
        "ONLY with valid JSON, no other text, in this exact format: "
        '{"rate_limit": number or null, "unit": "second" or "minute" or "hour" or "day" or null, "reason": "one short sentence"}.\n\n'
        "Question: Does this text state a maximum request rate or scanning "
        "throttle for automated tools (e.g. 'no more than 10 requests per "
        "second', 'please keep scanning to a slow, reasonable pace', "
        "'max 1 req/s')? Extract the numeric rate and its time unit if "
        "stated, even if phrased informally. Return null for both fields "
        "if no rate limit is mentioned at all.\n\n"
        f"Text:\n{text[:8000]}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "User-Agent": "bug-bounty-hunter-vet/1.0",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"].strip().strip("`")
            if content.startswith("json"):
                content = content[4:].strip()
            rm = re.search(r'"rate_limit"\s*:\s*(\d+(?:\.\d+)?|null)', content)
            um = re.search(r'"unit"\s*:\s*"?(second|minute|hour|day|null)"?', content, re.IGNORECASE)
            reasonm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', content, re.DOTALL)
            reason = reasonm.group(1) if reasonm else content[:150]
            if not rm or rm.group(1) == "null":
                log_mistral_call(program_name, text[:200], False, reason, error=None)
                _MISTRAL_CACHE[cache_key] = {"rate": None, "reason": reason}
                _MISTRAL_CALLS_SINCE_SAVE += 1
                if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                    save_mistral_cache(_MISTRAL_CACHE)
                    _MISTRAL_CALLS_SINCE_SAVE = 0
                return None
            value = float(rm.group(1))
            unit = um.group(1).lower() if um else "second"
            if unit == "minute":
                rate = value / 60
            elif unit == "hour":
                rate = value / 3600
            elif unit == "day":
                rate = value / 86400
            else:
                rate = value
            log_mistral_call(program_name, text[:200], True, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"rate": rate, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return rate
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    body = e.read().decode()
                except Exception:
                    body = "<could not read body>"
                retry_after = e.headers.get("Retry-After") if e.headers else None
                with open(os.path.join(OUTPUT_DIR, "mistral_429_debug.log"), "a") as df:
                    df.write(f"--- {program_name} ---\n")
                    df.write(f"retry_after: {retry_after}\n")
                    df.write(f"body: {body}\n\n")
                try:
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                wait = 5 * (attempt + 1)
                if e.code == 429:
                    try:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        if ra is not None:
                            wait = max(wait, min(int(float(ra)) + 1, 90))
                    except (TypeError, ValueError):
                        pass
                time.sleep(wait)
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, text[:200], None, None, error=str(last_err))
    return "error"


def check_rate_limit_two_layer(text, program_name):
    rate, snippet = check_rate_limit(text)
    if rate is not None:
        result = mistral_check_rate_limit(snippet, program_name)
        if result == "error":
            # Mistral confirmation failed transiently, but regex already
            # found an explicit rate in the text - keep it rather than
            # discarding a real detected limit and silently treating the
            # program as having no rate limit at all (condition #2 fail).
            return rate, "review"
        if result is not None:
            return min(rate, result), None
        return rate, "review"
    if not text:
        return None, None
    lowest_rate = None
    any_error = False
    for chunk in _chunk_text(text)[:MAX_FULLTEXT_FALLBACK_CHUNKS]:
        result = mistral_check_rate_limit(chunk, program_name)
        if result == "error":
            any_error = True
            continue
        if result is not None:
            if lowest_rate is None or result < lowest_rate:
                lowest_rate = result
    if lowest_rate is not None:
        return lowest_rate, None
    if any_error:
        return None, "review"
    return None, None
def clean_html(text):
    return re.sub(r"<[^<]+?>", " ", text or "")


def discover_hackerone(token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
    while url:
        data, err = fetch_json(url, headers)
        if err:
            log(f"[H1] pagination fetch failed: {err}")
            break
        skipped_private = 0
        for p in data.get("data", []):
            a = p["attributes"]
            if a.get("state") != "public_mode":
                skipped_private += 1
                continue
            programs.append({
                "handle": a.get("handle"),
                "name": a.get("name"),
                "submission_state": a.get("submission_state"),
                "offers_bounties": a.get("offers_bounties"),
            })
        if skipped_private:
            log(f"[H1] skipped {skipped_private} non-public (private/invite-only) programs this page")
        url = data.get("links", {}).get("next")
        time.sleep(0.3)
    log(f"[H1] discovered {len(programs)} total programs")
    return programs, auth


def fetch_hackerone_structured_scopes(handle, headers):
    """Fetch the FULL structured-scope list for a program via HackerOne's
    dedicated, paginated endpoint, rather than trusting the relationships
    blob embedded in the single program-show response (which HackerOne's
    own docs say is not the source of truth for the complete list - see
    'Get Structured Scopes'). Returns (list_of_scope_attribute_dicts, error).
    On any fetch error, returns (None, err) so the caller can fall back."""
    scopes = []
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes?page[size]=100"
    seen_urls = set()
    while url:
        if url in seen_urls:
            break  # defensive: avoid an infinite loop if the API ever repeats a `next` link
        seen_urls.add(url)
        data, err = fetch_json(url, headers)
        if err:
            return None, err
        for s in data.get("data", []):
            sa = s.get("attributes", {})
            if sa:
                scopes.append(sa)
        url = data.get("links", {}).get("next")
        if url:
            time.sleep(0.3)
    return scopes, None


def clean_asset_identifier(raw):
    """HackerOne's asset_identifier field can come back as markdown link
    syntax, e.g. '[www.example.com](https://www.example.com)', instead of
    a plain domain. Extract the real domain from the URL portion when this
    happens; otherwise return the value unchanged."""
    if not raw:
        return raw
    m = re.match(r'^\[([^\]]+)\]\((https?://[^)]+)\)$', raw.strip())
    if m:
        url_part = m.group(2)
        domain = re.sub(r'^https?://', '', url_part).split('/')[0]
        return domain
    return raw


def evaluate_policy_conditions(text, program_name, min_rate, safe_harbor_override=None, id_verification_override=None):
    """Runs policy-text conditions (safe harbor, automation, ID verification,
    rate limit) IN ORDER and stops at the first hard-fail or review - same
    short-circuit behavior as the original per-platform vet functions.
    Restored after the unconditional-all-4-checks version proved too slow:
    at MISTRAL_MIN_INTERVAL_S=16s/call and up to 4 calls/program with no
    short-circuit, 592 programs could take ~10.5h, past the job timeout.
    Returns the same dict shape as before; any condition skipped because an
    earlier one already stopped evaluation is left at a "not_checked"
    sentinel (rate_limit: (None, "not_checked")) rather than a real result -
    callers only read hard_fail/needs_review/reasons/rate_limit[0], so this
    is safe.
    """
    reasons = []
    hard_fail = False
    any_review = False
    automation_status = "not_checked"
    id_req = "not_checked"
    id_basis = "not_checked"
    rate, rate_status = None, "not_checked"

    def result():
        eligible = (not hard_fail) and (not any_review)
        return {
            "eligible": eligible,
            "hard_fail": hard_fail,
            "needs_review": any_review and not hard_fail,
            "reasons": reasons,
            "safe_harbor": sh_ok,
            "safe_harbor_basis": sh_basis,
            "automation": automation_status,
            "id_verification": id_req,
            "id_verification_basis": id_basis,
            "rate_limit": (rate, rate_status),
        }

    # --- Safe harbor ---
    if safe_harbor_override is not None:
        sh_ok, sh_snippet, sh_basis = safe_harbor_override, "[structured API safe-harbor flag]", "structured"
    else:
        sh_ok, sh_snippet, sh_basis = check_safe_harbor_two_layer(text, program_name)
    if sh_ok == "review":
        any_review = True
        reasons.append(f"safe harbor: review - {sh_snippet}")
    elif not sh_ok:
        hard_fail = True
        reasons.append(f"safe harbor not confirmed: {(sh_snippet or 'no safe-harbor language found in full policy text')[:80]}")
    if hard_fail or any_review:
        return result()

    # --- Automation permission ---
    automation_status, auto_snippet = check_automation_ban_two_layer(text, program_name)
    if automation_status == "review":
        any_review = True
        reasons.append(f"automation: review - {auto_snippet}")
    elif automation_status != "allowed":
        hard_fail = True
        reason = "automation ban" if automation_status == "banned" else "no explicit automation permission (silent)"
        reasons.append(f"{reason}: {(auto_snippet or '')[:80]}")
    if hard_fail or any_review:
        return result()

    # --- ID verification ---
    id_req, id_snippet, id_basis = check_id_verification_two_layer(text, program_name, id_verification_override)
    if id_req == "review":
        any_review = True
        reasons.append(f"id verification: review - {id_snippet}")
    elif id_req is True:
        hard_fail = True
        reasons.append(f"requires ID verification: {(id_snippet or '')[:80]}")
    if hard_fail or any_review:
        return result()

    # --- Rate limit ---
    rate, rate_status = check_rate_limit_two_layer(text, program_name)
    if rate_status == "review":
        any_review = True
        reasons.append("rate limit: review - Mistral call failed on rate-limit check")
    elif rate is not None and rate < min_rate:
        hard_fail = True
        reasons.append(f"rate limit below {min_rate}/s (found: {rate})")

    return result()


def vet_hackerone_program(handle, auth, results):
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    data, err = fetch_json(f"https://api.hackerone.com/v1/hackers/programs/{handle}", headers)
    time.sleep(0.3)
    if err:
        results["skipped"].append((handle, err, 0))
        return
    a = data.get("attributes", {})
    policy = a.get("policy", "") or ""
    domains = []
    out_domains = []
    scope_attrs, scope_err = fetch_hackerone_structured_scopes(handle, headers)
    if scope_err:
        # Dedicated endpoint failed (rate limit, transient error, etc.) -
        # fall back to whatever was embedded in the program-show response
        # rather than treating the whole program as unvettable.
        scope_attrs = [s.get("attributes", {}) for s in data.get("relationships", {}).get("structured_scopes", {}).get("data", [])]
    for sa in scope_attrs:
        if sa.get("asset_type") not in ("URL", "WILDCARD"):
            continue
        asset = clean_asset_identifier(sa.get("asset_identifier") or "").lower()
        if not asset:
            continue
        if sa.get("eligible_for_submission"):
            domains.append(asset)
        elif sa.get("eligible_for_submission") is False:
            out_domains.append(asset)
    domain_count = len(domains)
    if a.get("submission_state") != "open":
        results["excluded"].append((handle, f"not open (submission_state={a.get('submission_state')})", domain_count))
        return
    if a.get("state") != "public_mode":
        results["excluded"].append((handle, f"not public (state={a.get('state')})", domain_count))
        return
    sh_override = True if a.get("gold_standard_safe_harbor") is True else None
    ev = evaluate_policy_conditions(policy, handle, MIN_RATE_LIMIT, safe_harbor_override=sh_override)
    if ev["hard_fail"]:
        results["excluded"].append((handle, " | ".join(ev["reasons"]), domain_count))
        return
    if ev["needs_review"]:
        results["skipped"].append((handle, " | ".join(ev["reasons"]), domain_count))
        return
    results["included"].append({
        "handle": handle,
        "offers_bounties": a.get("offers_bounties"),
        "safe_harbor": True,
        "rate_limit": ev["rate_limit"][0],
        "domains": domains,
        "out_domains": out_domains,
    })


def discover_intigriti(token):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data, err = fetch_json(
        "https://api.intigriti.com/external/researcher/v1/programs?limit=500", headers
    )
    if err:
        log(f"[Intigriti] discovery failed: {err}")
        return []
    items = data.get("records", [])
    log(f"[Intigriti] discovered {len(items)} total programs")
    return items


def vet_intigriti_program(program, token, results):
    pid = program["id"]
    name = program.get("name", pid)
    status = program.get("status", {}).get("value")
    if status != "Open":
        results["excluded"].append((pid, f"{name}: not open (status={status})", 0))
        return
    confidentiality = program.get("confidentialityLevel", {}).get("value")
    if confidentiality != "Public":
        results["excluded"].append((pid, f"{name}: not public (confidentialityLevel={confidentiality})", 0))
        return
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data, err = fetch_json(
        f"https://api.intigriti.com/external/researcher/v1/programs/{pid}", headers, max_retries=1
    )
    time.sleep(0.3)
    if err:
        if "403" in err:
            results["excluded"].append((pid, f"{name}: private/invite-gated program, no API access", 0))
        else:
            results["skipped"].append((pid, f"{name}: {err}", 0))
        return
    domains = []
    out_domains = []
    for d in data.get("domains", {}).get("content", []):
        asset_type = d.get("type", {}).get("value")
        tier = d.get("tier", {}).get("value")
        tier_id = d.get("tier", {}).get("id")
        if asset_type not in ("Url", "Wildcard"):
            continue
        endpoint = d.get("endpoint") or d.get("content")
        if not endpoint:
            continue
        endpoint = endpoint.strip().lower()
        if tier_id == 5:
            # tier.id 5 = genuinely out of scope (distinct from tier.value
            # "No Bounty", which is still a testable, in-scope asset that
            # simply doesn't pay a bounty).
            out_domains.append(endpoint)
            continue
        if tier == "No Bounty":
            continue
        domains.append(endpoint)
    domain_count = len(domains)
    roe = data.get("rulesOfEngagement", {}).get("content", {})
    roe_text = json.dumps(roe)
    sh_override = True if roe.get("safeHarbour") is True else None
    ev = evaluate_policy_conditions(roe_text, name, MIN_RATE_LIMIT, safe_harbor_override=sh_override)
    if ev["hard_fail"]:
        results["excluded"].append((pid, f"{name}: " + " | ".join(ev["reasons"]), domain_count))
        return
    if ev["needs_review"]:
        results["skipped"].append((pid, f"{name}: " + " | ".join(ev["reasons"]), domain_count))
        return
    results["included"].append({
        "handle": pid,
        "safe_harbor": True,
        "rate_limit": ev["rate_limit"][0],
        "domains": domains,
        "out_domains": out_domains,
    })


def extract_ywh_domains(scope_entries, slug="unknown"):
    domains = []
    unmatched = []
    skip_types = ("mobile-application", "mobile-application-android", "mobile-application-ios")
    skip_hosts = ("apps.apple.com", "play.google.com", "itunes.apple.com")
    for entry in scope_entries:
        if entry.get("scope_type") in skip_types:
            continue
        s = entry.get("scope", "")
        if not s:
            continue
        s2 = re.sub(r"^https?://", "", s)
        if any(h in s2 for h in skip_hosts):
            continue
        if not re.search(r"[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", s2):
            unmatched.append(s)
            continue
        s2 = re.split(r"[/?]", s2)[0]
        m = re.match(r"^([a-zA-Z0-9_\-.*]+)\(([a-zA-Z0-9\-.|]+)\)([a-zA-Z0-9_\-.]*)$", s2)
        if m:
            prefix, group, suffix = m.groups()
            for opt in group.split("|"):
                domains.append(f"{prefix}{opt}{suffix}".lower())
            continue
        s3 = re.sub(r'[()"].*$', "", s2).strip()
        if re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\-.*]*\.[a-zA-Z]{2,}$", s3):
            domains.append(s3.lower())
        else:
            unmatched.append(s)
    if unmatched:
        with open("yeswehack_unmatched.log", "a") as f:
            for u in unmatched:
                f.write(f"{slug}\t{u}\n")
    return sorted(set(domains))


_YWH_OOS_DOMAIN_RE = re.compile(r"(?:\*\.)?\b[a-zA-Z0-9][a-zA-Z0-9*\-]*(?:\.[a-zA-Z0-9*][a-zA-Z0-9*\-]*){1,}\b")


def mistral_check_out_of_scope_negation(entry_text, domain, program_name):
    global _MISTRAL_CALLS_SINCE_SAVE
    if not entry_text:
        return None
    cache_key = hashlib.sha256(("oosneg:" + domain + ":" + entry_text[:8000]).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, entry_text[:200], cached.get("is_out"), cached["reason"] + " [CACHED]", error=None)
        return cached.get("is_out")
    if not MISTRAL_API_KEY:
        return "error"
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return "error"
    _mistral_pace()
    prompt = (
        "You are reviewing an out-of-scope policy statement from a bug "
        "bounty program. Answer ONLY with valid JSON, no other text, in "
        'this exact format: {"is_out_of_scope": true or false, "reason": "one short sentence"}.\n\n'
        f"Question: Based on this text, is the domain '{domain}' genuinely "
        "out of scope? Watch carefully for negation phrasing that reverses "
        "the meaning (e.g. 'Testing any system OTHER THAN X is prohibited' "
        f"means X IS in scope, not out of scope). Text:\n{entry_text[:2000]}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 300,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "User-Agent": "bug-bounty-hunter-vet/1.0",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"].strip().strip("`")
            if content.startswith("json"):
                content = content[4:].strip()
            im = re.search(r'"is_out_of_scope"\s*:\s*(true|false)', content, re.IGNORECASE)
            reasonm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', content, re.DOTALL)
            reason = reasonm.group(1) if reasonm else content[:150]
            if not im:
                log_mistral_call(program_name, entry_text[:200], None, reason, error=None)
                _MISTRAL_CACHE[cache_key] = {"is_out": None, "reason": reason}
                _MISTRAL_CALLS_SINCE_SAVE += 1
                if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                    save_mistral_cache(_MISTRAL_CACHE)
                    _MISTRAL_CALLS_SINCE_SAVE = 0
                return None
            is_out = im.group(1).lower() == "true"
            log_mistral_call(program_name, entry_text[:200], is_out, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"is_out": is_out, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return is_out
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    body = e.read().decode()
                except Exception:
                    body = "<could not read body>"
                retry_after = e.headers.get("Retry-After") if e.headers else None
                with open(os.path.join(OUTPUT_DIR, "mistral_429_debug.log"), "a") as df:
                    df.write(f"--- {program_name} ---\n")
                    df.write(f"retry_after: {retry_after}\n")
                    df.write(f"body: {body}\n\n")
                try:
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                wait = 5 * (attempt + 1)
                if e.code == 429:
                    try:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        if ra is not None:
                            wait = max(wait, min(int(float(ra)) + 1, 90))
                    except (TypeError, ValueError):
                        pass
                time.sleep(wait)
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, entry_text[:200], None, None, error=str(last_err))
    return "error"


def extract_ywh_out_of_scope_domains(out_of_scope_entries, slug="unknown"):
    # YesWeHack's out_of_scope field is free-text prose, not structured
    # scope entries like `scopes` - so regex extracts candidate domains,
    # then each candidate is confirmed against its source sentence via AI
    # to catch negation phrasing (e.g. "Testing any system OTHER THAN X"
    # means X is IN scope, not out). Fail-safe: on AI error/no-verdict,
    # keep the domain excluded - over-excluding is safe, under-excluding
    # is not.
    out_domains = []
    for entry in out_of_scope_entries or []:
        if not isinstance(entry, str):
            continue
        text = re.sub(r"https?://", "", entry)
        candidates = sorted(set(m.strip(".").lower() for m in _YWH_OOS_DOMAIN_RE.findall(text)))
        for domain in candidates:
            result = mistral_check_out_of_scope_negation(entry, domain, slug)
            if result is False:
                continue  # negation detected: domain is actually in-scope
            out_domains.append(domain)  # True, None, or "error" -> keep excluded (fail-safe)
    return sorted(set(out_domains))


def discover_yeswehack():
    programs = []
    page = 1
    nb_pages = 1
    while page <= nb_pages:
        data, err = fetch_json(
            f"https://api.yeswehack.com/programs?page={page}",
            {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if err:
            log(f"[YWH] page {page} fetch failed: {err}")
            page += 1
            continue
        programs.extend(data.get("items", []))
        nb_pages = data.get("pagination", {}).get("nb_pages", nb_pages)
        page += 1
        time.sleep(0.3)
    log(f"[YWH] discovered {len(programs)} total programs")
    return programs


def vet_yeswehack_program(program, results):
    slug = program["slug"]
    if program.get("status") != "V":
        results["excluded"].append((slug, f"not open (status={program.get('status')})", 0))
        return
    if program.get("public") is not True:
        results["excluded"].append((slug, "not public", 0))
        return
    if program.get("demo") is True:
        results["excluded"].append((slug, "demo program", 0))
        return
    if program.get("disabled") is True:
        results["excluded"].append((slug, "disabled program", 0))
        return
    if program.get("archived") is True:
        results["excluded"].append((slug, "archived program", 0))
        return
    data, err = fetch_json(
        f"https://api.yeswehack.com/programs/{slug}",
        {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    time.sleep(0.3)
    if err:
        results["skipped"].append((slug, err, 0))
        return
    domains = extract_ywh_domains(data.get("scopes", []), slug)
    out_domains = extract_ywh_out_of_scope_domains(data.get("out_of_scope", []), slug)
    if out_domains:
        domains = sorted(set(domains) - set(out_domains))
    domain_count = len(domains)
    rules = data.get("rules") or clean_html(data.get("rules_html", "")) or ""
    ev = evaluate_policy_conditions(rules, slug, MIN_RATE_LIMIT)
    if ev["hard_fail"]:
        results["excluded"].append((slug, " | ".join(ev["reasons"]), domain_count))
        return
    if ev["needs_review"]:
        results["skipped"].append((slug, " | ".join(ev["reasons"]), domain_count))
        return
    results["included"].append({
        "slug": slug,
        "bounty": program.get("bounty"),
        "safe_harbor": True,
        "rate_limit": ev["rate_limit"][0],
        "domains": domains,
        "out_domains": out_domains,
    })


def _hp_deref(raw, val, depth=0, maxdepth=8):
    if depth > maxdepth or not isinstance(val, int):
        return val
    v = raw[val]
    if isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and v[0] in ("ShallowReactive", "Reactive"):
        return _hp_deref(raw, v[1], depth + 1, maxdepth)
    if isinstance(v, dict):
        return {k: _hp_deref(raw, x, depth + 1, maxdepth) for k, x in v.items()}
    if isinstance(v, list):
        return [_hp_deref(raw, x, depth + 1, maxdepth) for x in v]
    return v


def fetch_hackenproof_program(slug):
    body, err = fetch_text(
        f"https://hackenproof.com/programs/{slug}",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
        timeout=20,
    )
    if err:
        return None, err
    m = re.search(r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>', body, re.DOTALL)
    if not m:
        return None, "NUXT_DATA not found"
    try:
        raw = json.loads(m.group(1))
    except Exception as e:
        return None, f"JSON parse error: {e}"
    try:
        root = raw[1]
        data_obj = _hp_deref(raw, root["data"], maxdepth=1)
        program = _hp_deref(raw, data_obj["program"], maxdepth=6)
    except Exception as e:
        return None, f"NUXT_DATA shape error: {e}"
    if not isinstance(program, dict) or "state" not in program:
        return None, "unexpected program shape"
    return program, None


def discover_hackenproof():
    body, err = fetch_text(
        "https://hackenproof.com/sitemap.xml",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
        timeout=20,
    )
    if err:
        log(f"[HackenProof] sitemap fetch failed: {err}")
        return []
    slugs = re.findall(r"<loc>https://hackenproof\.com/programs/([^<]+)</loc>", body)
    programs = [{"slug": s} for s in slugs]
    log(f"[HackenProof] discovered {len(programs)} total programs (via sitemap)")
    return programs


def vet_hackenproof_program(program, results):
    slug = program["slug"]
    data, err = fetch_hackenproof_program(slug)
    time.sleep(0.3)
    if err:
        results["skipped"].append((slug, f"fetch/parse error: {err}", 0))
        return
    if data.get("state") != "published":
        results["excluded"].append((slug, f"not open (state={data.get('state')})", 0))
        return
    activity_name = (data.get("activityStatus") or {}).get("name")
    if activity_name and activity_name != "Active":
        results["excluded"].append((slug, f"not active (status={activity_name})", 0))
        return
    if data.get("isAudit") is True:
        results["excluded"].append((slug, "audit program, not BBP", 0))
        return
    scopes = data.get("scopes", []) or []
    domains = sorted(set(
        d for s in scopes if not s.get("out_of_scope")
        for d in [extract_root_domain(s.get("target", ""))] if d
    ))
    out_domains = sorted(set(
        d for s in scopes if s.get("out_of_scope")
        for d in [extract_root_domain(s.get("target", ""))] if d
    ))
    if out_domains:
        domains = sorted(set(domains) - set(out_domains))
    domain_count = len(domains)
    id_verification_override = data.get("kycRequired")
    rules = " ".join(filter(None, [
        data.get("programRules", ""),
        data.get("focusArea", ""),
        data.get("eligibilityAndCoordinateDisclosure", ""),
        data.get("disclosureGuidelines", ""),
    ]))
    ev = evaluate_policy_conditions(rules, slug, MIN_RATE_LIMIT, id_verification_override=id_verification_override)
    if ev["hard_fail"]:
        results["excluded"].append((slug, " | ".join(ev["reasons"]), domain_count))
        return
    if ev["needs_review"]:
        results["skipped"].append((slug, " | ".join(ev["reasons"]), domain_count))
        return
    results["included"].append({
        "slug": slug,
        "bounty": True,
        "safe_harbor": True,
        "rate_limit": ev["rate_limit"][0],
        "domains": domains,
        "out_domains": out_domains,
    })


def discover_bugcrowd():
    programs = []
    page = 1
    total_pages = None
    while total_pages is None or page <= total_pages:
        data, err = fetch_json(
            f"https://bugcrowd.com/engagements?page={page}",
            {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if err:
            log(f"[Bugcrowd] page {page} fetch failed: {err}")
            page += 1
            if total_pages is None and page > 50:
                log("[Bugcrowd] giving up after 50 failed pages with no pagination info")
                break
            continue
        batch = data.get("engagements", [])
        if not batch:
            log(f"[Bugcrowd] page {page} empty, stopping")
            break
        programs.extend(batch)
        if total_pages is None:
            meta = data.get("paginationMeta") or {}
            limit = meta.get("limit")
            total_count = meta.get("totalCount")
            if limit and total_count is not None:
                total_pages = -(-total_count // limit)  # ceil division
                log(f"[Bugcrowd] paginationMeta: {total_count} total, {limit}/page -> {total_pages} pages")
            else:
                log("[Bugcrowd] no paginationMeta found, falling back to empty-page stop condition")
        page += 1
        time.sleep(0.3)
    log(f"[Bugcrowd] discovered {len(programs)} total programs")
    return programs


def vet_bugcrowd_program(program, results):
    slug = program["briefUrl"].rstrip("/").split("/")[-1]
    if program.get("isDemo"):
        results["excluded"].append((slug, "demo engagement", 0))
        return
    if program.get("isBanned"):
        results["excluded"].append((slug, "banned engagement", 0))
        return
    if program.get("isPrivate") is not False:
        results["excluded"].append((slug, "private/invite-only engagement", 0))
        return
    if program.get("accessStatus") != "open":
        results["excluded"].append((slug, f"not open (accessStatus={program.get('accessStatus')})", 0))
        return
    # BBP-only gate removed: VDP programs are also researched now, not just paid BBPs.
    cl_data, err = fetch_json(
        f"https://bugcrowd.com/engagements/{slug}/changelog.json",
        {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    time.sleep(0.3)
    if err:
        results["skipped"].append((slug, err, 0))
        return
    changelogs = cl_data.get("changelogs", [])
    if not changelogs:
        results["skipped"].append((slug, "no changelog entries", 0))
        return
    latest = next((c for c in changelogs if c.get("changelogState") == "Latest"), changelogs[0])
    full, err2 = fetch_json(
        f"https://bugcrowd.com/engagements/{slug}/changelog/{latest['id']}.json",
        {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    time.sleep(0.3)
    if err2:
        results["skipped"].append((slug, err2, 0))
        return
    brief = full.get("data", {}).get("brief", {})
    sh_status = (brief.get("safeHarborStatus") or {}).get("status")
    desc = clean_html(brief.get("description", ""))
    overview = clean_html(brief.get("targetsOverview", ""))
    additional = clean_html(brief.get("additionalInformation", ""))
    text = desc + overview + additional
    if sh_status == "full":
        sh_override = True
    else:
        sh_override = None  # unset (includes "partial" and missing) - fall through to text-based check below
    safe_harbor = True
    skip_categories = ("android", "ios", "ip_address", "network")
    domains = []
    out_domains = []
    for grp in full.get("data", {}).get("scope", []):
        target_domains = []
        for t in grp.get("targets", []):
            if t.get("category") in skip_categories:
                continue
            uri = t.get("uri")
            name = t.get("name", "") or ""
            if uri:
                target_domains.append(re.sub(r"^https?://", "", uri).split("/")[0].lower())
            elif re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\-.*]*\.[a-zA-Z]{2,}$", name.strip()):
                target_domains.append(name.strip().lower())
        if grp.get("inScope"):
            domains.extend(target_domains)
        else:
            out_domains.extend(target_domains)
    domain_count = len(set(domains))
    ev = evaluate_policy_conditions(text, slug, MIN_RATE_LIMIT, safe_harbor_override=sh_override)
    if ev["hard_fail"]:
        results["excluded"].append((slug, " | ".join(ev["reasons"]), domain_count))
        return
    if ev["needs_review"]:
        results["skipped"].append((slug, " | ".join(ev["reasons"]), domain_count))
        return
    rate = ev["rate_limit"][0]
    results["included"].append({
        "slug": slug,
        "safe_harbor": True,
        "rate_limit": rate,
        "domains": sorted(set(domains)),
        "out_domains": sorted(set(out_domains)),
    })


def new_results():
    return {"included": [], "excluded": [], "skipped": []}


def save_shard_results(results, platform, shard_idx, total_discovered):
    path = f"{platform}_shard_{shard_idx}_results.json"
    with open(path, "w") as f:
        json.dump({"results": results, "total_discovered": total_discovered}, f)
    log(f"[{platform} shard {shard_idx}] saved partial results to {path}")


def load_and_merge_shards(platform, num_shards):
    merged = new_results()
    total_discovered = 0
    for i in range(1, num_shards + 1):
        path = f"{platform}_shard_{i}_results.json"
        if not os.path.exists(path):
            log(f"[{platform} merge] WARNING: {path} missing, skipping (results incomplete!)")
            continue
        with open(path) as f:
            data = json.load(f)
        merged["included"].extend(data["results"]["included"])
        merged["excluded"].extend(data["results"]["excluded"])
        merged["skipped"].extend(data["results"]["skipped"])
        total_discovered += data["total_discovered"]
    return merged, total_discovered


def merge_scope_file(path, entries_by_program, max_removal_pct=50):
    new_domains = set()
    new_out_domains = set()
    for p in entries_by_program:
        new_domains.update(p.get("domains", []))
        new_out_domains.update(p.get("out_domains", []))
    old_domains = set()
    old_out_domains = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("IN:"):
                    old_domains.add(line[3:])
                elif line.startswith("OUT:"):
                    old_out_domains.add(line[4:])
    added = new_domains - old_domains
    removed = old_domains - new_domains
    removal_pct = (len(removed) / len(old_domains) * 100) if old_domains else 0
    force_apply = os.environ.get("SCOPE_GUARD_OVERRIDE") == "true"
    removal_guard_triggered = removal_pct > max_removal_pct and not force_apply
    if removal_guard_triggered:
        log(f"  [GUARD] {path}: would remove {len(removed)}/{len(old_domains)} "
            f"({removal_pct:.1f}%) - exceeds {max_removal_pct}% threshold. "
            f"Keeping previous IN: entries, applying additions only.")
        log(f"  [GUARD] Would-be removed: {len(removed)} (skipped this run). Adding: {len(added)}.")
        new_domains = old_domains | added
        removed = set()
    if (len(new_domains) < MIN_ABSOLUTE_DOMAINS_PER_PLATFORM
            and len(old_domains) >= MIN_ABSOLUTE_DOMAINS_PER_PLATFORM
            and not force_apply):
        log(f"  [GUARD] {path}: new result has only {len(new_domains)} domain(s), below the absolute floor of {MIN_ABSOLUTE_DOMAINS_PER_PLATFORM}. NOT applying.")
        return {"applied": False, "added": len(added), "removed": len(removed), "total": len(old_domains)}

    out_added = new_out_domains - old_out_domains
    out_removed = old_out_domains - new_out_domains
    out_removal_pct = (len(out_removed) / len(old_out_domains) * 100) if old_out_domains else 0
    out_guard_triggered = out_removal_pct > max_removal_pct and not force_apply
    if out_guard_triggered:
        log(f"  [GUARD] {path} OUT-scope: would remove {len(out_removed)}/{len(old_out_domains)} "
            f"({out_removal_pct:.1f}%) - exceeds {max_removal_pct}% threshold. "
            f"Keeping previous OUT: entries untouched this run.")
        new_out_domains = old_out_domains

    if os.path.exists(path):
        backup_path = f"{path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(path, backup_path)
        log(f"  [BACKUP] {path} -> {backup_path}")
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        for d in sorted(new_domains):
            f.write(f"IN:{d}\n")
        for d in sorted(new_out_domains):
            f.write(f"OUT:{d}\n")
    os.replace(tmp_path, path)
    if added or removed or out_added or out_removed:
        diff_path = path.replace(".txt", "_diff.log")
        with open(diff_path, "a") as f:
            f.write(f"\n=== {datetime.now().isoformat()} ===\n")
            for d in sorted(added):
                f.write(f"+ IN:{d}\n")
            for d in sorted(removed):
                f.write(f"- IN:{d}\n")
            for d in sorted(out_added if not out_guard_triggered else []):
                f.write(f"+ OUT:{d}\n")
            for d in sorted(out_removed if not out_guard_triggered else []):
                f.write(f"- OUT:{d}\n")
        log(f"  [DIFF] logged to {diff_path}")
    log(f"  [APPLIED] {path}: {len(new_domains)} IN ({len(added)} added, {len(removed)} removed), "
        f"{len(new_out_domains)} OUT ({len(out_added) if not out_guard_triggered else 0} added, "
        f"{len(out_removed) if not out_guard_triggered else 0} removed)")
    return {"applied": True, "added": len(added), "removed": len(removed), "total": len(new_domains),
            "out_total": len(new_out_domains)}
def summarize(platform, results, total_discovered, write_files=True):
    log(f"\n=== {platform} summary ===")
    log(f"  total discovered from platform: {total_discovered}")
    log(f"  included: {len(results['included'])}")
    log(f"  excluded (failed a condition): {len(results['excluded'])}")
    log(f"  skipped (fetch/parse error): {len(results['skipped'])}")

    excluded_path = f"{platform.lower()}_excluded_full.txt"
    skipped_path = f"{platform.lower()}_skipped_full.txt"
    if write_files:
        excluded_tmp = f"{excluded_path}.tmp"
        with open(excluded_tmp, "w") as ef:
            for name, reason, domain_count in results["excluded"]:
                ef.write(f"{name}\t{reason}\t{domain_count}\n")
        os.replace(excluded_tmp, excluded_path)
        skipped_tmp = f"{skipped_path}.tmp"
        with open(skipped_tmp, "w") as sf:
            for name, reason, domain_count in results["skipped"]:
                sf.write(f"{name}\t{reason}\t{domain_count}\n")
        os.replace(skipped_tmp, skipped_path)
    else:
        log(f"  [SKIP] not writing {excluded_path} / {skipped_path} (platform not run)")
    n_excluded = len(results["excluded"])
    n_skipped = len(results["skipped"])
    log(f"  [FULL LIST] excluded -> {excluded_path} ({n_excluded} rows)")
    log(f"  [FULL LIST] skipped -> {skipped_path} ({n_skipped} rows)")

    if results["excluded"]:
        log("  exclusion reasons (first 10):")
        for name, reason, domain_count in results["excluded"][:10]:
            log(f"    - {name}: {reason} (domains: {domain_count})")
    if results["skipped"]:
        log("  skip reasons (first 10):")
        for name, reason, domain_count in results["skipped"][:10]:
            log(f"    - {name}: {reason} (domains: {domain_count})")

    if write_files:
        stats_path = os.path.join(OUTPUT_DIR, "discovery_stats.csv")
        is_new = not os.path.exists(stats_path)
        with open(stats_path, "a", newline="") as sf:
            w = csv.writer(sf)
            if is_new:
                w.writerow(["timestamp_utc", "platform", "total_discovered", "included", "excluded", "skipped", "excluded_domains", "skipped_domains", "run_id"])
            excluded_domains = sum(d for _, _, d in results["excluded"])
            skipped_domains = sum(d for _, _, d in results["skipped"])
            w.writerow([
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                platform,
                total_discovered,
                len(results["included"]),
                n_excluded,
                n_skipped,
                excluded_domains,
                skipped_domains,
                os.environ.get("GITHUB_RUN_ID", "local"),
            ])
        log(f"  [STATS] appended to {stats_path}")
    else:
        log(f"  [SKIP] not appending to discovery_stats.csv (platform not run)")


def update_domain_program_map(h1_results, int_results, ywh_results, bc_results, hp_results, ran_platforms, max_removal_pct=50):
    """Rebuild domain_program_map.csv rows for every platform that actually ran this
    invocation (dropping stale/removed programs for those platforms), while leaving
    rows for skipped platforms (e.g. a manual --platform test run, or no token set)
    completely untouched. Same 15% removal guard + backup as merge_scope_file /
    rebuild_domains_txt: a platform that "ran" but came back with degraded/near-empty
    data (bad auth, API change) has its rows left untouched instead of being wiped,
    since this CSV feeds filter_scope.py downstream in Weekend Recon."""
    existing_rows = []
    if os.path.exists(MAPPING_PATH):
        with open(MAPPING_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_rows.append((row["domain"], row["platform"], row["keyword"]))

    fresh_rows = []
    seen = set()
    platform_sources = [
        ("hackerone", h1_results, "handle"),
        ("intigriti", int_results, "handle"),
        ("yeswehack", ywh_results, "slug"),
        ("bugcrowd", bc_results, "slug"),
        ("hackenproof", hp_results, "slug"),
    ]
    for platform_name, results, key_field in platform_sources:
        if platform_name not in ran_platforms:
            continue
        for entry in results.get("included", []):
            keyword = entry.get(key_field)
            if not keyword:
                continue
            for domain in entry.get("domains", []):
                row = (domain, platform_name, keyword)
                if row not in seen:
                    fresh_rows.append(row)
                    seen.add(row)

    force_apply = os.environ.get("SCOPE_GUARD_OVERRIDE") == "true"
    guarded_platforms = set()
    for platform_name in ran_platforms:
        old_count = sum(1 for row in existing_rows if row[1] == platform_name)
        new_count = sum(1 for row in fresh_rows if row[1] == platform_name)
        removal_pct = ((old_count - new_count) / old_count * 100) if old_count else 0
        if removal_pct > max_removal_pct and not force_apply:
            log(f"  [GUARD] domain_program_map.csv/{platform_name}: would go from {old_count} "
                f"to {new_count} rows ({removal_pct:.1f}% drop) - exceeds {max_removal_pct}% "
                f"threshold. NOT applying for {platform_name}. Old rows left untouched.")
            guarded_platforms.add(platform_name)

    kept_rows = [row for row in existing_rows
                 if row[1] not in ran_platforms or row[1] in guarded_platforms]
    fresh_rows = [row for row in fresh_rows if row[1] not in guarded_platforms]

    all_rows = kept_rows + fresh_rows

    if os.path.exists(MAPPING_PATH):
        backup_path = f"{MAPPING_PATH}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(MAPPING_PATH, backup_path)
        log(f"  [BACKUP] {MAPPING_PATH} -> {backup_path}")

    with open(MAPPING_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "platform", "keyword"])
        for row in all_rows:
            writer.writerow(row)
    applied_platforms = sorted(set(ran_platforms) - guarded_platforms)
    log(f"[CSV] domain_program_map.csv: rebuilt {len(fresh_rows)} rows for "
        f"{applied_platforms}, kept {len(kept_rows)} rows untouched for skipped/guarded platforms")

    write_excluded_domains_file(EXCLUDED_OUTPUT_PATH, existing_rows, platform_sources, set(applied_platforms))

def write_excluded_domains_file(path, existing_rows, platform_sources, ran_platforms):
    """Write every domain whose program was excluded/skipped this run
    (for platforms that actually ran) to a persisted file, so downstream
    workflows (recon/scan) can trust this instead of re-vetting.
    Domains belonging only to platforms that did NOT run this invocation
    are carried forward from the old file untouched (mirrors the 'kept'
    logic in update_domain_program_map)."""
    old_excluded = set()
    if os.path.exists(path):
        with open(path) as f:
            old_excluded = {line.strip() for line in f if line.strip()}
    domains_on_ran_platforms = {domain for domain, platform, keyword in existing_rows if platform in ran_platforms}
    kept_excluded = old_excluded - domains_on_ran_platforms

    included_keywords = {}
    for platform_name, results, key_field in platform_sources:
        if platform_name not in ran_platforms:
            continue
        included_keywords[platform_name] = {
            entry.get(key_field) for entry in results.get("included", []) if entry.get(key_field)
        }

    fresh_excluded = set()
    for domain, platform, keyword in existing_rows:
        if platform not in ran_platforms:
            continue
        if keyword not in included_keywords.get(platform, set()):
            fresh_excluded.add(domain)

    excluded_domains = kept_excluded | fresh_excluded
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        for d in sorted(excluded_domains):
            f.write(f"{d}\n")
    os.replace(tmp_path, path)
    log(f"[EXCLUDED] {path}: {len(excluded_domains)} domain(s) excluded total "
        f"({len(fresh_excluded)} from this run's platforms, {len(kept_excluded)} kept from skipped platforms)")
    return len(excluded_domains)


def extract_root_domain(asset):
    """Extract the registrable root domain from a scope asset (URL, wildcard,
    or bare host). Returns None if it can't be parsed as a domain."""
    asset = asset.strip()
    if not asset:
        return None
    asset = asset.lstrip("*.").replace("https://", "").replace("http://", "")
    asset = asset.split("/")[0].split(":")[0].lower()
    if "[" in asset and "]" in asset:
        asset = re.sub(r"\[.*?\]", "", asset)
    if "*" in asset:
        # The clean subdomain-wildcard case ("*.example.com") was already
        # handled by the lstrip above. If "*" is still present here, check
        # WHERE it landed: a wildcard deeper in the subdomain (e.g.
        # "api*.hubapi.com", "a.*.b.example.com") still has an unambiguous
        # root domain. A wildcard inside the actual registrable domain or
        # suffix label (e.g. "paypal-*.com") has no single correct root to
        # recover — guessing would fabricate a domain never actually
        # declared in scope, so bail on that case only.
        placeholder = "wildcardplaceholder"
        probe = asset.replace("*", placeholder)
        ext_probe = tldextract.extract(probe)
        if placeholder in ext_probe.domain or placeholder in ext_probe.suffix:
            return None
        asset = asset.replace("*", "")
    ext = tldextract.extract(asset)
    if not ext.domain or not ext.suffix:
        return None
    # tldextract doesn't validate that a label is a legal hostname
    # component (no leading/trailing hyphen, no double hyphen at the
    # edges). Reject anything that isn't, rather than returning a
    # domain that was never actually valid.
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", ext.domain):
        return None
    return f"{ext.domain}.{ext.suffix}"


def rebuild_domains_txt(scope_paths, max_removal_pct=50):
    """Fresh rebuild: domains.txt = root domains derived from the union of the
    4 committed scope files (already individually guarded). Never built from a
    single run's ran_platforms results, so a manual --platform run can't wipe
    out the other platforms' domains. Same 20% removal guard + backup as
    merge_scope_file."""
    new_roots = set()
    for path in scope_paths:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("IN:"):
                    root = extract_root_domain(line[3:])
                    if root:
                        new_roots.add(root)

    old_roots = set()
    if os.path.exists(DOMAINS_TXT_PATH):
        with open(DOMAINS_TXT_PATH) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    old_roots.add(line)

    added = new_roots - old_roots
    removed = old_roots - new_roots
    removal_pct = (len(removed) / len(old_roots) * 100) if old_roots else 0
    force_apply = os.environ.get("SCOPE_GUARD_OVERRIDE") == "true"
    removal_guard_triggered = removal_pct > max_removal_pct and not force_apply
    if removal_guard_triggered:
        log(f"[GUARD] {DOMAINS_TXT_PATH}: would remove {len(removed)}/{len(old_roots)} "
            f"({removal_pct:.1f}%) - exceeds {max_removal_pct}% threshold. "
            f"Keeping previous entries, applying additions only.")
        log(f"[GUARD] Would-be removed: {len(removed)} (skipped this run). Adding: {len(added)}.")
        new_roots = old_roots | added
        removed = set()
    if (len(new_roots) < MIN_ABSOLUTE_DOMAINS_TOTAL
            and len(old_roots) >= MIN_ABSOLUTE_DOMAINS_TOTAL
            and not force_apply):
        log(f"[GUARD] {DOMAINS_TXT_PATH}: new result has only {len(new_roots)} domain(s) total, below the absolute floor of {MIN_ABSOLUTE_DOMAINS_TOTAL}. NOT applying.")
        return {"applied": False, "added": len(added), "removed": len(removed), "total": len(old_roots)}

    if os.path.exists(DOMAINS_TXT_PATH):
        backup_path = f"{DOMAINS_TXT_PATH}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(DOMAINS_TXT_PATH, backup_path)
        log(f"[BACKUP] {DOMAINS_TXT_PATH} -> {backup_path}")

    domains_tmp_path = f"{DOMAINS_TXT_PATH}.tmp"
    with open(domains_tmp_path, "w") as f:
        for d in sorted(new_roots):
            f.write(f"{d}\n")
    os.replace(domains_tmp_path, DOMAINS_TXT_PATH)

    if added or removed:
        diff_path = DOMAINS_TXT_PATH.replace(".txt", "_diff.log")
        with open(diff_path, "a") as f:
            f.write(f"\n=== {datetime.now().isoformat()} ===\n")
            for d in sorted(added):
                f.write(f"+ {d}\n")
            for d in sorted(removed):
                f.write(f"- {d}\n")
        log(f"[DIFF] logged to {diff_path}")

    log(f"[APPLIED] {DOMAINS_TXT_PATH}: {len(new_roots)} total ({len(added)} added, {len(removed)} removed)")
    return {"applied": True, "added": len(added), "removed": len(removed), "total": len(new_roots)}

_DOMAIN_LINE_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")


def validate_final_output():
    problems = []
    if not os.path.exists(DOMAINS_TXT_PATH):
        problems.append(f"{DOMAINS_TXT_PATH} does not exist")
        return problems
    with open(DOMAINS_TXT_PATH) as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    if len(lines) < MIN_ABSOLUTE_DOMAINS_TOTAL:
        problems.append(f"domains.txt has only {len(lines)} domain(s), below the absolute floor of {MIN_ABSOLUTE_DOMAINS_TOTAL}")
    malformed = [d for d in lines if not _DOMAIN_LINE_RE.match(d)]
    if malformed:
        problems.append(f"{len(malformed)} malformed line(s) in domains.txt, e.g. {malformed[:5]}")
    dupes = len(lines) - len(set(lines))
    if dupes:
        problems.append(f"{dupes} duplicate line(s) in domains.txt")
    if os.path.exists(MAPPING_PATH):
        with open(MAPPING_PATH, newline="") as f:
            reader = csv.DictReader(f)
            csv_domains = {row["domain"] for row in reader if row.get("domain")}
        if lines and not csv_domains:
            problems.append("domain_program_map.csv is empty but domains.txt is not")
    else:
        problems.append(f"{MAPPING_PATH} does not exist")
    return problems


def run_vet_pass(programs, vet_fn, results, key_fn, platform_name, max_wait=3900):
    """Run vet_fn over all programs, then retry once any program that was
    skipped specifically due to a Mistral API failure — since that's
    usually quota exhaustion, wait for the actual quota reset time
    (_MISTRAL_QUOTA_EXHAUSTED_UNTIL) rather than a fixed short cooldown,
    capped at max_wait seconds so a single bad quota reading can't hang
    the job indefinitely."""
    for p in programs:
        vet_fn(p)
    retry = [p for p in programs
             if any(key_fn(p) == s[0] and "Mistral call failed" in s[1] for s in results["skipped"])]
    if retry:
        remaining = _MISTRAL_QUOTA_EXHAUSTED_UNTIL - time.time()
        if remaining > max_wait:
            log(f"[{platform_name}] {len(retry)} program(s) skipped — Mistral quota resets in {int(remaining)}s, not retrying this run")
            return
        wait = remaining if remaining > 0 else 90  # no known quota deadline -> short retry is fine
        log(f"[{platform_name}] {len(retry)} program(s) skipped due to Mistral failure — retrying once after {int(wait)}s cooldown")
        time.sleep(wait)
        for p in retry:
            results["skipped"] = [s for s in results["skipped"] if s[0] != key_fn(p)]
            vet_fn(p)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=["hackerone", "intigriti", "yeswehack", "bugcrowd", "hackenproof"], default=None,
                         help="Run only one platform instead of all five")
    parser.add_argument("--shard", default=None,
                         help="HackerOne only: vet a slice of programs, format 'N/M' (1-indexed), e.g. '1/4'. "
                              "Writes partial results to hackerone_shard_N_results.json and exits - "
                              "no scope/domain/git output. Use --merge-shards afterward to combine.")
    parser.add_argument("--merge-shards", type=int, default=None,
                         help="HackerOne only: merge this many previously-saved shard result files "
                              "and proceed with the normal scope/domain/git output.")
    args = parser.parse_args()

    if args.shard and args.platform not in ("hackerone", "hackenproof"):
        log("ERROR: --shard is only supported for --platform hackerone or hackenproof")
        sys.exit(2)
    if args.merge_shards and args.platform not in ("hackerone", "hackenproof"):
        log("ERROR: --merge-shards is only supported for --platform hackerone or hackenproof")
        sys.exit(2)

    h1_token = os.environ.get("HACKERONE_TOKEN")
    int_token = os.environ.get("INTIGRITI_TOKEN")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # HackerOne shard mode: vet a slice, save partial results, exit early.
    # No scope/domain/CSV/git writes here - shards run in parallel and would
    # race on those files. Only the merge job below touches them.
    if args.shard:
        shard_idx, num_shards = (int(x) for x in args.shard.split("/"))
        if not (1 <= shard_idx <= num_shards):
            log(f"[{args.platform} shard] ERROR: invalid --shard {args.shard}")
            sys.exit(2)
        shard_results = new_results()
        if args.platform == "hackerone":
            if not h1_token:
                log("[H1 shard] ERROR: no HACKERONE_TOKEN set")
                sys.exit(1)
            programs, auth = discover_hackerone(h1_token)
            total = len(programs)
            per_shard = -(-total // num_shards)  # ceil
            start = (shard_idx - 1) * per_shard
            end = min(start + per_shard, total)
            my_programs = programs[start:end]
            log(f"[H1 shard {shard_idx}/{num_shards}] {len(my_programs)} of {total} programs (index {start}:{end})")
            run_vet_pass(my_programs, lambda p: vet_hackerone_program(p["handle"], auth, shard_results),
                         shard_results, lambda p: p["handle"], f"H1-shard{shard_idx}")
            save_shard_results(shard_results, "hackerone", shard_idx, len(my_programs))
        elif args.platform == "hackenproof":
            hp_auth_check = os.environ.get("HACKENPROOF_AUTH")
            if not hp_auth_check:
                log("[HackenProof shard] ERROR: no HACKENPROOF_AUTH set")
                sys.exit(1)
            programs = discover_hackenproof()
            total = len(programs)
            per_shard = -(-total // num_shards)  # ceil
            start = (shard_idx - 1) * per_shard
            end = min(start + per_shard, total)
            my_programs = programs[start:end]
            log(f"[HackenProof shard {shard_idx}/{num_shards}] {len(my_programs)} of {total} programs (index {start}:{end})")
            run_vet_pass(my_programs, lambda p: vet_hackenproof_program(p, shard_results),
                         shard_results, lambda p: p["slug"], f"HP-shard{shard_idx}")
            save_shard_results(shard_results, "hackenproof", shard_idx, len(my_programs))
        save_mistral_cache(_MISTRAL_CACHE)
        log(f"[{args.platform} shard {shard_idx}/{num_shards}] done: {len(shard_results['included'])} included, "
            f"{len(shard_results['excluded'])} excluded, {len(shard_results['skipped'])} skipped")
        return

    ran_platforms = set()
    applied_platforms = set()
    h1_results = new_results()
    if args.merge_shards and args.platform == "hackerone":
        ran_platforms.add("hackerone")
        h1_results, total_discovered = load_and_merge_shards("hackerone", args.merge_shards)
        summarize("HackerOne", h1_results, total_discovered)
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "hackerone_scope.txt"), h1_results["included"])
        log(f"[H1 merge] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("hackerone")
    elif args.platform in (None, "hackerone") and h1_token:
        ran_platforms.add("hackerone")
        programs, auth = discover_hackerone(h1_token)
        run_vet_pass(programs, lambda p: vet_hackerone_program(p["handle"], auth, h1_results),
                     h1_results, lambda p: p["handle"], "H1")
        summarize("HackerOne", h1_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "hackerone_scope.txt"), h1_results["included"])
        log(f"[H1] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("hackerone")
    else:
        if args.platform not in (None, "hackerone"):
            log("[H1] skipped due to --platform filter")
        else:
            log("[H1] no HACKERONE_TOKEN set, skipping platform")
            summarize("HackerOne", h1_results, 0, write_files=False)

    int_results = new_results()
    if args.platform in (None, "intigriti") and int_token:
        ran_platforms.add("intigriti")
        programs = discover_intigriti(int_token)
        run_vet_pass(programs, lambda p: vet_intigriti_program(p, int_token, int_results),
                     int_results, lambda p: p.get("name", p["id"]), "Intigriti")
        summarize("Intigriti", int_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "intigriti_scope.txt"), int_results["included"])
        log(f"[Intigriti] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("intigriti")
    else:
        if args.platform not in (None, "intigriti"):
            log("[Intigriti] skipped due to --platform filter")
        else:
            log("[Intigriti] no INTIGRITI_TOKEN set, skipping platform")
            summarize("Intigriti", int_results, 0, write_files=False)

    ywh_results = new_results()
    if args.platform in (None, "yeswehack"):
        ran_platforms.add("yeswehack")
        programs = discover_yeswehack()
        run_vet_pass(programs, lambda p: vet_yeswehack_program(p, ywh_results),
                     ywh_results, lambda p: p["slug"], "YWH")
        summarize("YesWeHack", ywh_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "yeswehack_scope.txt"), ywh_results["included"])
        log(f"[YWH] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("yeswehack")

    bc_results = new_results()
    if args.platform in (None, "bugcrowd"):
        ran_platforms.add("bugcrowd")
        programs = discover_bugcrowd()
        run_vet_pass(programs, lambda p: vet_bugcrowd_program(p, bc_results),
                     bc_results, lambda p: p["briefUrl"].rstrip("/").split("/")[-1], "Bugcrowd")
        summarize("Bugcrowd", bc_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "bugcrowd_scope.txt"), bc_results["included"])
        log(f"[Bugcrowd] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("bugcrowd")
    hp_auth = os.environ.get("HACKENPROOF_AUTH")
    hp_results = new_results()
    if args.merge_shards and args.platform == "hackenproof":
        ran_platforms.add("hackenproof")
        hp_results, total_discovered = load_and_merge_shards("hackenproof", args.merge_shards)
        summarize("HackenProof", hp_results, total_discovered)
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "hackenproof_scope.txt"), hp_results["included"])
        log(f"[HackenProof merge] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("hackenproof")
    elif args.platform in (None, "hackenproof") and hp_auth:
        ran_platforms.add("hackenproof")
        programs = discover_hackenproof()
        run_vet_pass(programs, lambda p: vet_hackenproof_program(p, hp_results),
                     hp_results, lambda p: p["slug"], "HackenProof")
        summarize("HackenProof", hp_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "hackenproof_scope.txt"), hp_results["included"])
        log(f"[HackenProof] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("hackenproof")
    else:
        if args.platform not in (None, "hackenproof"):
            log("[HackenProof] skipped due to --platform filter")
        else:
            log("[HackenProof] no HACKENPROOF_AUTH set, skipping platform")
            summarize("HackenProof", hp_results, 0, write_files=False)

    update_domain_program_map(h1_results, int_results, ywh_results, bc_results, hp_results, applied_platforms)
    scope_paths = [os.path.join(OUTPUT_DIR, f"{p}_scope.txt")
                   for p in ("hackerone", "intigriti", "yeswehack", "bugcrowd", "hackenproof")]
    r = rebuild_domains_txt(scope_paths)
    log(f"[domains.txt] rebuild result: {r}")

    save_mistral_cache(_MISTRAL_CACHE)
    log(f"[MISTRAL CACHE] saved {len(_MISTRAL_CACHE)} cached decisions to {MISTRAL_CACHE_PATH}")

    log("\n=== All platforms complete ===")

    problems = validate_final_output()
    if problems:
        log("\n=== FINAL OUTPUT VALIDATION FAILED ===")
        for p in problems:
            log(f"  [PROBLEM] {p}")
        log("Failing the job so this doesn't silently reach Recon.")
        sys.exit(1)
    log("[VALIDATION] domains.txt and domain_program_map.csv look sane")

# ==========================================================================
# Mistral second-layer automation-ban detection
# ==========================================================================

MISTRAL_URL = "https://api.mistral.ai/v1/chat/completions"
MISTRAL_LOG_PATH = os.path.join(OUTPUT_DIR, "mistral_review_log.txt")
MISTRAL_CACHE_PATH = os.path.join(OUTPUT_DIR, "mistral_ban_cache.json")

def load_mistral_cache():
    if os.path.exists(MISTRAL_CACHE_PATH):
        try:
            with open(MISTRAL_CACHE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def save_mistral_cache(cache):
    tmp_path = f"{MISTRAL_CACHE_PATH}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(cache, f, indent=2, sort_keys=True)
    os.replace(tmp_path, MISTRAL_CACHE_PATH)

_MISTRAL_CACHE = load_mistral_cache()
_MISTRAL_QUOTA_EXHAUSTED_UNTIL = 0
_MISTRAL_CALLS_SINCE_SAVE = 0
_MISTRAL_LAST_CALL_TS = [0.0]
MISTRAL_MIN_INTERVAL_S = 16  # stay under 4 req/min free-tier cap with margin

def _mistral_pace():
    elapsed = time.time() - _MISTRAL_LAST_CALL_TS[0]
    if elapsed < MISTRAL_MIN_INTERVAL_S:
        time.sleep(MISTRAL_MIN_INTERVAL_S - elapsed)
    _MISTRAL_LAST_CALL_TS[0] = time.time()

def mistral_check_ban(snippet, program_name):
    cache_key = hashlib.sha256(("autoban:v2:" + snippet).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, snippet, cached["is_ban"], cached["reason"] + " [CACHED]", error=None)
        return cached["is_ban"]
    if not MISTRAL_API_KEY:
        return None
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL, _MISTRAL_CALLS_SINCE_SAVE
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return None
    _mistral_pace()
    prompt = (
        "You are reviewing a single snippet from a bug bounty program's "
        "policy text. Answer ONLY with valid JSON, no other text, in this "
        'exact format: {"is_ban": true or false, "reason": "one short sentence"}.\n\n'
        "Question: Does this snippet ban the ACT of using automated "
        "scanners/tools against their systems?\n\n"
        "THE KEY TEST - identify the subject of the restriction:\n"
        "- If the subject is YOU / THE TESTER / THE ACTION ('do not use', "
        "'avoid scanning', 'don't automate testing', 'no automated attacks "
        "against our systems') -> this restricts the ACT of scanning -> true.\n"
        "- If the subject is the REPORT / SUBMISSION / RESULT / OUTPUT "
        "('reports will be rejected', 'submissions from automated tools "
        "won't be accepted', 'results without manual confirmation', "
        "'do not submit unverified output', 'scanner-generated reports', "
        "'must be validated manually before submission') -> this restricts "
        "what you may SUBMIT, not what tools you may run -> false. These "
        "are report-quality/triage rules, not scanning bans, even when the "
        "word 'automated' or the phrase 'manually' appears.\n\n"
        "A simple check: could you legally run the scanner and just "
        "manually verify/write up the finding yourself before submitting? "
        "If yes, the snippet is NOT a ban (false) - it only gates what "
        "gets submitted, not what tooling is allowed.\n\n"
        "Examples:\n"
        "BAN (true): 'Do not use automated scanners against our applications.'\n"
        "BAN (true): 'Don't brute-force or automate testing, challenges are "
        "made for manual solving.'\n"
        "BAN (true): 'Avoid automated scanning, DAST, fuzzing.'\n"
        "NOT A BAN (false): 'Reports generated purely by automated tools "
        "without manual verification will be closed.'\n"
        "NOT A BAN (false): 'Reports from automated tools or scans without "
        "a working Proof of Concept.'\n"
        "NOT A BAN (false): 'All reports must be validated manually, "
        "submission from automated tools wont be accepted.' (the ban targets "
        "the submission, not the act of scanning)\n"
        "NOT A BAN (false): 'Any report generated by automatic tool without "
        "a POC.' (short form of a submission/report-quality rule, not a "
        "tool-use ban)\n\n"
        "NOT A BAN (false): '## DoS Testing Policy ... No automated tools or "
        "high-volume attacks' - even though this says 'no automated tools,' "
        "it appears under a DoS Testing Policy heading, so it restricts DoS-style "
        "automation as part of the DoS sub-policy, not general scanning. A section "
        "header naming a specific narrow context (DoS, CSRF, account creation) scopes "
        "everything under it to that context only - it does not become a blanket ban.\n\n"
        "Also answer false if the mention of automation is in an unrelated "
        "context (e.g. CSRF, DoS-only sub-policies, or automated account "
        "creation) rather than about testing/scanning tools.\n\n"
        f"Snippet:\n{snippet}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 1200,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "User-Agent": "bug-bounty-hunter-vet/1.0",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            finish_reason = data["choices"][0].get("finish_reason")
            if finish_reason and finish_reason != "stop":
                with open(os.path.join(OUTPUT_DIR, "mistral_parse_fail_debug.log"), "a") as pf:
                    pf.write(f"--- {program_name} ---\n")
                    pf.write(f"finish_reason: {finish_reason}\n")
                    pf.write(f"RAW: {json.dumps(data)}\n\n")
            text = data["choices"][0]["message"]["content"].strip()
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
            m = re.search(r'"is_ban"\s*:\s*(true|false)', text, re.IGNORECASE)
            if not m:
                with open(os.path.join(OUTPUT_DIR, "mistral_parse_fail_debug.log"), "a") as pf:
                    pf.write(f"--- {program_name} ---\n")
                    pf.write(f"FULL RESPONSE: {text!r}\n\n")
                raise ValueError(f"could not find is_ban in response: {text[:150]}")
            is_ban = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text, re.DOTALL)
            reason = rm.group(1) if rm else text[:150]
            log_mistral_call(program_name, snippet, is_ban, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"is_ban": is_ban, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return is_ban
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    body = e.read().decode()
                except Exception:
                    body = "<could not read body>"
                retry_after = e.headers.get("Retry-After") if e.headers else None
                with open(os.path.join(OUTPUT_DIR, "mistral_429_debug.log"), "a") as df:
                    df.write(f"--- {program_name} ---\n")
                    df.write(f"retry_after: {retry_after}\n")
                    df.write(f"body: {body}\n\n")
                try:
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                wait = 5 * (attempt + 1)
                if e.code == 429:
                    try:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        if ra is not None:
                            wait = max(wait, min(int(float(ra)) + 1, 90))
                    except (TypeError, ValueError):
                        pass
                time.sleep(wait)
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, snippet, None, None, error=str(last_err))
    return None
def mistral_check_automation_allowed(snippet, program_name):
    cache_key = hashlib.sha256(("autoallow:v1:" + snippet).encode()).hexdigest()
    if cache_key in _MISTRAL_CACHE:
        cached = _MISTRAL_CACHE[cache_key]
        log_mistral_call(program_name, snippet, cached["is_allowed"], cached["reason"] + " [CACHED]", error=None)
        return cached["is_allowed"]
    if not MISTRAL_API_KEY:
        return None
    global _MISTRAL_QUOTA_EXHAUSTED_UNTIL, _MISTRAL_CALLS_SINCE_SAVE
    if time.time() < _MISTRAL_QUOTA_EXHAUSTED_UNTIL:
        return None
    _mistral_pace()
    prompt = (
        "You are reviewing a single snippet from a bug bounty program's "
        "policy text. Answer ONLY with valid JSON, no other text, in this "
        'exact format: {"is_allowed": true or false, "reason": "one short sentence"}.\n\n'
        "Question: Does this snippet EXPLICITLY grant permission for the ACT "
        "of using automated scanners/tools against their systems?\n\n"
        "THE KEY TEST: this must be a clear, affirmative grant of permission "
        "to run automated scanning tools - not merely the absence of a ban, "
        "not a mention of automation in an unrelated context, and not a "
        "rule about what may be SUBMITTED (report/output rules do not "
        "grant or restrict tool use, they gate submissions).\n\n"
        "Examples:\n"
        "ALLOWED (true): 'Automated scanning is permitted on all in-scope assets.'\n"
        "ALLOWED (true): 'You may use automated tools as long as you respect rate limits.'\n"
        "ALLOWED (true): 'We allow both manual and automated testing.'\n"
        "NOT ALLOWED (false): 'Reports from automated tools without a working "
        "PoC will be closed.' (a submission rule, not a grant of scanning "
        "permission)\n"
        "NOT ALLOWED (false): 'Please respect our rate limits.' (says nothing "
        "about whether automation itself is permitted)\n"
        "NOT ALLOWED (false): silence / no mention of automated tooling at all.\n\n"
        f"Snippet:\n{snippet}"
    )
    body = json.dumps({
        "model": "mistral-small-latest",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        MISTRAL_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "User-Agent": "bug-bounty-hunter-vet/1.0",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode())
            text = data["choices"][0]["message"]["content"].strip()
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
            m = re.search(r'"is_allowed"\s*:\s*(true|false)', text, re.IGNORECASE)
            if not m:
                raise ValueError(f"could not find is_allowed in response: {text[:150]}")
            is_allowed = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text, re.DOTALL)
            reason = rm.group(1) if rm else text[:150]
            log_mistral_call(program_name, snippet, is_allowed, reason, error=None)
            _MISTRAL_CACHE[cache_key] = {"is_allowed": is_allowed, "reason": reason}
            _MISTRAL_CALLS_SINCE_SAVE += 1
            if _MISTRAL_CALLS_SINCE_SAVE >= 50:
                save_mistral_cache(_MISTRAL_CACHE)
                _MISTRAL_CALLS_SINCE_SAVE = 0
            return is_allowed
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    ra_val = float(retry_after) if retry_after is not None else None
                except (TypeError, ValueError):
                    ra_val = None
                if ra_val is not None and ra_val > 300:
                    _MISTRAL_QUOTA_EXHAUSTED_UNTIL = time.time() + ra_val
                    break
            if e.code in (503, 429) and attempt < 2:
                wait = 5 * (attempt + 1)
                if e.code == 429:
                    try:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        if ra is not None:
                            wait = max(wait, min(int(float(ra)) + 1, 90))
                    except (TypeError, ValueError):
                        pass
                time.sleep(wait)
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_mistral_call(program_name, snippet, None, None, error=str(last_err))
    return None


def log_mistral_call(program_name, snippet, is_ban, reason, error):
    with open(MISTRAL_LOG_PATH, "a") as f:
        f.write(f"--- {program_name} ---\n")
        f.write(f"snippet: {snippet[:200]!r}\n")
        if error:
            f.write(f"ERROR: {error} -> defaulted to REVIEW/SKIP\n")
        else:
            f.write(f"decision: {'BAN' if is_ban else 'NOT A BAN'} | reason: {reason}\n")
        f.write("\n")


def check_automation_ban_two_layer(text, program_name):
    """Returns (status, snippet) where status is one of:
      "banned"  - explicit ban on the ACT of automated scanning, confirmed
      "allowed" - explicit permission for automated scanning, confirmed
      "silent"  - neither found anywhere in the text (condition #3: no
                  evidence of permission = no permission = drop)
      "review"  - a Mistral call failed; queue for retry, don't decide yet
    """
    # Layer 1a: regex fast-path for explicit ban language, Mistral-confirmed
    # (Mistral filters out false positives like report-quality/submission
    # rules that mention "automated" but don't ban the act of scanning).
    banned, ban_snippet = check_automation_ban(text)
    if banned:
        result = mistral_check_ban(ban_snippet, program_name)
        if result is None:
            return "review", f"[Mistral call failed — queued for retry] {ban_snippet[:80]}"
        if result:
            return "banned", f"[Mistral-confirmed ban] {ban_snippet[:80]}"
        # Mistral says this snippet isn't actually a ban (e.g. a submission
        # rule) - that's not evidence of permission either, so fall through
        # to check for explicit allow language / genuine silence below.

    if not text:
        return "silent", None

    # Layer 1b: regex fast-path for explicit allow language, Mistral-confirmed.
    # Regex sweeps the FULL text here (no chunk cap), so this doesn't miss
    # allow language that happens to fall outside the full-text fallback's
    # chunk limit below.
    allowed, allow_snippet = check_automation_allow(text)
    if allowed:
        result = mistral_check_automation_allowed(allow_snippet, program_name)
        if result is None:
            return "review", f"[Mistral call failed — queued for retry] {allow_snippet[:80]}"
        if result:
            return "allowed", f"[Mistral-confirmed explicit allow] {allow_snippet[:80]}"
        # Mistral says this snippet isn't actually a grant of permission -
        # fall through to the full-text ban re-check below.

    # Layer 2: regex found no clear signal either way — send full policy to
    # Mistral for a real read instead of guessing off loose keywords, chunked
    # so a ban clause past the old 8000-char cutoff can't be missed.
    any_review = False
    for chunk in _chunk_text(text)[:MAX_FULLTEXT_FALLBACK_CHUNKS]:
        result = mistral_check_ban(chunk, program_name)
        if result is None:
            any_review = True
            continue
        if result:
            return "banned", "[Mistral-confirmed ban, no regex match]"

    # Layer 2b: same full-text Mistral fallback for explicit ALLOW language.
    # Without this, allow detection only ever had the narrow regex gate above
    # (Layer 1b) with no full-text safety net - unlike ban, which gets this
    # re-read. That asymmetry meant real explicit-permission text in natural
    # phrasing the regex didn't anticipate fell straight through to "silent".
    for chunk in _chunk_text(text)[:MAX_FULLTEXT_FALLBACK_CHUNKS]:
        result = mistral_check_automation_allowed(chunk, program_name)
        if result is None:
            any_review = True
            continue
        if result:
            return "allowed", "[Mistral-confirmed explicit allow, no regex match]"

    if any_review:
        return "review", "[Mistral call failed on full-text check — queued for retry]"

    # No ban found anywhere (regex or full-text read), and no explicit allow
    # language found either. Per condition #3, silence is NOT permission.
    return "silent", "[No automation ban found, but no explicit allow language found either - condition #3 requires explicit permission, not just absence of a ban]"

if __name__ == "__main__":
    main()
