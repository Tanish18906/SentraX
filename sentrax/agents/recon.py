"""SentraX AI — Recon Agent.

Reference: Docs/Agents.md Section 1.
Job: Map the attack surface (DAST crawl or SAST code scan). No reasoning, pure data collection.
"""

from __future__ import annotations

import os
import re
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import requests

from sentrax.utils.schema import FormInfo, PageInfo, ReconFolderResult, ReconURLResult, SASTFindingRaw


class TargetUnreachableError(Exception):
    """Raised when the target URL cannot be reached."""
    pass


class ReconAgent:
    """Reconnaissance agent for DAST URL crawling and SAST folder scanning."""

    # Common API / endpoint patterns in web apps
    API_PATTERN = re.compile(
        r"""['"`](/(?:api|rest|v[0-9]+|user|users|order|orders|auth|login|register|review|reviews|product|products|search|account|admin)[a-zA-Z0-9_\-/\.]*)['"`]""",
        re.IGNORECASE,
    )

    # SAST regex rules
    SAST_RULES = [
        (
            "sqli_concat",
            re.compile(
                r"""(?:SELECT\b|INSERT\s+INTO\b|UPDATE\b|DELETE\s+FROM\b).*?['"]\s*\+\s*[a-zA-Z0-9_]+|["'].*?(?:SELECT\b|INSERT\s+INTO\b|UPDATE\b|DELETE\s+FROM\b).*?%\s*[a-zA-Z0-9_]+|f["'].*?(?:SELECT\b|INSERT\s+INTO\b|UPDATE\b|DELETE\s+FROM\b).*?\{[a-zA-Z0-9_]+\}""",
                re.IGNORECASE,
            ),
        ),
        (
            "xss_innerhtml",
            re.compile(
                r"""(?:\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\()"""
            ),
        ),
        (
            "hardcoded_secret",
            re.compile(
                r"""(?:JWT_SECRET|API_KEY|SECRET_KEY|DATABASE_PASSWORD|AUTH_SECRET)\s*=\s*['"][a-zA-Z0-9_\-]{6,}['"]""",
                re.IGNORECASE,
            ),
        ),
        (
            "idor_missing_authz",
            re.compile(
                r"""(?:findById|findByPk|findOne|get_object_or_404)\s*\(\s*(?:req\.params\.[a-zA-Z0-9_]+|request\.(?:GET|POST|query_params)\[['"][a-zA-Z0-9_]+['"]\])""",
                re.IGNORECASE,
            ),
        ),
    ]

    IGNORED_DIRS = {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".idea",
        ".vscode",
        "dist",
        "build",
    }

    SOURCE_EXTENSIONS = {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".py",
        ".php",
        ".rb",
        ".java",
        ".go",
        ".html",
        ".vue",
    }

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update(
            {"User-Agent": "SentraX-Security-Scanner/1.0 (+https://github.com/Tanish18906/SentraX)"}
        )

    def scan_url(
        self,
        target_url: str,
        max_depth: int = 2,
        max_pages: int = 20,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Crawl a live target URL (DAST mode).

        Args:
            target_url: Root URL to start scanning (e.g. http://localhost:3000)
            max_depth: Crawling depth limit
            max_pages: Maximum number of pages to crawl
            timeout: Request timeout in seconds

        Returns:
            Dict matching ReconURLResult schema
        """
        # Normalize target URL
        parsed_target = urlparse(target_url)
        if not parsed_target.scheme:
            target_url = "http://" + target_url
            parsed_target = urlparse(target_url)

        base_netloc = parsed_target.netloc

        # Sanity check connectivity first
        try:
            initial_resp = self.session.get(target_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            raise TargetUnreachableError(f"Could not reach {target_url} — is the target running? ({e})")

        visited_urls: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(initial_resp.url, 0)])
        pages_result: List[PageInfo] = []

        while queue and len(visited_urls) < max_pages:
            current_url, depth = queue.popleft()

            # Clean URL (strip fragments)
            clean_url = current_url.split("#")[0]
            if clean_url in visited_urls:
                continue
            visited_urls.add(clean_url)

            try:
                if clean_url == initial_resp.url:
                    resp = initial_resp
                else:
                    resp = self.session.get(clean_url, timeout=timeout, allow_redirects=True)

                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                html_text = resp.text
                soup = BeautifulSoup(html_text, "html.parser")

                # Extract forms
                forms: List[FormInfo] = []
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    method = form_tag.get("method", "GET").upper()

                    # Extract input field names
                    fields: List[str] = []
                    for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                        name = input_tag.get("name") or input_tag.get("id")
                        input_type = input_tag.get("type", "text").lower()
                        if name and input_type not in ("submit", "button", "reset"):
                            if name not in fields:
                                fields.append(name)

                    # Normalize action URL
                    if action:
                        action_url = urljoin(clean_url, action)
                        action_path = urlparse(action_url).path
                    else:
                        action_path = urlparse(clean_url).path

                    forms.append(FormInfo(action=action_path or "/", method=method, fields=fields))

                # Extract observed endpoints
                endpoints: Set[str] = set()
                # 1. From form actions
                for f in forms:
                    endpoints.add(f.action)

                # 2. From regex search across HTML and JS
                for match in self.API_PATTERN.finditer(html_text):
                    ep = match.group(1)
                    if ep and len(ep) > 1:
                        endpoints.add(ep)

                # 3. Check referenced same-host scripts for API endpoints
                for script_tag in soup.find_all("script", src=True):
                    src = script_tag.get("src", "")
                    if src:
                        script_url = urljoin(clean_url, src)
                        parsed_script = urlparse(script_url)
                        if parsed_script.netloc == base_netloc:
                            try:
                                s_resp = self.session.get(script_url, timeout=timeout)
                                if s_resp.status_code == 200:
                                    for match in self.API_PATTERN.finditer(s_resp.text):
                                        ep = match.group(1)
                                        if ep and len(ep) > 1:
                                            endpoints.add(ep)
                            except Exception:
                                pass

                # 4. Discover links for next crawl level
                if depth < max_depth:
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_link = urljoin(clean_url, href)
                        parsed_link = urlparse(full_link)

                        # Only follow HTTP(S) links on the same host
                        if parsed_link.netloc == base_netloc and parsed_link.scheme in ("http", "https"):
                            clean_link = full_link.split("#")[0]
                            if clean_link not in visited_urls:
                                queue.append((clean_link, depth + 1))
                                if parsed_link.path:
                                    endpoints.add(parsed_link.path)

                pages_result.append(
                    PageInfo(
                        url=clean_url,
                        forms=forms,
                        endpoints_observed=sorted(list(endpoints)),
                    )
                )

            except requests.exceptions.RequestException:
                continue

        result = ReconURLResult(
            mode="url",
            target=target_url,
            pages=pages_result,
        )
        return result.model_dump()

    def scan_folder(self, folder_path: str) -> Dict[str, Any]:
        """Scan a local directory for vulnerability patterns (SAST mode).

        Args:
            folder_path: Directory path to scan

        Returns:
            Dict matching ReconFolderResult schema
        """
        resolved_path = Path(folder_path).resolve()
        if not resolved_path.exists() or not resolved_path.is_dir():
            raise FileNotFoundError(f"Folder not found: {folder_path}")

        findings: List[SASTFindingRaw] = []

        for root, dirs, files in os.walk(resolved_path):
            # Filter out ignored directories in-place
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]

            for file_name in files:
                file_ext = os.path.splitext(file_name)[1].lower()
                if file_ext not in self.SOURCE_EXTENSIONS:
                    continue

                full_file_path = os.path.join(root, file_name)
                try:
                    rel_path = os.path.relpath(full_file_path, resolved_path)
                except ValueError:
                    rel_path = str(full_file_path)

                try:
                    with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_idx, line_content in enumerate(lines, start=1):
                    stripped_line = line_content.strip()
                    if not stripped_line or stripped_line.startswith(("//", "#", "/*", "*")):
                        continue

                    for pattern_name, regex in self.SAST_RULES:
                        if regex.search(stripped_line):
                            findings.append(
                                SASTFindingRaw(
                                    file=rel_path,
                                    line=line_idx,
                                    pattern=pattern_name,
                                    snippet=stripped_line[:200],
                                )
                            )

        result = ReconFolderResult(
            mode="folder",
            target=str(folder_path),
            findings_raw=findings,
        )
        return result.model_dump()

    def run(self, target: str, mode: str = "url") -> Dict[str, Any]:
        """Dispatch scan based on mode ('url' or 'folder')."""
        if mode == "url":
            return self.scan_url(target)
        elif mode == "folder":
            return self.scan_folder(target)
        else:
            raise ValueError(f"Unknown recon mode: {mode}. Must be 'url' or 'folder'.")
