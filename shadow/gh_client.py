"""shadow/gh_client.py: the ONLY module in Muninn's GitHub Action wedge that
makes a network call.

Every other module the Action uses (shadow/doctor.py, shadow/redact.py,
shadow/receipt.py) is local and read-only: they read files on disk and
return data structures. This module is the single seam where a byte leaves
the runner, wrapping exactly the three GitHub REST endpoints the Action
needs (list PR comments, create a comment, edit a comment) behind one small
class, GitHubClient, whose every network call funnels through the single
_request method.

That funnel is what makes the Action's test suite honestly claim "zero
network calls": tests construct a GitHubClient subclass (or monkeypatch
_request) that records calls instead of making them, so the suite can
assert both the UPSERT decision (edit vs. create) and that _request itself
was never called with a real socket.

Pure stdlib (urllib) -- Muninn's core has no third-party HTTP dependency and
this module does not introduce one.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

DEFAULT_API_BASE = "https://api.github.com"
USER_AGENT = "muninn-context-receipt-action"
REQUEST_TIMEOUT_SECONDS = 30
COMMENTS_PAGE_SIZE = 100   # GitHub's own max per_page for this endpoint
COMMENTS_MAX_PAGES = 1000  # hard cap so a misbehaving API can't loop forever
                           # (100k comments; far beyond any real PR)


class GitHubClient:
    """Thin wrapper over the issue-comment endpoints. `repo` is "owner/name"
    (GITHUB_REPOSITORY's own format). Every method below reduces to one
    _request call, so a caller (or a test) that wants to intercept ALL
    network traffic needs to replace exactly one method."""

    def __init__(self, token: str, repo: str,
                api_base: str = DEFAULT_API_BASE) -> None:
        self.token = token
        self.repo = repo
        self.api_base = api_base.rstrip("/")

    def _request(self, method: str, path: str,
                body: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.api_base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            })
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            payload = resp.read()
            return json.loads(payload) if payload else None

    def list_issue_comments(self, issue_number: int) -> List[Dict[str, Any]]:
        """A PR's comments live under the /issues/ endpoint on GitHub's API
        (a PR IS an issue for comment purposes). PAGINATED: walks every page
        at GitHub's own max page size (COMMENTS_PAGE_SIZE=100) so
        upsert_comment below finds Muninn's own marked comment (and edits
        it, never duplicates it) regardless of how many other comments a PR
        has accumulated. Stops as soon as a page comes back short (the
        standard "last page" signal) rather than always walking
        COMMENTS_MAX_PAGES -- that constant exists only as a hard backstop
        against an API that never returns a short page, not as the normal
        stopping condition."""
        all_comments: List[Dict[str, Any]] = []
        for page in range(1, COMMENTS_MAX_PAGES + 1):
            result = self._request(
                "GET",
                f"/repos/{self.repo}/issues/{issue_number}/comments"
                f"?per_page={COMMENTS_PAGE_SIZE}&page={page}")
            page_comments = result or []
            all_comments.extend(page_comments)
            if len(page_comments) < COMMENTS_PAGE_SIZE:
                break
        return all_comments

    def create_issue_comment(self, issue_number: int, body: str) -> Dict[str, Any]:
        return self._request(
            "POST", f"/repos/{self.repo}/issues/{issue_number}/comments",
            {"body": body})

    def update_issue_comment(self, comment_id: int, body: str) -> Dict[str, Any]:
        return self._request(
            "PATCH", f"/repos/{self.repo}/issues/comments/{comment_id}",
            {"body": body})


def find_marked_comment(comments: List[Dict[str, Any]],
                        marker: str) -> Optional[Dict[str, Any]]:
    """Pure, no I/O: the first comment (if any) whose body carries the
    hidden marker. Separated from upsert_comment so a test can exercise the
    search logic without touching a client at all."""
    for c in comments:
        if marker in (c.get("body") or ""):
            return c
    return None


def upsert_comment(client: GitHubClient, issue_number: int, body: str,
                   marker: str) -> Dict[str, Any]:
    """Find Muninn's own prior comment on this PR by the hidden marker and
    EDIT it; only create a new comment when none exists. This is the whole
    upsert contract the Action promises: one Context Receipt comment per PR,
    updated in place on every run, never a spam trail."""
    existing = find_marked_comment(client.list_issue_comments(issue_number), marker)
    if existing is not None:
        return client.update_issue_comment(existing["id"], body)
    return client.create_issue_comment(issue_number, body)
