from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Protocol

from src.models.policy_schema import StructuredPolicy
from src.translator.core import PolicySchemaTranslator


@dataclass(frozen=True)
class PolicyChange:
    policy_id: str
    raw_text: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)
    version_hint: str | None = None


@dataclass(frozen=True)
class PolicyUpdateResult:
    policy_id: str
    changed: bool
    fingerprint: str
    source: str
    updated_at: datetime
    affected_workflows: tuple[str, ...]
    diff_summary: str | None = None


class AgentWorkflowProtocol(Protocol):
    def apply_policy_update(self, policy: StructuredPolicy) -> None:
        """
        Apply an updated policy in place.
        Implementations should swap references atomically to avoid downtime.
        """


class PolicyChangeSourceProtocol(Protocol):
    def fetch_changes(self) -> list[PolicyChange]:
        """Return latest policy changes from this source."""


@dataclass
class _PolicyState:
    fingerprint: str
    policy: StructuredPolicy
    source: str
    updated_at: datetime
    raw_text: str


class LiveUpdateEngine:
    """
    Monitors external and internal policy sources and propagates hot updates
    to active workflows with zero restart requirements.
    """

    def __init__(self, translator: PolicySchemaTranslator | None = None, poll_interval_seconds: float = 2.0) -> None:
        self._translator = translator or PolicySchemaTranslator()
        self._poll_interval_seconds = max(0.1, poll_interval_seconds)
        self._state_lock = threading.RLock()
        self._workflow_lock = threading.RLock()
        self._states: dict[str, _PolicyState] = {}
        self._workflows: dict[str, AgentWorkflowProtocol] = {}
        self._subscriptions: dict[str, set[str]] = {}
        self._sources: list[PolicyChangeSourceProtocol] = []
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None

    def register_workflow(self, workflow_id: str, workflow: AgentWorkflowProtocol, policy_ids: set[str] | None = None) -> None:
        with self._workflow_lock:
            self._workflows[workflow_id] = workflow
            self._subscriptions[workflow_id] = set(policy_ids or [])
            if not self._subscriptions[workflow_id]:
                for policy_state in self._states.values():
                    workflow.apply_policy_update(policy_state.policy)
            else:
                for policy_id in self._subscriptions[workflow_id]:
                    if policy_id in self._states:
                        workflow.apply_policy_update(self._states[policy_id].policy)

    def unregister_workflow(self, workflow_id: str) -> None:
        with self._workflow_lock:
            self._workflows.pop(workflow_id, None)
            self._subscriptions.pop(workflow_id, None)

    def add_source(self, source: PolicyChangeSourceProtocol) -> None:
        self._sources.append(source)

    def start(self) -> None:
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._run_monitor_loop, name="policy-live-update", daemon=True)
        self._monitor_thread.start()

    def stop(self, timeout_seconds: float = 3.0) -> None:
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=timeout_seconds)
        self._monitor_thread = None

    def sync_once(self) -> list[PolicyUpdateResult]:
        results: list[PolicyUpdateResult] = []
        for source in self._sources:
            for change in source.fetch_changes():
                results.append(self.apply_change(change))
        return results

    def apply_change(self, change: PolicyChange) -> PolicyUpdateResult:
        fingerprint = self._fingerprint(change.raw_text)
        with self._state_lock:
            current = self._states.get(change.policy_id)
            if current and current.fingerprint == fingerprint:
                return PolicyUpdateResult(
                    policy_id=change.policy_id,
                    changed=False,
                    fingerprint=fingerprint,
                    source=change.source,
                    updated_at=current.updated_at,
                    affected_workflows=(),
                    diff_summary=None,
                )

            policy = self._translator.translate(change.raw_text, context=change.metadata)
            policy.policy_id = change.policy_id
            policy.raw_source = change.raw_text
            if change.version_hint:
                policy.version = change.version_hint
            elif current:
                policy.version = self._increment_patch_version(current.policy.version)

            now = datetime.utcnow()
            diff_summary = self._summarize_diff(current.raw_text if current else "", change.raw_text)
            self._states[change.policy_id] = _PolicyState(
                fingerprint=fingerprint,
                policy=policy,
                source=change.source,
                updated_at=now,
                raw_text=change.raw_text,
            )

        affected = self._broadcast_policy(change.policy_id, policy)
        return PolicyUpdateResult(
            policy_id=change.policy_id,
            changed=True,
            fingerprint=fingerprint,
            source=change.source,
            updated_at=now,
            affected_workflows=tuple(sorted(affected)),
            diff_summary=diff_summary,
        )

    def get_policy(self, policy_id: str) -> StructuredPolicy | None:
        with self._state_lock:
            state = self._states.get(policy_id)
            return state.policy if state else None

    def list_policies(self) -> dict[str, StructuredPolicy]:
        with self._state_lock:
            return {policy_id: state.policy for policy_id, state in self._states.items()}

    def snapshot_workflow_policies(self) -> dict[str, tuple[StructuredPolicy, ...]]:
        """
        Returns the currently active policies per registered workflow.
        If a workflow does not expose active policy state, this falls back to
        subscription mappings from the live policy state.
        """
        with self._workflow_lock:
            workflows = dict(self._workflows)
            subscriptions = {k: set(v) for k, v in self._subscriptions.items()}
        with self._state_lock:
            states = {policy_id: state.policy for policy_id, state in self._states.items()}

        snapshot: dict[str, tuple[StructuredPolicy, ...]] = {}
        for workflow_id, workflow in workflows.items():
            if hasattr(workflow, "list_active_policies"):
                policies = workflow.list_active_policies()
                snapshot[workflow_id] = tuple(policies)
                continue

            subscribed = subscriptions.get(workflow_id, set())
            if not subscribed:
                snapshot[workflow_id] = tuple(states.values())
            else:
                snapshot[workflow_id] = tuple(states[p] for p in sorted(subscribed) if p in states)
        return snapshot

    def _run_monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_once()
            finally:
                self._stop_event.wait(self._poll_interval_seconds)

    def _broadcast_policy(self, policy_id: str, policy: StructuredPolicy) -> list[str]:
        applied: list[str] = []
        with self._workflow_lock:
            workflows = list(self._workflows.items())
            subscriptions = {workflow_id: set(self._subscriptions.get(workflow_id, set())) for workflow_id, _ in workflows}

        for workflow_id, workflow in workflows:
            subscribed = subscriptions.get(workflow_id, set())
            if subscribed and policy_id not in subscribed:
                continue
            workflow.apply_policy_update(policy)
            applied.append(workflow_id)
        return applied

    @staticmethod
    def _fingerprint(raw_text: str) -> str:
        return hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    @staticmethod
    def _summarize_diff(old_text: str, new_text: str) -> str | None:
        old_words = set(old_text.split())
        new_words = set(new_text.split())
        added = sorted(new_words - old_words)
        removed = sorted(old_words - new_words)
        if not added and not removed:
            return None
        return f"added={added[:6]} removed={removed[:6]}"

    @staticmethod
    def _increment_patch_version(version: str) -> str:
        parts = version.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            return "1.0.1"
        major, minor, patch = (int(p) for p in parts)
        return f"{major}.{minor}.{patch + 1}"


class InMemoryPolicyChangeSource:
    """
    Convenience source for tests and local integrations.
    Use push_change(...) to enqueue external or internal policy updates.
    """

    def __init__(self) -> None:
        self._queue: list[PolicyChange] = []
        self._lock = threading.Lock()

    def push_change(
        self,
        policy_id: str,
        raw_text: str,
        source: str,
        metadata: dict[str, Any] | None = None,
        version_hint: str | None = None,
    ) -> None:
        change = PolicyChange(
            policy_id=policy_id,
            raw_text=raw_text,
            source=source,
            metadata=metadata or {},
            version_hint=version_hint,
        )
        with self._lock:
            self._queue.append(change)

    def fetch_changes(self) -> list[PolicyChange]:
        with self._lock:
            changes = list(self._queue)
            self._queue.clear()
        return changes


class AtomicWorkflowStore:
    """
    Minimal workflow helper that demonstrates zero-downtime updates.
    Reads always succeed while policies are hot-swapped under a lock.
    """

    def __init__(self, workflow_logic: Callable[[dict[str, StructuredPolicy], dict[str, Any]], dict[str, Any]] | None = None) -> None:
        self._policies: dict[str, StructuredPolicy] = {}
        self._lock = threading.RLock()
        self._workflow_logic = workflow_logic or self._default_logic

    def apply_policy_update(self, policy: StructuredPolicy) -> None:
        with self._lock:
            self._policies[policy.policy_id] = policy

    def execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            snapshot = dict(self._policies)
        return self._workflow_logic(snapshot, payload)

    @staticmethod
    def _default_logic(policies: dict[str, StructuredPolicy], payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "policy_count": len(policies),
            "payload": payload,
            "active_policy_ids": sorted(policies.keys()),
        }
