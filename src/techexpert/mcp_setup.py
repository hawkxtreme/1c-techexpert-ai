"""A process-owned loopback setup window for the installed MCP plugin."""

from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException
from threading import Lock, Thread
from time import monotonic


MAX_SETUPS = 64


def _result(data):
    return dict(status='succeeded', operation='init', data=data)


def _refuse(reason, message, *, data=None):
    return dict(status='invalid_input', operation='init', data=data, stop_reason=reason, message=message)


@dataclass
class _Window:
    request: dict
    server: object
    worker: Thread
    readiness: dict
    ending: str | None = None

    def view(self, status):
        profile, investigation = self.server.configuration_result
        return dict(wizard_status=status, investigation_id=self.server.investigation_id,
                    profile_revision=profile, investigation_revision=investigation)


class SetupWindows:
    def __init__(self):
        self.lock = Lock()
        self.current = None
        self.finished = {}

    def _finish(self, reason):
        window = self.current
        window.ending = window.ending or reason
        window.server.stop_requested.set()
        window.worker.join(3)
        if window.worker.is_alive() or not window.server.profile_lock.acquire(timeout=2):
            return False
        try:
            self.finished[window.request['operation_key']] = (window.request, window.view(window.ending))
            self.current = None
        finally:
            window.server.profile_lock.release()
        return True

    def _refresh(self):
        window = self.current
        if window is None:
            return True
        if window.ending is not None:
            return self._finish(window.ending)
        if monotonic() >= window.server.deadline:
            return self._finish('expired')
        if not window.worker.is_alive():
            return self._finish('failed')
        return True

    @staticmethod
    def _page_ready(server):
        probe = HTTPConnection('127.0.0.1', server.server_port, timeout=2)
        try:
            probe.request('GET', '/')
            reply = probe.getresponse()
            return reply.status == 200 and reply.headers.get_content_type() == 'text/html'
        except (HTTPException, OSError):
            return False
        finally:
            probe.close()

    def _open(self, request, state_for_call, cancel):
        from .gui import create_server
        from .readiness import check

        state = state_for_call()
        case = request.get('investigation_id')
        entrypoint = request.get('entrypoint_sha256')
        report = check(state, investigation_id=case, entrypoint_sha256=entrypoint)
        readiness = {name: report[name] for name in ('status', 'state_storage', 'capabilities', 'actions')}
        if (report['status'] == 'blocked' or report['state_storage']['free_bytes'] is None
                or case and report['profile']['status'] == 'invalid'):
            return _refuse('setup_not_ready', 'Check the bundle, state storage and selected investigation.',
                           data=dict(readiness=readiness))
        if cancel.is_set():
            return dict(status='cancelled', operation='init')
        try:
            server = create_server(state, ttl=request['ttl_seconds'], investigation_id=case, entrypoint_sha256=entrypoint)
        except (OSError, ValueError):
            return _refuse('setup_listener_unavailable', 'Check loopback access and the selected investigation.')
        worker = Thread(target=server.serve_forever, daemon=True, name='techexpert-init')
        try:
            worker.start()
        except RuntimeError:
            server.server_close()
            return _refuse('setup_listener_unavailable', 'Could not start the local setup window.')
        window = self.current = _Window(request, server, worker, readiness)
        if not self._page_ready(server):
            self._finish('failed')
            return _refuse('setup_listener_unavailable', 'The local setup page did not respond.')
        if monotonic() >= server.deadline:
            if self._finish('expired'):
                return _result(self.finished[request['operation_key']][1])
            return _refuse('setup_closing', 'The setup window expired. Check the same key again.')
        if cancel.is_set():
            self._finish('closed')
            return dict(status='cancelled', operation='init')
        return _result(dict(window.view('open'), readiness=readiness, url=server.url))

    def call(self, request, state_for_call, cancel):
        key, action = request['operation_key'], request['action']
        with self.lock:
            if not self._refresh():
                return _refuse('setup_closing', 'The setup window is closing. Check the same key again.')
            if key in self.finished:
                saved, data = self.finished[key]
                if action == 'open' and saved != request:
                    return _refuse('setup_key_conflict', 'This key already belongs to a different setup request.')
                return _result(data)
            window = self.current
            if window is not None and window.request['operation_key'] == key:
                if action == 'status':
                    return _result(window.view('open'))
                if action == 'close':
                    if self._finish('closed'):
                        return _result(self.finished[key][1])
                    return _refuse('setup_closing', 'Close is in progress. Check the same key again.')
                if window.request != request:
                    return _refuse('setup_key_conflict', 'This key already belongs to a different setup request.')
                return _result(dict(window.view('open'), readiness=window.readiness, url=window.server.url))
            if action != 'open':
                return _refuse('setup_unknown', 'This MCP session has no setup with the selected key.')
            if window is not None:
                return _refuse('setup_busy', 'A setup window is already open in this MCP session.')
            if len(self.finished) >= MAX_SETUPS:
                return _refuse('setup_history_limit', 'Open a fresh MCP session for another setup window.')
            return self._open(request, state_for_call, cancel)

    def shutdown(self):
        if self.current is not None:
            self._finish('closed')

    def request_shutdown(self):
        window = self.current
        if window is not None:
            window.server.stop_requested.set()
