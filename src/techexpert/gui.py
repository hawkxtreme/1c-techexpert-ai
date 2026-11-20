"""Short-lived, loopback-only source configuration for the current AI harness."""

import io
import json
import math
import os
import re
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import profiles
from .gui_storage import Storage, StorageConflict, setup_context
from .operation_state import StateSpaceError


MAX_BODY = 64 * 1024
ASSET = Path(__file__).with_name('assets') / 'init.html'


class InitServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def __init__(self, state_dir, ttl, investigation_id=None,entrypoint_sha256=None):
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or ttl <= 0:
            raise ValueError('TTL must be a positive finite number of seconds')
        self.state_dir = Path(state_dir)
        setup_context(self.state_dir, investigation_id)
        self.investigation_id=investigation_id
        self.storage = Storage(self.state_dir)
        self.entrypoint_sha256=entrypoint_sha256
        self.demo_lock=threading.Lock()
        self.file_check_lock = threading.Lock()
        self.deadline = time.monotonic() + ttl
        self.token = secrets.token_urlsafe(32)
        self.profile_lock = threading.Lock()
        self.pending_profile_binding = None
        self.configuration_result = (None, None)
        self.stop_requested = threading.Event()
        super().__init__(('127.0.0.1', 0), InitHandler)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.url = f'{self.origin}/#token={self.token}'

    def serve_forever(self, poll_interval=0.05):
        def stop_at_deadline_or_request():
            self.stop_requested.wait(max(0, self.deadline - time.monotonic()))
            self.shutdown()

        threading.Thread(target=stop_at_deadline_or_request, daemon=True).start()
        try:
            super().serve_forever(poll_interval=poll_interval)
        finally:
            self.stop_requested.set()
            self.server_close()


class InitHandler(BaseHTTPRequestHandler):
    server_version = 'TechExpertLocal'
    sys_version = ''

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_args):
        # URLs, source paths and credentials must not become access-log entries.
        pass

    def _reply(self, status, body, content_type='application/json; charset=utf-8', nonce=None, etag=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if etag is not None:self.send_header('ETag',etag)
        policy = "default-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        if nonce:
            policy += f"; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'"
        self.send_header('Content-Security-Policy', policy)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status, data, etag=None):
        self._reply(status, json.dumps(data, ensure_ascii=False, allow_nan=False).encode('utf-8'),etag=etag)

    def _error(self, status, message):
        self._json(status, {'error': message})

    @staticmethod
    def _profile_etag(profile):return '"profile-'+str(profile['revision'] if profile else 0)+'"'

    def _expected_profile_revision(self):
        values=self.headers.get_all('If-Match',[])
        if not values:
            self._error(428,'Сначала загрузите профиль в актуальном окне init. Сохранение без его ревизии не выполняется.')
            return None
        match=re.fullmatch(r'"profile-(0|[1-9][0-9]{0,9})"',values[0]) if len(values)==1 else None
        if match is None:
            self._error(400,'Для сохранения требуется одна точная ревизия загруженного профиля.')
            return None
        return int(match[1])

    def _editing_profile(self):
        if self.server.investigation_id is None:
            return profiles.load_profile(self.server.state_dir)
        context = setup_context(self.server.state_dir, self.server.investigation_id)
        return context['profile_snapshot'] if context else None

    def _save_profile(self, data, expected):
        state = self.server.state_dir
        identifier = self.server.investigation_id
        if identifier is None:
            return profiles.save_profile(state, data, expected_revision=expected)

        from .investigations import _digest, read_for_display
        from .investigation_retention import writer

        with writer(state, identifier):
            context = read_for_display(state, identifier)
            result = profiles.save_profile(state, data, expected_revision=expected,
                                           pinned_profile=context['profile_snapshot'])
        self.server.pending_profile_binding = (result['revision'], (context['profile_sha256'], _digest(result)))
        return result

    @staticmethod
    def _context(doc):
        from .source_passports import setup_states
        return dict(investigation_id=doc['investigation_id'],revision=doc['revision'],task=doc['task'],
            template_id=doc['template']['id'],variant=doc['variant']['id'] if doc['variant'] else None,
            template_revision=doc['template']['revision'],template_title=doc['template']['title'],
            template_variants=doc['template']['variants'],
            time_mode=doc['time_mode'],scale=doc['scale'],
            workflow_stage=doc.get('workflow_stage','initial_analysis'),continuation=doc.get('continuation'),
            observation_window_seconds=(doc['observation_plan']['duration_seconds'] if doc['observation_plan'] else doc['episode'].get('requested_window_seconds')),
            profile_revision=doc['profile_snapshot']['revision'] if doc['profile_snapshot'] else None,source_states=setup_states(doc))

    def _guard(self, *, write=False, api=False):
        hosts = self.headers.get_all('Host', [])
        if hosts != [f'127.0.0.1:{self.server.server_port}']:
            self._error(403, 'Недопустимый адрес локального помощника.')
            return False
        origins = self.headers.get_all('Origin', [])
        if (write and origins != [self.server.origin]) or (origins and origins != [self.server.origin]):
            self._error(403, 'Запрос разрешён только из окна локального помощника.')
            return False
        if self.server.stop_requested.is_set() or time.monotonic() >= self.server.deadline:
            self._error(410, 'Время работы помощника истекло. Повторите init в текущем чате.')
            return False
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            self._error(400, 'Параметры доступа не передаются в адресе запроса.')
            return False
        if api:
            headers = self.headers.get_all('Authorization', [])
            expected = 'Bearer ' + self.server.token
            if len(headers) != 1 or not secrets.compare_digest(headers[0], expected):
                self._error(401, 'Откройте актуальную ссылку init из текущего чата.')
                return False
        return True

    def _read_json(self):
        content_types = self.headers.get_all('Content-Type', [])
        if len(content_types) != 1 or self.headers.get_content_type() != 'application/json':
            self._error(415, 'Ожидается JSON.')
            return None
        if self.headers.get_content_charset('utf-8').lower() not in ('utf-8', 'utf8'):
            self._error(415, 'Ожидается JSON в UTF-8.')
            return None
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
            self._error(400, 'Некорректная длина запроса.')
            return None
        length = int(lengths[0])
        if length > MAX_BODY:
            self._error(413, 'Настройки слишком велики для одного запроса.')
            return None
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete body')
            data = json.loads(raw.decode('utf-8'), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            if not isinstance(data, dict):
                raise ValueError('Object required')
        except (UnicodeError, ValueError, RecursionError):
            self._error(400, 'Некорректный JSON: требуется объект настроек.')
            return None
        except TimeoutError:
            self._error(408, 'Не удалось получить запрос полностью.')
            return None
        return data

    def do_GET(self):
        if not self._guard(api=self.path != '/'):
            return
        try:
            if self.path == '/':
                nonce = secrets.token_urlsafe(18)
                html = ASSET.read_text(encoding='utf-8').replace('__CSP_NONCE__', nonce)
                self._reply(200, html.encode('utf-8'), 'text/html; charset=utf-8', nonce)
            elif self.path == '/api/profile':
                with self.server.profile_lock:
                    result = self._editing_profile()
                self._json(200, result,etag=self._profile_etag(result))
            elif self.path == '/api/storage':
                self._json(200, self.server.storage.settings(self.server.investigation_id))
            elif self.path == '/api/doctor':
                self._json(200, profiles.doctor(self.server.state_dir))
            elif self.path == '/api/readiness':
                from .readiness import check
                self._json(200,check(self.server.state_dir,entrypoint_sha256=self.server.entrypoint_sha256,investigation_id=self.server.investigation_id))
            elif self.path == '/api/templates':
                from .incident_templates import catalogue
                try:book=catalogue(state_dir=self.server.state_dir)
                except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
                    # An embedded investigation template remains usable even if
                    # its independent mutable catalogue is lost or damaged.
                    book=catalogue()
                    book['private_catalogue']=dict(status='unavailable',error_type=type(exc).__name__,detail=str(exc)[:1024])
                self._json(200,book)
            elif self.path == '/api/source-help':
                from .source_help import catalogue
                self._json(200,dict(catalogue(), file_tj_lookup=os.name == 'nt'))
            elif self.path == '/api/starter-location':
                from .discovery import default_starter_path
                path=default_starter_path();self._json(200,dict(path=str(path) if path is not None else None,checked=False))
            elif self.path == '/api/context':
                context = setup_context(self.server.state_dir, self.server.investigation_id)
                self._json(200, self._context(context) if context else None)
            else:
                self._error(404, 'Неизвестное действие помощника.')
        except ValueError as error:
            self._error(400, str(error))
        except OSError:
            self._error(500, 'Локальные материалы недоступны. Проверьте путь и права доступа.')

    def do_POST(self):
        if not self._guard(write=True, api=True):
            return
        if self.path not in ('/api/profile', '/api/starter','/api/ras','/api/check','/api/file-check','/api/context','/api/demo','/api/profile-editor','/api/profile-compose','/api/storage'):
            self._error(404, 'Неизвестное действие помощника.')
            return
        data = self._read_json()
        if data is None or not self._guard(write=True, api=True):
            return
        try:
            if self.path=='/api/demo':
                if data:raise ValueError('Демонстрация использует только комплектный синтетический SC-01, без параметров источников.')
                from .readiness import check,read_demo,require_demo,run_demo
                with self.server.demo_lock:
                    require_demo(check(self.server.state_dir))
                    previous=read_demo(self.server.state_dir)
                    if previous['status']!='completed':run_demo(self.server.state_dir)
                    result=read_demo(self.server.state_dir)
            elif self.path=='/api/storage':
                try:
                    result = self.server.storage.request(self.server.investigation_id, data)
                except (OSError, KeyError, TypeError, AttributeError, RecursionError):
                    self._error(400, 'Не удалось проверить действие с хранилищем. Обновите материалы и проверьте состояние очистки.')
                    return
            elif self.path=='/api/context':
                from .investigations import revise
                if not self.server.investigation_id:raise ValueError('Помощник открыт без выбранного расследования.')
                if set(data)!={'expected_revision','profile_revision'}:raise ValueError('Помощник связывает сохранённые настройки. Вопросы об инциденте уточняются в чате.')
                with self.server.profile_lock:
                    if not self._guard(write=True, api=True):return
                    number=data['profile_revision']
                    pending = self.server.pending_profile_binding
                    if type(number) is not int or pending is None or number != pending[0]:
                        raise ValueError('Для привязки укажите ревизию, сохранённую в этом помощнике.')
                    revised=revise(self.server.state_dir,self.server.investigation_id,
                        {'profile_revision':number},expected_revision=data['expected_revision'],
                        expected_profile_hashes=pending[1])
                    self.server.pending_profile_binding = None
                    self.server.configuration_result=(number, revised['revision'])
                    result=self._context(revised)
            elif self.path=='/api/ras':
                if set(data)-{'endpoint','executable','docker_container','cluster','infobase'}:raise ValueError('Unsupported RAS parameter')
                if type(data.get('endpoint')) is not str or ('executable' in data and type(data['executable']) is not str):raise ValueError('RAS endpoint and executable must be text')
                if any(data.get(key) is not None and type(data[key]) is not str for key in ('docker_container','cluster','infobase')):raise ValueError('RAS selection must be text or null')
                result=profiles.discover_ras(data.get('endpoint'),executable=data.get('executable','rac'),
                                            docker_container=data.get('docker_container') or None,cluster=data.get('cluster') or None,infobase=data.get('infobase') or None)
            elif self.path=='/api/profile-editor':
                if set(data)!={'profile'}:raise ValueError('Требуется выбранный профиль.')
                from .profile_resources import editor_context
                result=editor_context(data['profile'])
            elif self.path=='/api/profile-compose':
                if set(data)-{'view','draft_profile','connection_bindings','connection_edits','base_registrations','discovery_resources','base_merge','registration_decisions'} or 'view' not in data:raise ValueError('Недопустимое поле редактора профиля.')
                expected=self._expected_profile_revision()
                if expected is None:return
                from .profile_resources import compose_profile,resource_impact,retain_editor_resources,editor_context
                with self.server.profile_lock:
                    before = self._editing_profile()
                    profiles.require_profile_revision(before, expected)
                    draft=data.get('draft_profile')
                    result=compose_profile(draft if draft is not None else before,data['view'],connection_bindings=data.get('connection_bindings'),connection_edits=data.get('connection_edits'),base_registrations=data.get('base_registrations'),discovery_resources=data.get('discovery_resources'),base_merge=data.get('base_merge'),registration_decisions=data.get('registration_decisions'))
                    result['profile']=retain_editor_resources(result['profile'],before)
                    result['editor']=editor_context(result['profile'])
                    result['impact']=resource_impact(before,result['profile'])
            elif self.path=='/api/check':
                result=profiles.check_profile(data)
            elif self.path == '/api/file-check':
                from . import kernel, profile_files

                if set(data) == {'profile'}:
                    request = profile_files.from_profile(data['profile'])
                elif set(data) == {'bases'}:
                    request = profile_files.from_bases(data['bases'])
                elif set(data) == {'tj_bases'}:
                    request = profile_files.from_bases(data['tj_bases'], kind='file_tj')
                else:
                    raise ValueError('Выберите профиль или файловые базы для локальной проверки.')
                if not self.server.file_check_lock.acquire(blocking=False):
                    self._error(409, 'Локальная проверка уже выполняется.')
                    return
                try:
                    if request['items']:
                        output = io.StringIO()
                        call = kernel.invoke(self.server.state_dir, profile_files.ACTION,
                            dict(request='inline-request.json'), limits=dict(query_seconds=20), request_document=request)
                        kernel.emit(call, output)
                        answer = json.loads(output.getvalue())
                        if call['exit_code'] != 0 or answer.get('status') != 'succeeded':
                            raise ValueError('Локальная проверка не завершилась. Проверьте доступность пути или выберите один источник.')
                        result = dict(answer['data'], kernel_call_id=answer['kernel_call_id'])
                    else:
                        result = profile_files.inspect(request)
                finally:
                    self.server.file_check_lock.release()
            elif self.path == '/api/starter':
                if set(data)-{'path','include_registrations'} or type(data.get('include_registrations',False)) is not bool:raise ValueError('Недопустимое поле чтения списка.')
                path = data.get('path')
                if not isinstance(path, str) or not path.strip():
                    raise ValueError('Укажите путь к файлу .v8i или ibases.v8i.')
                if data.get('include_registrations'):
                    from .discovery import inspect_starter
                    result=inspect_starter(path)
                else:result = profiles.read_starter(path)
            else:
                expected=self._expected_profile_revision()
                if expected is None:return
                with self.server.profile_lock:
                    if not self._guard(write=True, api=True):return
                    result = self._save_profile(data, expected)
                    self.server.configuration_result=(result['revision'], None)
            self._json(200, result,etag=self._profile_etag(result) if self.path=='/api/profile' else None)
        except StateSpaceError as error:
            from .readiness import state_storage_help

            self._error(409, state_storage_help(error.storage))
        except StorageConflict as error:
            self._error(409, str(error))
        except profiles.ProfileRevisionConflict:
            self._error(409,'Настройки не сохранены. Откройте актуальную ревизию профиля и сопоставьте изменения в текущем чате.')
        except ValueError as error:
            self._error(400, str(error))
        except OSError:
            self._error(400, 'Не удалось прочитать файл или сохранить профиль. Проверьте путь и права.')


def create_server(state_dir, ttl=900, investigation_id=None,entrypoint_sha256=None):
    """Bind only to loopback; no browser, sources or remote services are opened."""
    return InitServer(state_dir, ttl,investigation_id=investigation_id,entrypoint_sha256=entrypoint_sha256)


def run_gui(state_dir, open_browser=False, ttl=900, investigation_id=None,entrypoint_sha256=None):
    from .readiness import check
    report=check(state_dir,entrypoint_sha256=entrypoint_sha256,investigation_id=investigation_id)
    if report['state_storage']['free_bytes'] is None:
        print(json.dumps({'url': None,'readiness':report},ensure_ascii=False), flush=True)
        return 2
    server = create_server(state_dir, ttl=ttl,investigation_id=investigation_id,entrypoint_sha256=entrypoint_sha256)
    print(json.dumps({'url': server.url,'readiness':report},ensure_ascii=False), flush=True)
    try:
        if open_browser:
            webbrowser.open(server.url)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
