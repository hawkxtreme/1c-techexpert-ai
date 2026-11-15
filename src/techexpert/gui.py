"""Short-lived, loopback-only source configuration for the current AI harness."""

import json
import math
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import profiles


MAX_BODY = 64 * 1024
ASSET = Path(__file__).with_name('assets') / 'init.html'


class InitServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def __init__(self, state_dir, ttl):
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or ttl <= 0:
            raise ValueError('TTL must be a positive finite number of seconds')
        self.state_dir = Path(state_dir)
        self.deadline = time.monotonic() + ttl
        self.token = secrets.token_urlsafe(32)
        self.profile_lock = threading.Lock()
        super().__init__(('127.0.0.1', 0), InitHandler)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.url = f'{self.origin}/#token={self.token}'

    def serve_forever(self, poll_interval=0.05):
        timer = threading.Timer(max(0, self.deadline - time.monotonic()), self.shutdown)
        timer.daemon = True
        timer.start()
        try:
            super().serve_forever(poll_interval=poll_interval)
        finally:
            timer.cancel()
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

    def _reply(self, status, body, content_type='application/json; charset=utf-8', nonce=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        policy = "default-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        if nonce:
            policy += f"; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'"
        self.send_header('Content-Security-Policy', policy)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status, data):
        self._reply(status, json.dumps(data, ensure_ascii=False, allow_nan=False).encode('utf-8'))

    def _error(self, status, message):
        self._json(status, {'error': message})

    def _guard(self, *, write=False, api=False):
        hosts = self.headers.get_all('Host', [])
        if hosts != [f'127.0.0.1:{self.server.server_port}']:
            self._error(403, 'Недопустимый адрес локального помощника.')
            return False
        origins = self.headers.get_all('Origin', [])
        if (write and origins != [self.server.origin]) or (origins and origins != [self.server.origin]):
            self._error(403, 'Запрос разрешён только из окна локального помощника.')
            return False
        if time.monotonic() >= self.server.deadline:
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
                    result = profiles.load_profile(self.server.state_dir)
                self._json(200, result)
            elif self.path == '/api/doctor':
                self._json(200, profiles.doctor())
            else:
                self._error(404, 'Неизвестное действие помощника.')
        except ValueError as error:
            self._error(400, str(error))
        except OSError:
            self._error(500, 'Локальные материалы недоступны. Проверьте путь и права доступа.')

    def do_POST(self):
        if not self._guard(write=True, api=True):
            return
        if self.path not in ('/api/profile', '/api/starter'):
            self._error(404, 'Неизвестное действие помощника.')
            return
        data = self._read_json()
        if data is None or not self._guard(write=True, api=True):
            return
        try:
            if self.path == '/api/starter':
                path = data.get('path')
                if not isinstance(path, str) or not path.strip():
                    raise ValueError('Укажите путь к файлу .v8i или ibases.v8i.')
                result = profiles.read_starter(path)
            else:
                with self.server.profile_lock:
                    result = profiles.save_profile(self.server.state_dir, data)
            self._json(200, result)
        except ValueError as error:
            self._error(400, str(error))
        except OSError:
            self._error(400, 'Не удалось прочитать файл или сохранить профиль. Проверьте путь и права.')


def create_server(state_dir, ttl=900):
    """Bind only to loopback; no browser, sources or remote services are opened."""
    return InitServer(state_dir, ttl)


def run_gui(state_dir, open_browser=False, ttl=900):
    server = create_server(state_dir, ttl=ttl)
    print(json.dumps({'url': server.url}), flush=True)
    try:
        if open_browser:
            webbrowser.open(server.url)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
