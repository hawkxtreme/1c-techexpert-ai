"""Storage actions limited to the current loopback helper and its investigation."""

import os
from pathlib import Path
import re
from threading import Lock

from . import case_retention, export_retention, index_retention, investigation_materials
from . import investigation_retention, investigations, operation_state as fs, retention_policy
from .inputs import InputError


_CLEANUP = {'reports': investigation_retention, 'copies': case_retention,
            'indexes': index_retention, 'working_copies': export_retention}
_POLICIES = {'reports': 'reports', 'copies': 'case-inputs', 'indexes': 'case-indexes',
             'working_copies': 'export-work-copies'}
_PAGE_SIZE = 24


class StorageConflict(InputError):
    """The view or approval must be refreshed before proceeding."""


def setup_context(state, investigation_id):
    if investigation_id is None or investigation_retention.status(state, investigation_id) is not None:
        return None
    return investigations.read_for_display(state, investigation_id)


def _choice(category, policy):
    return dict(revision=policy['revision'], days=policy[retention_policy.CATEGORIES[category][1]])


def _target(row):
    if row.get('status') != 'present':
        return None
    if row['category'] == 'indexes':
        return row['product_id'], row['source_id']
    if os.name == 'nt' and row['category'] == 'copies' and row['product_kind'] == 'case':
        return row['product_id'], Path(row['path']).stem
    if os.name == 'nt' and row['category'] == 'working_copies':
        return row['export_plan_id'],
    return None


def _digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


class Storage:
    def __init__(self, state):
        self.state = state
        self.lock = Lock()
        self.reviewed = None

    def settings(self, investigation_id):
        policies = {key: _choice(key, retention_policy.load(self.state, category=key))
                    for key in retention_policy.CATEGORIES}
        return dict(state_dir=str(fs.safe(self.state)), investigation_id=investigation_id, policies=policies)

    def request(self, investigation_id, request):
        if not self.lock.acquire(blocking=False):
            raise StorageConflict('Дождитесь завершения текущего действия с хранилищем.')
        try:
            action = request.get('action')
            data = {key: value for key, value in request.items() if key != 'action'}
            if action == 'save_policy':
                return self._save_policy(data)
            if action not in ('materials', 'preview', 'apply'):
                raise InputError('Неизвестное действие с хранилищем.')
            if not investigation_id:
                raise InputError('Откройте настройку источников из сохранённого расследования.')
            if action == 'materials':
                return self._materials(investigation_id, data)
            if action == 'preview':
                return self._preview(investigation_id, data)
            return self._apply(investigation_id, data)
        finally:
            self.lock.release()

    def _save_policy(self, data):
        category = data.get('category')
        if (set(data) != {'category', 'revision', 'days'} or type(category) is not str
                or category not in retention_policy.CATEGORIES):
            raise InputError('Выберите срок хранения для одной категории.')
        _, field = retention_policy.CATEGORIES[category]
        try:
            saved = retention_policy.save(self.state, dict(schema_version=1, **{field: data['days']}),
                                          expected_revision=data['revision'], category=category)
        except retention_policy.PolicyRevisionConflict as error:
            raise StorageConflict('Срок уже изменён. Обновите настройки хранения.') from error
        return _choice(category, saved)

    def _revision(self, investigation_id, expected):
        retired = investigation_retention.status(self.state, investigation_id)
        current = retired['head_revision'] if retired else investigations._read_head(self.state, investigation_id)['revision']
        if current != expected:
            raise StorageConflict('Расследование изменилось. Обновите материалы перед действием.')

    def _inventory(self, investigation_id, category, offset, limit, expected):
        if category is not None and (type(category) is not str or category not in investigation_materials.CATEGORIES):
            raise InputError('Выберите категорию материалов.')
        if expected is not None and (type(expected) is not int or not 1 <= expected <= 1000):
            raise InputError('Некорректная ревизия отображаемых материалов.')
        value = investigation_materials.view(self.state, investigation_id, category=category, offset=offset, limit=limit)
        if expected is not None and value['head_revision'] != expected:
            raise StorageConflict('Расследование изменилось. Обновите материалы перед действием.')
        return value

    def _materials(self, investigation_id, data):
        if set(data) - {'category', 'offset', 'revision'}:
            raise InputError('Недопустимое поле запроса материалов.')
        offset = data.get('offset', 0)
        category = data.get('category')
        value = self._inventory(investigation_id, category, offset, _PAGE_SIZE, data.get('revision'))
        if 'entries' in value:
            value['previous_offset'] = max(0, offset - _PAGE_SIZE) if offset else None
        for position, row in enumerate(value.get('entries', []), offset):
            if category is not None and _target(row):
                row['cleanup_selection'] = dict(category=category, offset=position, revision=value['head_revision'],
                                                row_sha256=fs.digest(row))
        return value

    def _preview(self, investigation_id, data):
        self.reviewed = None
        category = data.get('category')
        base = {'category', 'revision', 'use_policy'}
        if (type(category) is not str or category not in _CLEANUP or type(data.get('revision')) is not int
                or type(data.get('use_policy')) is not bool
                or set(data) != (base if category == 'reports' else base | {'offset', 'row_sha256'})):
            raise InputError('Выберите материалы и откройте предпросмотр очистки.')
        revision = data['revision']
        if category == 'reports':
            self._revision(investigation_id, revision)
            reviewed = investigation_retention.preview(self.state, investigation_id, use_policy=data['use_policy'])
            if reviewed['status'] == 'cleanup_pending':
                reviewed = investigation_retention.pending_review(self.state, investigation_id) or reviewed
            if reviewed['status'] == 'ready' and reviewed['plan']['head']['revision'] != revision:
                raise StorageConflict('Отчёты изменились. Обновите материалы.')
        else:
            if not _digest(data['row_sha256']):
                raise InputError('Некорректный идентификатор отображаемого материала.')
            inventory = self._inventory(investigation_id, category, data['offset'], 1, revision)
            rows = inventory.get('entries', [])
            target = _target(rows[0]) if rows else None
            if target is None or fs.digest(rows[0]) != data['row_sha256']:
                raise StorageConflict('Материал изменился или недоступен в этом расследовании. Обновите список.')
            reviewed = _CLEANUP[category].preview(self.state, *target, use_policy=data['use_policy'])
        if reviewed['status'] != 'ready':
            return dict(category=category, status=reviewed['status'])
        plan = reviewed['plan']
        digest = reviewed['plan_sha256']
        self.reviewed = investigation_id, category, revision, plan, digest
        summary = dict(status='ready', category=category, plan_sha256=digest, logical_bytes=reviewed['logical_bytes'])
        if plan['policy'] is not None:
            summary['policy'] = _choice(_POLICIES[category], plan['policy'])
        if category == 'reports':
            return dict(summary, path=plan['path'], report_revisions=revision, file_count=len(plan['files']),
                        attached_products=len(plan['attached_products']), operations=plan['operation_references'],
                        resuming=reviewed.get('resuming', False))
        summary['path'] = plan['file']['path']
        if category == 'copies':
            summary['impact'] = plan['impact']
        return summary

    def _apply(self, investigation_id, data):
        if set(data) != {'plan_sha256'} or not _digest(data['plan_sha256']):
            raise InputError('Требуется подтверждение точного плана очистки.')
        reviewed = self.reviewed
        if reviewed is None or reviewed[0] != investigation_id or reviewed[-1] != data['plan_sha256']:
            raise StorageConflict('Сначала откройте актуальный предпросмотр очистки в этой вкладке.')
        _, category, revision, plan, digest = reviewed
        if category == 'reports':
            self._revision(investigation_id, revision)
            result = investigation_retention.apply(self.state, plan, expected_sha256=digest)
        else:
            with investigation_retention.writer(self.state, investigation_id):
                self._revision(investigation_id, revision)
                result = _CLEANUP[category].apply(self.state, plan, expected_sha256=digest)
        return dict(category=category, status=result['status'], plan_sha256=digest,
                    logical_bytes_removed=result.get('logical_bytes_removed'))
