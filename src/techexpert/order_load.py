"""Evidence calculations for the controlled Windows/file-mode order workload.

Hashes bind immutable artifacts; runner statements remain runner attestations,
not independent authentication. Modes never select a cause or expected HTTP
count. Request interval sums are observations, not job duration or job wait.
"""
import csv
import hashlib
import io
import json
import ntpath
import re
import uuid
from datetime import datetime, timezone


VERSION = '8.3.27.1989'
REVISION = 'sc01-catalog-v1'
MAX_BYTES = 1024 * 1024
MAX_ROWS = 1000
MAX_CALLS = 10000
MAX_INT = 2 ** 63 - 1
BUSINESS_FIELDS = ('order_id', 'sku', 'qty', 'price', 'amount', 'catalog_revision')


class _Issue(ValueError):
    pass


def _obj(value):
    if not isinstance(value, dict):
        raise _Issue('expected_object')
    return value


def _list(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise _Issue('invalid_or_excessive_list')
    return value


def _text(value, maximum=128):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum or
            any(char in value for char in '\x00\r\n')):
        raise _Issue('invalid_text_field')
    return value


def _int(value, minimum=0, maximum=MAX_INT):
    if type(value) is not int or not minimum <= value <= maximum:
        raise _Issue('integer_field_required')
    return value


def _uuid(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value):
        raise _Issue('invalid_uuid')
    parsed = uuid.UUID(value)
    if not parsed.int:
        raise _Issue('zero_uuid')
    return str(parsed)


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise _Issue('invalid_sha256')
    return value.lower()


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError, UnicodeError) as error:
        raise _Issue('invalid_json_value') from error


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _json(data):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _Issue('duplicate_json_key')
            result[key] = value
        return result

    def nonfinite(_):
        raise _Issue('nonfinite_json_number')

    try:
        return _obj(json.loads(data.decode('utf-8-sig'), object_pairs_hook=object_pairs, parse_constant=nonfinite))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise _Issue(str(error) if isinstance(error, _Issue) else 'invalid_json_document') from error


def _path(value):
    value = _text(value, 4096)
    drive, tail = ntpath.splitdrive(value)
    if not drive or not tail or not ntpath.isabs(value):
        raise _Issue('absolute_windows_database_path_required')
    return ntpath.normcase(ntpath.normpath(value))


def _bytes(source, maximum=MAX_BYTES):
    data = source.get('data')
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise _Issue('source_bytes_missing_or_excessive')
    if hashlib.sha256(data).hexdigest() != _hash(source.get('sha256')):
        raise _Issue('source_hash_mismatch')
    if 'size' in source and _int(source['size'], 1, maximum) != len(data):
        raise _Issue('source_size_mismatch')
    return data


def _reference(source, data):
    return dict(id=source['id'] + ':1', source=source['id'], sha256=_hash(source['sha256']),
                line=1, end_line=max(1, len(data.splitlines())), byte_start=0, byte_end=len(data))


def _check_ref(ref, expected):
    ref = _obj(ref)
    if (ref.get('id') != expected['id'] or ref.get('source') != expected['source'] or
            _hash(ref.get('sha256')) != expected['sha256']):
        raise _Issue('evidence_reference_mismatch')
    for key in ('line', 'byte_start', 'byte_end'):
        if key in ref and (type(ref[key]) is not int or ref[key] != expected[key]):
            raise _Issue('evidence_position_mismatch')


def _read(source, maximum=MAX_BYTES):
    data = _bytes(source, maximum)
    ref = _reference(source, data)
    if 'evidence' in source:
        _check_ref(source['evidence'], ref)
    return data, ref


def _refs(*refs):
    result, seen = [], set()
    for ref in refs:
        key = (ref['id'], ref['sha256'])
        if key not in seen:
            result.append(ref)
            seen.add(key)
    return result


def _one(sources, format):
    found = [source for source in sources.values() if source.get('format') == format]
    if len(found) != 1:
        raise _Issue('missing_or_duplicate_' + format)
    return found[0]


def _identity(bundle, report):
    sources = {}
    for source in _list(_obj(bundle).get('sources'), 32):
        source = _obj(source)
        key = _text(source.get('id'), 256)
        if key in sources:
            raise _Issue('duplicate_source_id')
        sources[key] = source
    correlation = _obj(_obj(report).get('job_correlation'))
    life, link = _obj(correlation.get('job_lifecycle')), _obj(correlation.get('native_link'))
    if life.get('status') != 'established' or link.get('status') != 'established':
        raise _Issue('verified_lifecycle_and_native_identity_required')
    identity = _obj(link.get('identity'))
    job, nonce = _uuid(life.get('job_uuid')), _uuid(identity.get('nonce'))
    if _uuid(identity.get('job_uuid')) != job or identity.get('process_label') != '1cv8':
        raise _Issue('job_identity_or_process_conflict')
    native = sources.get(_text(identity.get('source'), 256))
    if not isinstance(native, dict) or native.get('format') != '1c-tj-text-v1':
        raise _Issue('native_identity_source_missing')
    raw, native_ref = _read(native, 16 * MAX_BYTES)
    if _hash(identity.get('sha256')) != native_ref['sha256']:
        raise _Issue('native_identity_hash_conflict')
    if _obj(native.get('profile')).get('platform_version') != VERSION:
        raise _Issue('unsupported_platform_profile')
    database = _path(identity.get('database_file'))
    docs, refs = {}, {}
    for wrapped in _list(bundle.get('lifecycle_documents'), 3):
        wrapped = _obj(wrapped)
        role = wrapped.get('role')
        if role not in ('controller', 'worker_enter', 'worker_exit') or role in docs:
            raise _Issue('missing_or_duplicate_runtime_role')
        evidence = _obj(wrapped.get('evidence'))
        source = sources.get(_text(evidence.get('source'), 256))
        if not isinstance(source, dict) or source.get('format') != '1c-job-runtime-v1':
            raise _Issue('runtime_source_missing')
        data, ref = _read(source)
        _check_ref(evidence, ref)
        parsed = _json(data)
        if _canonical(wrapped.get('data')) != _canonical(parsed):
            raise _Issue('runtime_data_not_matching_snapshot')
        if (type(parsed.get('schema')) is not int or parsed['schema'] != 1 or
                parsed.get('origin') != 'controlled_real_background_job'):
            raise _Issue('unsupported_runtime_origin')
        if _uuid(parsed.get('job_uuid')) != job or _uuid(parsed.get('nonce')) != nonce:
            raise _Issue('mixed_runtime_runs')
        docs[role], refs[role] = parsed, ref
    if set(docs) != {'controller', 'worker_enter', 'worker_exit'}:
        raise _Issue('all_runtime_roles_required')
    batch = _uuid(docs['controller'].get('batch_id'))
    for data in docs.values():
        if 'batch_id' in data and _uuid(data['batch_id']) != batch:
            raise _Issue('mixed_runtime_batches')
    proof_refs = _list(life.get('evidence'), 32)
    body_refs = _list(_obj(link.get('body')).get('runtime_evidence'), 32)
    for role, ref in refs.items():
        candidates = [r for r in proof_refs if isinstance(r, dict) and r.get('id') == ref['id']]
        if len(candidates) != 1:
            raise _Issue('lifecycle_snapshot_not_in_verified_report')
        _check_ref(candidates[0], ref)
        if role != 'controller':
            candidates = [r for r in body_refs if isinstance(r, dict) and r.get('id') == ref['id']]
            if len(candidates) != 1:
                raise _Issue('worker_snapshot_not_in_verified_native_link')
            _check_ref(candidates[0], ref)
    return sources, docs, refs, dict(job_uuid=job, nonce=nonce, batch_id=batch, database_file=database), native_ref


def _csv(data):
    try:
        reader = csv.reader(io.StringIO(data.decode('utf-8-sig'), newline=''), strict=True)
        if next(reader, None) != ['order_id', 'sku', 'qty']:
            raise _Issue('orders_csv_header_mismatch')
        rows, ids = [], set()
        for row in reader:
            if len(rows) >= MAX_ROWS or len(row) != 3:
                raise _Issue('orders_csv_row_limit_or_shape')
            order, sku, qty = row
            order, sku = _text(order), _text(sku)
            if not re.fullmatch(r'[1-9][0-9]{0,18}', qty) or order in ids:
                raise _Issue('orders_csv_quantity_or_duplicate_id')
            rows.append(dict(order_id=order, sku=sku, qty=_int(int(qty), 1)))
            ids.add(order)
        if not rows:
            raise _Issue('empty_orders_csv')
        return rows
    except (UnicodeError, csv.Error) as error:
        raise _Issue('invalid_orders_csv') from error


def _same_run(data, identity):
    for key in ('job_uuid', 'nonce', 'batch_id'):
        if _uuid(data.get(key)) != identity[key]:
            raise _Issue('artifact_run_identity_mismatch')


def _service(sources, identity):
    raw, ref = _read(_one(sources, 'sc01-http-service-v1'))
    service = _json(raw)
    if (type(service.get('schema')) is not int or service['schema'] != 1 or
            service.get('origin') != 'controlled_loopback_http_service'):
        raise _Issue('unsupported_http_service_origin')
    _same_run(service, identity)
    _uuid(service.get('service_instance'))
    if service.get('host') != '127.0.0.1':
        raise _Issue('service_is_not_controlled_loopback')
    _int(service.get('port'), 1, 65535)
    _int(service.get('delay_ms'), 0, 60000)
    if service.get('catalog_revision') != REVISION:
        raise _Issue('unsupported_catalog_revision')
    catalog = _obj(service.get('catalog'))
    if not 1 <= len(catalog) <= MAX_ROWS:
        raise _Issue('catalog_size_limit')
    for sku, price in catalog.items():
        _text(sku)
        _int(price)
    _list(service.get('requests'), MAX_CALLS)
    return service, ref


def _observed_computer_name(docs):
    """A consistent runtime label, never a physical node identifier or alias."""
    def normalize(value):
        try:
            value = _text(value, 255)
            if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise _Issue('invalid_computer_name')
            return _text(value.casefold(), 255)
        except _Issue as error:
            raise _Issue('runtime_computer_name_missing_or_invalid') from error

    names = {normalize(docs[role].get('computer_name'))
             for role in ('controller', 'worker_enter', 'worker_exit')}
    final = docs['controller'].get('final_job_snapshot')
    if isinstance(final, dict) and 'computer_name' in final:
        names.add(normalize(final['computer_name']))
    if len(names) != 1:
        raise _Issue('runtime_computer_names_conflict')
    return next(iter(names))


def _capture(sources, identity, input_sha, service, observed_computer_name):
    if observed_computer_name is None:
        raise _Issue('observed_runtime_computer_name_not_verified')
    raw, capture_ref = _read(_one(sources, 'sc01-run-capture-v1'))
    capture = _json(raw)
    if (type(capture.get('schema')) is not int or capture['schema'] != 1 or
            capture.get('origin') != 'controlled_isolated_1c_runner'):
        raise _Issue('unsupported_runner_capture_origin')
    _same_run(capture, identity)
    if capture.get('platform_version') != VERSION or _path(capture.get('database_file')) != identity['database_file']:
        raise _Issue('capture_database_or_platform_mismatch')
    seed = _hash(capture.get('database_seed_sha256'))
    try:
        service_module_sha256 = _hash(capture.get('service_module_sha256'))
    except _Issue as error:
        raise _Issue('service_module_sha256_missing_or_invalid') from error
    if _hash(capture.get('database_before_sha256')) != seed:
        raise _Issue('database_not_restored_to_declared_seed')
    code, code_ref = _read(_one(sources, '1c-source-text-v1'))
    try:
        code.decode('utf-8-sig')
    except UnicodeError as error:
        raise _Issue('invalid_utf8_source_module') from error
    if _hash(capture.get('module_sha256')) != code_ref['sha256'] or _hash(capture.get('input_sha256')) != input_sha:
        raise _Issue('capture_module_or_input_hash_mismatch')
    if _int(capture.get('process_exit_code'), 0) != 0 or capture.get('natural_exit') is not True:
        raise _Issue('controlled_process_not_successfully_closed')
    if 'service_instance' in capture:
        if service is None or _uuid(capture['service_instance']) != _uuid(service['service_instance']):
            raise _Issue('capture_service_instance_mismatch')
    return dict(status='verified', provenance='capture_runner_attested', database_seed_sha256=seed,
                database_before_sha256=seed, module_sha256=code_ref['sha256'], input_sha256=input_sha,
                service_module_sha256=service_module_sha256, observed_computer_name=observed_computer_name,
                computer_name_basis='consistent_runtime_observed_label_not_physical_node_id',
                evidence=[capture_ref, code_ref])


def _projection(rows):
    projection = []
    for row in _list(rows, MAX_ROWS):
        row = _obj(row)
        if set(row) != set(BUSINESS_FIELDS):
            raise _Issue('business_row_fields_mismatch')
        projection.append(dict(order_id=_text(row['order_id']), sku=_text(row['sku']),
            qty=_int(row['qty'], 1), price=_int(row['price']), amount=_int(row['amount'], 0, MAX_INT * MAX_INT),
            catalog_revision=_text(row['catalog_revision'])))
    return sorted(projection, key=lambda row: tuple(row[key] for key in BUSINESS_FIELDS))


def _results(input_rows, service, controller, workload, evidence):
    catalog = service['catalog']
    expected = []
    for row in input_rows:
        if row['sku'] not in catalog:
            raise _Issue('input_sku_missing_from_catalog')
        price = catalog[row['sku']]
        expected.append(dict(row, price=price, amount=price * row['qty'], catalog_revision=REVISION))
    expected = _projection(expected)
    actual = _projection(controller.get('result_rows'))
    written = _int(workload.get('written_count'), 0, MAX_ROWS)
    result = dict(status='matches_expected', expected_count=len(expected), actual_count=len(actual),
                  written_count=written, expected_sha256=_digest(expected), actual_sha256=_digest(actual),
                  mismatch_count=0, mismatches=[], evidence=evidence, projection='sc01-business-rows-v1')

    def mismatch(order, field, reason):
        result['mismatch_count'] += 1
        if len(result['mismatches']) < 20:
            result['mismatches'].append(dict(order_id=order, field=field, reason=reason))

    expected_by_id, seen = {row['order_id']: row for row in expected}, set()
    for row in actual:
        order = row['order_id']
        if order in seen:
            mismatch(order, 'order_id', 'duplicate')
        seen.add(order)
        if order not in expected_by_id:
            mismatch(order, 'order_id', 'unexpected')
        else:
            for field in BUSINESS_FIELDS:
                if row[field] != expected_by_id[order][field]:
                    mismatch(order, field, 'different')
    for order in expected_by_id.keys() - seen:
        mismatch(order, 'order_id', 'missing')
    if written != len(expected) or written != len(actual):
        mismatch(None, 'written_count', 'different')
    if result['mismatch_count']:
        result['status'] = 'mismatch'
    return result


def _utc(value):
    try:
        stamp = datetime.fromisoformat(_text(value, 64))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError('offset')
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise _Issue('invalid_service_UTC_timestamp') from error


def _calls(workload, service, identity, evidence, load_bounds):
    clients, servers = {}, {}
    for call in _list(workload.get('http_calls'), MAX_CALLS):
        call = _obj(call)
        rid = _uuid(call.get('request_id'))
        if rid in clients or _uuid(call.get('response_request_id')) != rid:
            raise _Issue('client_request_or_response_id_conflict')
        for field in ('job_uuid', 'nonce', 'batch_id'):
            if field in call and _uuid(call[field]) != identity[field]:
                raise _Issue('client_call_run_identity_conflict')
        _text(call.get('sku'))
        if _int(call.get('status'), 100, 599) != 200 or call.get('catalog_revision') != REVISION:
            raise _Issue('client_response_status_or_revision_conflict')
        start, finish = _int(call.get('started_utc_ms')), _int(call.get('finished_utc_ms'))
        if finish < start or (load_bounds is not None and not load_bounds[0] <= start <= finish <= load_bounds[1]):
            raise _Issue('client_request_time_conflict')
        clients[rid] = call
    for request in service['requests']:
        request = _obj(request)
        rid = _uuid(request.get('request_id'))
        if rid in servers:
            raise _Issue('duplicate_server_request_id')
        _same_run(request, identity)
        if _int(request.get('status'), 100, 599) != 200 or request.get('completed') is not True:
            raise _Issue('server_request_not_completed_successfully')
        sku = _text(request.get('sku'))
        if (sku not in service['catalog'] or _int(request.get('price')) != service['catalog'][sku] or
                request.get('catalog_revision') != REVISION):
            raise _Issue('server_price_or_revision_conflict')
        start, finish = _int(request.get('started_monotonic_ns')), _int(request.get('finished_monotonic_ns'))
        elapsed = _int(request.get('elapsed_us'))
        if finish < start or elapsed != (finish - start) // 1000:
            raise _Issue('server_monotonic_elapsed_conflict')
        if _utc(request.get('finished_utc')) < _utc(request.get('started_utc')):
            raise _Issue('server_UTC_order_conflict')
        if 'response_sha256' in request:
            _hash(request['response_sha256'])
        servers[rid] = request
    if clients.keys() != servers.keys():
        raise _Issue('client_server_request_sets_differ')
    for rid, client in clients.items():
        server = servers[rid]
        if any(client[key] != server[key] for key in ('sku', 'status', 'catalog_revision')):
            raise _Issue('client_server_response_conflict')
        if 'price' in client and _int(client['price']) != server['price']:
            raise _Issue('client_server_price_conflict')
        if 'response_sha256' in client and _hash(client['response_sha256']) != _hash(server.get('response_sha256')):
            raise _Issue('response_body_hash_conflict')
    unique = len({call['sku'] for call in clients.values()})
    return dict(status='verified', count=len(clients), unique_skus=unique, repeated_lookups=len(clients)-unique,
                server_elapsed_seconds=sum(call['elapsed_us'] for call in servers.values()) / 1000000,
                client_elapsed_seconds=sum(call['finished_utc_ms']-call['started_utc_ms'] for call in clients.values()) / 1000,
                service_instance=_uuid(service['service_instance']), evidence=evidence,
                metric_basis='sum_of_request_intervals; not_job_duration_or_wait; no_cross_clock_join')


def analyze_order_load(bundle, report):
    """Return bounded observations, preserving independent component failures."""
    result = dict(status='not_verified', scope='controlled_windows_file_8.3.27.1989', mode=None,
        workload_signature=dict(input_sha256=None, catalog_revision=None, catalog_sha256=None, row_count=None,
            service_profile='sc01-http-service-v1', service_delay_ms=None, database_seed_sha256=None,
            platform_version=VERSION, database_file=None, observed_computer_name=None,
            service_module_sha256=None, evidence=[]),
        result_validation=dict(status='not_verified', expected_count=None, actual_count=None, written_count=None,
            expected_sha256=None, actual_sha256=None, mismatch_count=None, mismatches=[], evidence=[]),
        external_calls=dict(status='not_verified', count=None, unique_skus=None, repeated_lookups=None,
            server_elapsed_seconds=None, client_elapsed_seconds=None, evidence=[]),
        capture_validation=dict(status='not_verified', provenance=None, evidence=[]),
        load_duration_ms=None, load_duration_evidence=[], limitations=[])

    def issue(error, component):
        if len(result['limitations']) < 100:
            result['limitations'].append(dict(code=str(error), component=component))

    try:
        sources, docs, refs, identity, native_ref = _identity(bundle, report)
        raw, csv_ref = _read(_one(sources, 'sc01-orders-csv-v1'))
        rows = _csv(raw)
        workload = _obj(docs['worker_exit'].get('workload'))
        input_sha = csv_ref['sha256']
        if (_hash(workload.get('input_sha256')) != input_sha or
                _hash(docs['controller'].get('input_sha256')) != input_sha):
            raise _Issue('runtime_input_hash_conflict')
        for document in docs.values():
            if 'input_sha256_after' in document and _hash(document['input_sha256_after']) != input_sha:
                raise _Issue('input_changed_during_run')
        if (_int(workload.get('input_rows'), 1, MAX_ROWS) != len(rows) or
                _int(workload.get('unique_skus'), 1, MAX_ROWS) != len({row['sku'] for row in rows})):
            raise _Issue('workload_input_counts_conflict')
        if workload.get('mode') not in ('baseline', 'cached'):
            raise _Issue('unknown_workload_mode')
        result['mode'] = workload['mode']
        signature = result['workload_signature']
        signature.update(input_sha256=input_sha, row_count=len(rows), database_file=identity['database_file'],
                         evidence=_refs(csv_ref, native_ref, refs['controller'], refs['worker_exit']))
    except _Issue as error:
        issue(error, 'identity_and_input')
        return result

    observed_name = None
    try:
        observed_name = _observed_computer_name(docs)
        signature.update(observed_computer_name=observed_name,
                         evidence=_refs(*signature['evidence'], *refs.values()))
    except _Issue as error:
        issue(error, 'observed_computer_name')

    load_bounds = None
    try:
        start, finish = _int(workload.get('load_started_utc_ms')), _int(workload.get('load_finished_utc_ms'))
        if not _int(docs['worker_enter'].get('observed_utc_ms')) <= start <= finish <= _int(docs['worker_exit'].get('observed_utc_ms')):
            raise _Issue('load_bounds_outside_runtime_body')
        load_bounds = (start, finish)
        result.update(load_duration_ms=finish-start, load_duration_evidence=_refs(refs['worker_enter'], refs['worker_exit']))
    except _Issue as error:
        issue(error, 'load_duration')

    service = None
    try:
        service, service_ref = _service(sources, identity)
        controller = docs['controller']
        if 'port' in controller:
            _int(controller['port'], 1, 65535)
        for key in ('host', 'port', 'catalog_revision'):
            if key in controller and controller[key] != service[key]:
                raise _Issue('controller_service_configuration_conflict')
        signature.update(catalog_revision=REVISION, catalog_sha256=_digest(service['catalog']),
                         service_delay_ms=service['delay_ms'], evidence=_refs(*signature['evidence'], service_ref))
    except _Issue as error:
        service = None
        issue(error, 'service')

    try:
        capture = _capture(sources, identity, input_sha, service, observed_name)
        capture['evidence'] = _refs(*capture['evidence'], *refs.values())
        result['capture_validation'] = capture
        signature.update(database_seed_sha256=capture['database_seed_sha256'],
                         service_module_sha256=capture['service_module_sha256'],
                         evidence=_refs(*signature['evidence'], *capture['evidence']))
    except _Issue as error:
        issue(error, 'capture')

    if service is not None:
        try:
            result['result_validation'] = _results(rows, service, docs['controller'], workload,
                _refs(csv_ref, service_ref, refs['controller'], refs['worker_exit']))
        except _Issue as error:
            issue(error, 'business_result')
        try:
            result['external_calls'] = _calls(workload, service, identity,
                _refs(service_ref, refs['controller'], refs['worker_enter'], refs['worker_exit'], native_ref), load_bounds)
        except _Issue as error:
            issue(error, 'external_calls')
    complete = (not result['limitations'] and result['result_validation']['status'] == 'matches_expected' and
                result['external_calls']['status'] == 'verified' and result['capture_validation']['status'] == 'verified')
    result['status'] = 'observed' if complete else 'partial'
    return result
