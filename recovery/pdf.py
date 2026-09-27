"""Extract and merge vector payloads; restore links and page labels."""
import copy
import json
import re
import shutil
import subprocess
from .common import BuildError, encoded


def run(command, timeout=120):
    executable = shutil.which(command[0])
    if executable is None:
        raise BuildError('Required shadow tool unavailable: ' + command[0])
    try:
        result = subprocess.run([executable] + list(map(str, command[1:])),
                                capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError('Shadow tool failed: ' + str(exc)) from exc
    if result.returncode:
        raise BuildError('Shadow tool failed: ' + result.stderr.decode(errors='replace')[-1600:])
    return result.stdout


def _pdf_json(path):
    return json.loads(run(['qpdf', '--json', '--json-key=qpdf', '--json-key=pages',
                           '--json-stream-data=none', path]))


def _dereference(objects, value):
    if isinstance(value, str) and re.fullmatch(r'[0-9]+ [0-9]+ R', value):
        return objects['obj:' + value]['value']
    return value


def _real_destinations(data):
    """pdfTeX's missing-target substitutes are bare /Fit arrays; omit them."""
    objects = data['qpdf'][1]
    value = lambda obj: _dereference(objects, obj)
    catalog = value(objects['trailer']['value']['/Root'])
    names = value(catalog.get('/Names', {}))
    pending = [names.get('/Dests', {})]
    seen = set()
    result = {}
    while pending:
        node = pending.pop()
        if isinstance(node, str):
            if node in seen:
                raise BuildError('Cyclic PDF destination name tree')
            seen.add(node)
        node = value(node)
        entries = node.get('/Names', [])
        if len(entries) % 2:
            raise BuildError('Malformed destination name tree')
        for index in range(0, len(entries), 2):
            destination = value(entries[index + 1])
            if isinstance(destination, dict) and '/D' in destination:
                result[entries[index]] = destination['/D']
        pending.extend(node.get('/Kids', []))
    return result


def _named_links(data):
    pending = [data['qpdf'][1]]
    names = set()
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            destination = item.get('/D') if item.get('/S') == '/GoTo' else item.get('/Dest')
            if isinstance(destination, str) and destination.startswith(('u:', 'b:')):
                names.add(destination)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return names


def _merge_payloads(payloads, plan, destination, temporary, identity=None):
    """Merge selected pages and rebuild global destinations, labels and links."""
    first = payloads[plan['shadows'][0]['id']]
    merged = temporary / 'assembled-before-navigation.pdf'
    command = ['qpdf', first, '--pages']
    for step in plan['assembly']:
        command += [payloads[step['shadow']], str(step['page'])]
    command += ['--', merged]
    run(command)
    result = _pdf_json(merged)
    final_pages = [page['object'] for page in result['pages']]
    if len(final_pages) != plan['page_count']:
        raise BuildError('Assembled page count differs from the route')
    destinations = {}
    for shadow in plan['shadows']:
        source = _pdf_json(payloads[shadow['id']])
        page_slots = {page['object']: index for index, page in enumerate(source['pages'])}
        for name, value in _real_destinations(source).items():
            if not isinstance(value, list) or not value or value[0] not in page_slots:
                raise BuildError('Destination does not address a shadow page: ' + name)
            canonical_page = shadow['pages'][page_slots[value[0]]]
            target = [final_pages[canonical_page - 1]] + value[1:]
            if name in destinations and destinations[name] != target:
                raise BuildError('Conflicting actual PDF destinations: ' + name)
            destinations[name] = target
    objects = result['qpdf'][1]
    root_ref = objects['trailer']['value']['/Root']
    catalog = copy.deepcopy(_dereference(objects, root_ref))
    names = copy.deepcopy(_dereference(objects, catalog.get('/Names', {})))
    names['/Dests'] = {'/Names': [item for name in sorted(destinations)
                                for item in (name, destinations[name])]}
    catalog['/Names'] = names
    catalog['/OpenAction'] = [final_pages[0], '/Fit']
    catalog['/PageLabels'] = {'/Nums': [0, {'/S': '/r', '/St': 1},
                                       plan['frontmatter_pages'], {'/S': '/D', '/St': 1}]}
    patch = {'qpdf': [{'jsonversion': 2}, {'obj:' + root_ref: {'value': catalog}}]}
    if identity:
        info_ref = objects['trailer']['value'].get('/Info')
        if not isinstance(info_ref, str):
            raise BuildError('Expected the TeX PDF to retain its document information')
        info = copy.deepcopy(_dereference(objects, info_ref))
        for key, value in identity.items():
            info['/' + key] = 'u:' + value
        patch['qpdf'][1]['obj:' + info_ref] = {'value': info}
    patch_path = temporary / 'navigation.json'
    patch_path.write_bytes(encoded(patch))
    run(['qpdf', merged, '--update-from-json=' + str(patch_path), destination])
    run(['qpdf', '--check', destination])
    final_data = _pdf_json(destination)
    missing = _named_links(final_data) - set(destinations)
    if missing:
        raise BuildError('Unresolved assembled PDF destinations: ' + ', '.join(sorted(missing)[:10]))
    return {'named_destinations': len(destinations), 'named_links_resolve': True,
            'page_count': len(final_pages)}
