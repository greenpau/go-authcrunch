#!/usr/bin/env python3
"""Run exhaustive Go test/package shards and verify their CI evidence."""

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from change_tests import ROOT, packages


PORTAL_SHARDS = ('portal-challenges', 'portal-sessions', 'portal-protocols', 'portal-core')
SHARDS = (*PORTAL_SHARDS, 'identity', 'other-server', 'other-providers', 'other-core')
TESTED_FILES = {'coverage.html', 'coverage.out', 'index.html', 'junit.xml', 'run.json',
                'stderr.log', 'summary.json', 'test_output.html', 'test_output.jsonl'}


def partition(graph):
    """Split the large portal package by test; assign other packages once."""
    result = {name: [] for name in SHARDS}
    for name, package in sorted(graph.items()):
        directory = Path(package['Dir']).relative_to(ROOT).as_posix()
        if directory == 'pkg/authn':
            for shard in PORTAL_SHARDS:
                result[shard].append(name)
            continue
        def under(*prefixes):
            return any(directory == prefix or directory.startswith(prefix + '/')
                       for prefix in prefixes)
        if under('pkg/identity'):
            shard = 'identity'
        elif directory == '.' or under('cmd', 'pkg/authclient', 'pkg/httpserver'):
            shard = 'other-server'
        elif under('plugins', 'pkg/idp', 'pkg/ids'):
            shard = 'other-providers'
        else:
            shard = 'other-core'
        result[shard].append(name)
    if any(not group for group in result.values()):
        raise ValueError('Expected nonempty CI package shards')
    return result


def portal_partition(names):
    """Keep top-level tests intact, with exhaustive fallback for new names."""
    if (not names or names != sorted(set(names))
            or any(not re.fullmatch(r'(Test|Example|Fuzz)\w*', name) for name in names)):
        raise ValueError('Invalid portal test inventory')
    groups = {name: [] for name in PORTAL_SHARDS}
    for name in names:
        # Priority is intentional: e.g. OIDC refresh is a session test.
        if 'AuthenticationChallenge' in name:
            shard = 'portal-challenges'
        elif any(word in name for word in ('Refresh', 'Session', 'Cookie')):
            shard = 'portal-sessions'
        elif any(word in name for word in ('OIDC', 'OAuth', 'SAML', 'JWKS', 'PrivateKeys')):
            shard = 'portal-protocols'
        else:
            shard = 'portal-core'
        groups[shard].append(name)
    if any(not group for group in groups.values()):
        raise ValueError('Expected nonempty portal test shards')
    return groups


def inventory(package, output):
    """Run only under the resource guard; ask Go about runnable tests, not source regexes."""
    output.mkdir(parents=True, exist_ok=True)
    # Match the race/coverage build used by tested so the compiled cache is reusable.
    with (output / 'listing.txt').open('w') as stream:
        subprocess.run(['go', 'test', '-mod=readonly', '-race', '-covermode=atomic',
                        '-count=1', '-list=^(Test|Example|Fuzz)', package], cwd=ROOT,
                       stdout=stream, check=True, timeout=300)
    names = sorted(line for line in (output / 'listing.txt').read_text().splitlines()
                   if re.fullmatch(r'(Test|Example|Fuzz)\w*', line))
    portal_partition(names)
    (output / 'tests.json').write_text(json.dumps(names, indent=2) + '\n')


def coverage_directory():
    # Discovery and Make execute in ROOT even when the script is invoked elsewhere.
    return ROOT / Path(os.environ.get('COVERAGE_DIR', '.coverage'))


def directory(shard):
    return coverage_directory() / 'shards' / shard


def run(shard):
    output = directory(shard)
    output.mkdir(parents=True, exist_ok=True)
    selection_path = output / 'selection.json'
    # An early discovery/build/guard failure must invalidate an older successful run.
    selection_path.write_text(json.dumps(dict(shard=shard, complete=False)) + '\n')
    plan = partition(packages())
    selection = dict(schema='authcrunch/ci-selection/v2', shard=shard, complete=False,
                     packages=plan[shard], all_shards=plan)
    pattern = '.'
    if shard in PORTAL_SHARDS:
        discovery = output / 'discovery'
        subprocess.run([sys.executable, str(ROOT / 'assets/scripts/test_guard.py'), 'run',
                        sys.executable, str(Path(__file__).resolve()), 'inventory',
                        plan[shard][0], str(discovery)], cwd=ROOT, check=True,
                       env=dict(os.environ, COVERAGE_DIR=str(discovery)))
        names = json.loads((discovery / 'tests.json').read_text())
        selected = portal_partition(names)[shard]
        selection.update(portal_tests=names, selected_tests=selected)
        # Make expands command-line variables: $$ preserves the final regex anchor.
        pattern = '^(' + '|'.join(selected) + ')$$'
    selection_path.write_text(json.dumps(selection, indent=2) + '\n')
    print(f'Running {shard}: {len(plan[shard])} package(s)', flush=True)
    # Explicit Make arguments override inherited filters, including MAKEFLAGS.
    result = subprocess.run(['make', 'test', 'TEST=' + pattern,
                             'TEST_DIR=' + ' '.join(plan[shard]),
                             'MINIMUM_COVERAGE=1', 'COVERAGE_DIR=' + str(output)], cwd=ROOT)
    selection['complete'] = result.returncode == 0
    selection_path.write_text(json.dumps(selection, indent=2) + '\n')
    return result.returncode if result.returncode >= 0 else 1


def read_events(path):
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def summarize(shard):
    output = directory(shard)
    resource_path = output / 'resource-usage.json'
    resource = json.loads(resource_path.read_text()) if resource_path.exists() else {}
    completed, tests = [], []
    incomplete = ''
    selection_path = output / 'selection.json'
    if selection_path.exists() and not json.loads(selection_path.read_text()).get('complete'):
        incomplete = 'Shard did not complete successfully; reports may be from an earlier attempt.'
    try:
        for event in read_events(output / 'test_output.jsonl'):
            if event.get('Action') not in ('pass', 'fail', 'skip'):
                continue
            item = dict(package=event['Package'], outcome=event['Action'],
                        seconds=event.get('Elapsed', 0))
            if not event.get('Test'):
                completed.append(item)
            elif '/' not in event['Test']:
                tests.append(dict(item, test=event['Test']))
    except (FileNotFoundError, json.JSONDecodeError):
        incomplete = 'Test output is missing or incomplete; inspect the raw evidence.'
    timing = dict(shard=shard, resources=resource, incomplete=incomplete,
                  packages=sorted(completed, key=lambda item: item['seconds'], reverse=True),
                  slowest_tests=sorted(tests, key=lambda item: item['seconds'], reverse=True)[:20])
    output.mkdir(parents=True, exist_ok=True)
    (output / 'timing.json').write_text(json.dumps(timing, indent=2) + '\n')
    lines = [f'### Go tests: {shard}', '',
             f"Guard status: **{resource.get('status', 'unavailable')}**. "
             f"Elapsed: {resource.get('elapsed_seconds', '?')}s. "
             f"Peak memory: {resource.get('peak_memory_mib', '?')} MiB.", '']
    if resource.get('reason') or incomplete:
        lines.extend([resource.get('reason') or incomplete, ''])
    lines.extend(['| Package | Seconds | Result |', '| --- | ---: | --- |'])
    for item in timing['packages'][:10]:
        lines.append(f"| {item['package']} | {item['seconds']:.2f} | {item['outcome']} |")
    text = '\n'.join(lines) + '\n'
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as summary:
            summary.write(text)


def gate():
    """A failed or unexpectedly skipped dependency must fail the stable check."""
    selection = os.environ.get('SELECTION_RESULT')
    mode = os.environ.get('SELECTION_MODE')
    results = [os.environ.get(name) for name in ('GO_RESULT', 'QUALITY_RESULT')]
    if selection != 'success':
        raise ValueError('Test selection did not succeed')
    if mode == 'none' and results == ['skipped', 'skipped']:
        print('No validation required by change/release selection.')
        return
    if mode not in ('full', 'focused') or results != ['success', 'success']:
        raise ValueError(f'Incomplete validation: mode={mode}, Go/quality results={results}')
    print('All Go shards and repository quality gates passed.')


def verify_manifest(output):
    """Keep each downloaded tested generation complete and internally consistent."""
    manifest = json.loads((output / 'manifest.json').read_text())
    if manifest['version'] != 1 or manifest['algorithm'] != 'sha256':
        raise ValueError('Unsupported tested manifest')
    names = set()
    for entry in manifest['files']:
        name = entry['name']
        if name in names or Path(name).name != name or name in ('', '.', '..'):
            raise ValueError('Invalid tested artifact name')
        names.add(name)
        path = output / name
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if path.stat().st_size != entry['size'] or digest.hexdigest() != entry['sha256']:
            raise ValueError(f'Tested artifact integrity mismatch: {name}')
    if not TESTED_FILES <= names:
        raise ValueError('Incomplete tested manifest')


def merge():
    """Verify full execution and sum counters for intentional portal overlap only."""
    base = coverage_directory()
    plan = None
    portal_package = None
    portal_tests = None
    portal_blocks = None
    blocks = {}
    mode = None
    for shard in SHARDS:
        output = directory(shard)
        selected = json.loads((output / 'selection.json').read_text())
        if not selected['complete']:
            raise ValueError(f'Unfinished shard execution: {shard}')
        current_plan = selected['all_shards']
        if (selected['schema'] != 'authcrunch/ci-selection/v2'
                or set(current_plan) != set(SHARDS)
                or any(not group or group != sorted(set(group))
                       for group in current_plan.values())):
            raise ValueError('Incomplete shard plan')
        if plan is not None and plan != current_plan:
            raise ValueError('Shards were not produced from the same package plan')
        plan = current_plan
        if portal_package is None:
            if any(len(plan[name]) != 1 for name in PORTAL_SHARDS):
                raise ValueError('Portal test shards must each select one package')
            portal_package = plan[PORTAL_SHARDS[0]][0]
            if any(plan[name] != [portal_package] for name in PORTAL_SHARDS):
                raise ValueError('Portal test shards must share the same package')
            others = [package for name in SHARDS if name not in PORTAL_SHARDS
                      for package in plan[name]]
            if len(set(others)) != len(others) or portal_package in others:
                raise ValueError('Unexpected package overlap')
        if selected['shard'] != shard or selected['packages'] != plan[shard]:
            raise ValueError(f'Package selection mismatch for {shard}')
        expected_tests = None
        if shard in PORTAL_SHARDS:
            names = selected['portal_tests']
            discovery = output / 'discovery'
            if (json.loads((discovery / 'resource-usage.json').read_text())['status'] != 'passed'
                    or json.loads((discovery / 'tests.json').read_text()) != names):
                raise ValueError(f'Incomplete portal discovery for {shard}')
            expected_tests = portal_partition(names)[shard]
            if selected['selected_tests'] != expected_tests:
                raise ValueError(f'Incorrect portal test selection for {shard}')
            if portal_tests is not None and portal_tests != names:
                raise ValueError('Portal shards disagree about the test inventory')
            portal_tests = names
        verify_manifest(output)
        execution = json.loads((output / 'run.json').read_text())
        resource = json.loads((output / 'resource-usage.json').read_text())
        if (execution['exit_code'] != 0 or not execution['capture_complete']
                or not execution['child_started'] or resource['status'] != 'passed'):
            raise ValueError(f'Unsuccessful or incomplete evidence for {shard}')
        terminals, test_terminals = {}, set()
        for event in read_events(output / 'test_output.jsonl'):
            if event.get('Action') == 'fail':
                raise ValueError(f'Failed test evidence for {shard}')
            if not event.get('Test') and event.get('Action') in ('pass', 'skip'):
                name = event['Package']
                if name in terminals:
                    raise ValueError(f'Duplicate package execution: {name}')
                terminals[name] = event['Action']
            if (expected_tests is not None and event.get('Test')
                    and '/' not in event['Test'] and event.get('Action') in ('pass', 'skip')):
                name = event['Test']
                if event['Package'] != portal_package or name in test_terminals:
                    raise ValueError(f'Unexpected or duplicate portal test: {name}')
                test_terminals.add(name)
        if set(terminals) != set(plan[shard]):
            raise ValueError(f'Not every selected package completed in {shard}')
        if expected_tests is not None and test_terminals != set(expected_tests):
            raise ValueError(f'Not every selected portal test completed exactly once in {shard}')
        shard_blocks = {}
        with (output / 'coverage.out').open(encoding='utf-8') as profile:
            header = profile.readline().strip()
            if header != 'mode: atomic' or (mode is not None and mode != header):
                raise ValueError('Expected race-enabled atomic coverage profiles')
            mode = header
            for line in profile:
                block, statements, count = line.split()
                statements, count = int(statements), int(count)
                owner = block.rsplit(':', 1)[0].rsplit('/', 1)[0]
                if (statements < 0 or count < 0 or block in shard_blocks
                        or owner not in plan[shard]):
                    raise ValueError(f'Invalid or overlapping coverage block: {block}')
                shard_blocks[block] = statements
                if block in blocks:
                    if (shard not in PORTAL_SHARDS or owner != portal_package
                            or statements != blocks[block][0]):
                        raise ValueError(f'Unexpected coverage overlap: {block}')
                    count += blocks[block][1]
                blocks[block] = (statements, count)
        if shard in PORTAL_SHARDS:
            if not shard_blocks or (portal_blocks is not None and portal_blocks != shard_blocks):
                raise ValueError('Portal coverage profiles have different source blocks')
            portal_blocks = shard_blocks
    all_packages = {name for group in plan.values() for name in group}
    total = sum(statements for statements, _ in blocks.values())
    covered = sum(statements for statements, count in blocks.values() if count > 0)
    if not total or covered * 100 < total:
        raise ValueError('Combined coverage is below the 1 percent nonempty-profile policy')
    summary = dict(schema='authcrunch/ci-coverage/v2', packages=len(all_packages),
                   portal_tests=len(portal_tests),
                   shards=plan, covered=covered, statements=total, percent=100 * covered / total)
    # Shard manifests stay intact. This is an aggregate, not a fabricated tested run.
    output = base / 'combined'
    output.mkdir(parents=True, exist_ok=True)
    profile = mode + '\n' + ''.join(
        f'{block} {statements} {count}\n' for block, (statements, count) in sorted(blocks.items()))
    (output / 'coverage.out').write_text(profile)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    links = ''.join(f'<li><a href="../shards/{name}/index.html">{html.escape(name)}</a>'
                    f' ({len(plan[name])} packages)</li>' for name in SHARDS)
    (output / 'index.html').write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>AuthCrunch CI coverage</title>'
        '<h1>AuthCrunch CI coverage</h1>'
        f'<p>{len(all_packages)} packages passed; {covered}/{total} statements covered '
        f'({summary["percent"]:.2f}%).</p><ul>{links}</ul>'
        '<p><a href="coverage.out">Combined Go coverage profile</a></p></html>\n')
    text = f"Full suite: {len(all_packages)} packages; combined coverage {summary['percent']:.2f}%.\n"
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as step:
            step.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('matrix')
    commands.add_parser('plan')
    listing = commands.add_parser('inventory')
    listing.add_argument('package')
    listing.add_argument('output', type=Path)
    for command in ('run', 'summarize'):
        commands.add_parser(command).add_argument('shard', choices=SHARDS)
    commands.add_parser('gate')
    commands.add_parser('merge')
    args = parser.parse_args()
    if args.command == 'matrix':
        print(json.dumps(dict(include=[dict(shard=name, cache_group=name.split('-')[0])
                                       for name in SHARDS])))
    elif args.command == 'inventory':
        inventory(args.package, args.output)
    elif args.command == 'plan':
        print(json.dumps(partition(packages()), indent=2))
    elif args.command == 'run':
        return run(args.shard)
    elif args.command == 'summarize':
        summarize(args.shard)
    elif args.command == 'gate':
        gate()
    else:
        merge()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'CI tests: {error}', file=sys.stderr)
        sys.exit(1)
