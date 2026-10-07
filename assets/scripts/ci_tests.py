#!/usr/bin/env python3
"""Run exhaustive, disjoint Go package shards and verify their CI evidence."""

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import subprocess
import sys

from change_tests import ROOT, packages


SHARDS = ('portal', 'identity', 'other')
TESTED_FILES = {'coverage.html', 'coverage.out', 'index.html', 'junit.xml', 'run.json',
                'stderr.log', 'summary.json', 'test_output.html', 'test_output.jsonl'}


def partition(graph):
    """Discover new packages automatically; keep the two slow suites isolated."""
    result = {name: [] for name in SHARDS}
    for name, package in sorted(graph.items()):
        directory = Path(package['Dir']).relative_to(ROOT).as_posix()
        shard = 'other'
        for owner, prefix in (('portal', 'pkg/authn'), ('identity', 'pkg/identity')):
            if directory == prefix or directory.startswith(prefix + '/'):
                shard = owner
                break
        result[shard].append(name)
    if any(not group for group in result.values()):
        raise ValueError('Expected nonempty portal, identity, and other package shards')
    return result


def coverage_directory():
    # Discovery and Make execute in ROOT even when the script is invoked elsewhere.
    return ROOT / Path(os.environ.get('COVERAGE_DIR', '.coverage'))


def directory(shard):
    return coverage_directory() / 'shards' / shard


def run(shard):
    plan = partition(packages())
    output = directory(shard)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'selection.json').write_text(json.dumps(
        dict(shard=shard, packages=plan[shard], all_shards=plan), indent=2) + '\n')
    print(f'Running {shard}: {len(plan[shard])} of {sum(map(len, plan.values()))} packages', flush=True)
    # Explicit Make arguments override inherited filters, including MAKEFLAGS.
    result = subprocess.run(['make', 'test', 'TEST=.', 'TEST_DIR=' + ' '.join(plan[shard]),
                             'MINIMUM_COVERAGE=1', 'COVERAGE_DIR=' + str(output)], cwd=ROOT)
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
    """Publish a combined profile only from complete, successful disjoint runs."""
    base = coverage_directory()
    plan = None
    blocks = {}
    mode = None
    for shard in SHARDS:
        output = directory(shard)
        selected = json.loads((output / 'selection.json').read_text())
        current_plan = selected['all_shards']
        if set(current_plan) != set(SHARDS) or any(not group for group in current_plan.values()):
            raise ValueError('Incomplete shard plan')
        if plan is not None and plan != current_plan:
            raise ValueError('Shards were not produced from the same package plan')
        plan = current_plan
        if selected['shard'] != shard or selected['packages'] != plan[shard]:
            raise ValueError(f'Package selection mismatch for {shard}')
        execution = json.loads((output / 'run.json').read_text())
        resource = json.loads((output / 'resource-usage.json').read_text())
        if (execution['exit_code'] != 0 or not execution['capture_complete']
                or not execution['child_started'] or resource['status'] != 'passed'):
            raise ValueError(f'Unsuccessful or incomplete evidence for {shard}')
        terminals = {}
        for event in read_events(output / 'test_output.jsonl'):
            if event.get('Action') == 'fail':
                raise ValueError(f'Failed test evidence for {shard}')
            if not event.get('Test') and event.get('Action') in ('pass', 'skip'):
                name = event['Package']
                if name in terminals:
                    raise ValueError(f'Duplicate package execution: {name}')
                terminals[name] = event['Action']
        if set(terminals) != set(plan[shard]):
            raise ValueError(f'Not every selected package completed in {shard}')
        with (output / 'coverage.out').open(encoding='utf-8') as profile:
            header = profile.readline().strip()
            if header != 'mode: atomic' or (mode is not None and mode != header):
                raise ValueError('Expected race-enabled atomic coverage profiles')
            mode = header
            for line in profile:
                block, statements, count = line.split()
                statements, count = int(statements), int(count)
                if statements < 0 or count < 0 or block in blocks:
                    raise ValueError(f'Invalid or overlapping coverage block: {block}')
                blocks[block] = (statements, count)
        verify_manifest(output)
    all_packages = [name for group in plan.values() for name in group]
    if len(set(all_packages)) != len(all_packages):
        raise ValueError('Package shards overlap')
    total = sum(statements for statements, _ in blocks.values())
    covered = sum(statements for statements, count in blocks.values() if count > 0)
    if not total or covered * 100 < total:
        raise ValueError('Combined coverage is below the 1 percent nonempty-profile policy')
    summary = dict(schema='authcrunch/ci-coverage/v1', packages=len(all_packages),
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
    commands.add_parser('plan')
    for command in ('run', 'summarize'):
        commands.add_parser(command).add_argument('shard', choices=SHARDS)
    commands.add_parser('gate')
    commands.add_parser('merge')
    args = parser.parse_args()
    if args.command == 'plan':
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
