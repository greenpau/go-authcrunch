#!/usr/bin/env python3
"""Select applicable tests from Git changes; share policy with GitHub Actions."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
GLOBAL_FILES = {'Makefile', 'go.mod', 'go.sum', 'go.work', 'go.work.sum', 'VERSION'}
DOCUMENT_FILES = {'LICENSE', 'OWNERS', '.gitignore', '.github/FUNDING.yml', '.github/CODEOWNERS'}
EMBEDDED_TREES = ('pkg/authn/ui/', 'pkg/messaging/email_templates/', 'pkg/translate/data/')


def git(*arguments):
    return subprocess.run(['git', *arguments], cwd=ROOT, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout


def revision(value):
    """Resolve before diffing so revisions cannot be interpreted as Git options."""
    return git('rev-parse', '--verify', '--end-of-options', value + '^{commit}').decode().strip()


def changed_files(base='', head=''):
    if base:
        # Two endpoints are intentional: CI computes the PR merge base first.
        output = git('diff', '--name-only', '-z', '--no-renames',
                     revision(base), revision(head or 'HEAD'), '--')
    elif head:
        raise ValueError('CHANGE_HEAD requires CHANGE_BASE')
    else:
        # Union, not HEAD-to-worktree: a staged edit can be undone in the
        # worktree and must still select tests. --no-renames retains both paths.
        output = git('diff', '--cached', '--name-only', '-z', '--no-renames', '--')
        output += git('diff', '--name-only', '-z', '--no-renames', '--')
        output += git('ls-files', '--others', '--exclude-standard', '-z')
    return sorted({os.fsdecode(path) for path in output.split(b'\0') if path})


def classify(path):
    """Only known non-code inputs may skip validation; unknown inputs run all."""
    file = PurePosixPath(path)
    if path in GLOBAL_FILES or file.name in {'go.mod', 'go.sum', 'go.work', 'go.work.sum'}:
        return 'full'
    # Embedded content and fixtures remain test inputs even when named *.md.
    if (path.startswith(EMBEDDED_TREES + ('testdata/',))
            or ('testdata' in file.parts and path.startswith(('pkg/', 'cmd/', 'internal/')))):
        return 'go'
    if 'testdata' in file.parts and path.startswith(('assets/scripts/', '.github/')):
        return 'automation'
    if (path.startswith(('.codex/', '.vscode/', 'assets/cla/', '.github/ISSUE_TEMPLATE/',
                         '.github/PULL_REQUEST_TEMPLATE/'))
            or file.suffix.lower() in {'.md', '.rst'}
            or file.name == '.gitkeep' or path in DOCUMENT_FILES):
        return 'none'
    if path.startswith(('assets/scripts/', '.github/', 'assets/branding/')) or path == '.goreleaser.yaml':
        return 'automation'
    if file.suffix in {'.go', '.s', '.S', '.c', '.h', '.cc', '.cpp', '.syso'}:
        return 'go'
    # Package-local templates, configuration, certificates, and fixtures.
    if path.startswith(('pkg/', 'cmd/', 'internal/')):
        return 'go'
    return 'full'


def scope(paths):
    kinds = {classify(path) for path in paths}
    if 'full' in kinds:
        return 'full'
    return 'focused' if kinds - {'none'} else 'none'


def full_plan(paths, reason):
    return dict(mode='full', reason=reason, files=paths, packages=['./...'],
                automation=True, ui=True)


def packages():
    # No compilation or test execution. -e lets us detect incomplete graphs
    # explicitly; a missing dependency or broken source must never mean "skip".
    result = subprocess.run(['go', 'list', '-mod=readonly', '-e', '-json', './...'],
                            cwd=ROOT, check=True, capture_output=True, text=True, timeout=120)
    decoder = json.JSONDecoder()
    data = result.stdout.lstrip()
    found = {}
    while data:
        package, end = decoder.raw_decode(data)
        if package.get('Error') or package.get('DepsErrors'):
            raise ValueError('Go package graph contains errors')
        name = package['ImportPath']
        # Package names are later passed through Make's space-separated TEST_DIR.
        if not re.fullmatch(r'[A-Za-z0-9_./~\-]+', name):
            raise ValueError('Go package path cannot be represented in TEST_DIR')
        found[name] = package
        data = data[end:].lstrip()
    if not found:
        raise ValueError('No Go packages discovered')
    return found


def plan(paths):
    mode = scope(paths)
    if mode == 'full':
        return full_plan(paths, 'Global or unclassified test input changed.')
    selected = dict(mode=mode, reason='No code or test inputs changed.' if mode == 'none'
                    else 'Run owning packages and affected consumers.', files=paths,
                    packages=[], automation=any(classify(p) == 'automation' for p in paths),
                    ui=any(p.startswith(('pkg/authn/ui/', 'assets/branding/')) for p in paths))
    go_paths = [p for p in paths if classify(p) == 'go']
    if not go_paths:
        return selected
    if any(p.startswith('testdata/') for p in go_paths):
        selected['packages'] = ['./...']
        selected['reason'] = 'Shared root fixtures can affect every Go package.'
        return selected
    try:
        graph = packages()
        directories = {Path(p['Dir']).relative_to(ROOT).as_posix(): name
                       for name, p in graph.items()}
        owners, changed = set(), set()
        for path in go_paths:
            parent = PurePosixPath(path).parent
            # A deleted/new package must not be mistaken for its parent package.
            if path.endswith('.go'):
                owner = directories.get(parent.as_posix())
            else:
                owner = next((directories[p.as_posix()] for p in (parent, *parent.parents)
                              if p.as_posix() in directories), None)
            if owner is None:
                raise ValueError('Changed input has no current owning Go package')
            owners.add(owner)
            if not path.endswith('_test.go'):
                changed.add(owner)
        # Production imports propagate changes. Test imports select that
        # consumer's tests without treating its production API as changed.
        while True:
            consumers = {name for name, p in graph.items()
                         if changed.intersection(p.get('Imports', []))}
            if consumers <= changed:
                break
            changed.update(consumers)
        owners.update(changed)
        owners.update(name for name, p in graph.items() if changed.intersection(
            p.get('TestImports', []) + p.get('XTestImports', [])))
        # This repository's struct-tag compliance suite scans source at runtime.
        if any(p.endswith('.go') and not p.endswith('_test.go') for p in go_paths):
            owners.update(name for directory, name in directories.items() if directory == 'internal/tag')
        selected['packages'] = sorted(owners)
        return selected
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        return full_plan(paths, f'Cannot determine Go impact safely ({error}); running all tests.')


def run(selected, output):
    commands = []
    if selected['automation']:
        commands.append(['make', 'test-automation'])
    if selected['ui']:
        commands.append(['make', 'test-ui'])
    if selected['packages']:
        commands.append(['make', 'test', 'TEST=.', 'TEST_DIR=' + ' '.join(selected['packages']),
                         'COVERAGE_DIR=' + str(output / 'go')])
    for command in commands:
        print('Running: ' + ' '.join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode if result.returncode > 0 else 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default=os.environ.get('CHANGE_BASE', ''))
    parser.add_argument('--head', default=os.environ.get('CHANGE_HEAD', ''))
    parser.add_argument('--dry-run', action='store_true',
                        default=os.environ.get('CHANGE_DRY_RUN', '0') == '1')
    args = parser.parse_args()
    try:
        selected = plan(changed_files(args.base, args.head))
        print(json.dumps(selected, indent=2), flush=True)
        if args.dry_run or selected['mode'] == 'none':
            return 0
        output = Path(os.environ.get('COVERAGE_DIR', '.coverage')) / 'changes'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'selection.json').write_text(json.dumps(selected, indent=2) + '\n', encoding='utf-8')
        return run(selected, output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'change-test: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
