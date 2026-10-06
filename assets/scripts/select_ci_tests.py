#!/usr/bin/env python3
"""Classify event changes before installing tools or starting expensive jobs."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from change_tests import changed_files, git, revision, scope
from version import ROOT, check_version


def release_owns_validation():
    if (os.environ.get('GITHUB_EVENT_NAME') != 'push'
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'):
        return False
    try:
        version = check_version()
        sha = os.environ.get('GITHUB_SHA', '')
        head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                              capture_output=True, text=True, timeout=15).stdout.strip()
        if head != sha:
            return False
        tag = f'refs/tags/v{version}'
        result = subprocess.run(['git', 'ls-remote', '--tags', 'origin', tag, tag + '^{}'],
                                cwd=ROOT, check=True, capture_output=True, text=True, timeout=15)
        refs = {ref: object_id for object_id, ref in
                (line.split() for line in result.stdout.splitlines())}
        # ls-remote emits SHA then ref. A peeled ref proves an annotation exists;
        # it must identify this workflow's exact commit before we delegate tests.
        return tag in refs and refs.get(tag + '^{}') == sha
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Could not confirm the release tag; retaining normal change validation.')
        return False


def selection(release_dedup=True):
    full = dict(mode='full', base='', head='', reason='Full validation requested or no reliable diff available.')
    event = os.environ.get('GITHUB_EVENT_NAME', '')
    ref = os.environ.get('GITHUB_REF', '')
    # Reusable release workflows retain the original tag push context. Manual
    # and otherwise unsupported invocations also deliberately run the full gate.
    if ref.startswith('refs/tags/') or event not in {'push', 'pull_request'}:
        return full
    if release_dedup and release_owns_validation():
        return dict(mode='none', base='', head='', reason='The annotated release tag owns validation.')
    try:
        if revision('HEAD') != os.environ.get('GITHUB_SHA'):
            return full
        payload = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
        if event == 'pull_request':
            pull = payload['pull_request']
            head = revision(pull['head']['sha'])
            base = git('merge-base', revision(pull['base']['sha']), head).decode().strip()
        else:
            base = revision(payload['before'])
            head = revision(os.environ['GITHUB_SHA'])
        paths = changed_files(base, head)
        mode = scope(paths)
        return dict(mode=mode, base=base, head=head, reason=(
            'No code or test inputs changed.' if mode == 'none' else
            'Changed inputs require validation.'), files=paths)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'Cannot establish change range; retaining full validation ({error}).')
        return full


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-release-dedup', action='store_true',
                        help='For independent checks that are not owned by the release workflow.')
    args = parser.parse_args()
    selected = selection(release_dedup=not args.no_release_dedup)
    print(json.dumps(selected, indent=2))
    values = dict(run_tests=str(selected['mode'] != 'none').lower(),
                  mode=selected['mode'], base=selected['base'], head=selected['head'])
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
        for key, value in values.items():
            output.write(f'{key}={value}\n')


if __name__ == '__main__':
    main()
