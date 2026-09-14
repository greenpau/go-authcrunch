#!/usr/bin/env python3
"""Avoid duplicate branch tests when the same commit has its release tag."""

import os
from pathlib import Path
import subprocess

from version import ROOT, check_version


def should_run_tests():
    if (os.environ.get('GITHUB_EVENT_NAME') != 'push'
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'):
        return True
    try:
        version = check_version()
        sha = os.environ.get('GITHUB_SHA', '')
        head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                              capture_output=True, text=True, timeout=15).stdout.strip()
        if head != sha:
            return True
        tag = f'refs/tags/v{version}'
        result = subprocess.run(['git', 'ls-remote', '--tags', 'origin', tag, tag + '^{}'],
                                cwd=ROOT, check=True, capture_output=True, text=True, timeout=15)
        refs = {ref: object_id for object_id, ref in
                (line.split() for line in result.stdout.splitlines())}
        # ls-remote emits SHA then ref. A peeled ref proves an annotation exists;
        # it must identify this workflow's exact commit before we delegate tests.
        return not (tag in refs and refs.get(tag + '^{}') == sha)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Could not confirm the release tag; running the full test suite.')
        return True


def main():
    run_tests = should_run_tests()
    print('Running the full test suite.' if run_tests else
          'The release tag will run tests for this commit; skipping duplicate branch tests.')
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
        output.write(f'run_tests={str(run_tests).lower()}\n')


if __name__ == '__main__':
    main()
