#!/usr/bin/env python3
"""Check a selected release tag against its checkout and approved main history."""

import argparse
import json
import re
import subprocess
import sys


class PreflightError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise PreflightError()


NUMERIC = r'(?:0|[1-9][0-9]*)'
PRERELEASE_ID = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
TAG = re.compile(r'v' + NUMERIC + r'\.' + NUMERIC + r'\.' + NUMERIC
                 + r'(?:-' + PRERELEASE_ID + r'(?:\.' + PRERELEASE_ID + r')*)?'
                 + r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?')


def git(*arguments):
    result = subprocess.run(
        ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', *arguments],
        capture_output=True, check=False, timeout=15,
    )
    if result.returncode != 0:
        raise PreflightError()
    return result.stdout.strip().decode('ascii')


def main():
    parser = Parser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--main-ref', default='origin/main')
    options = parser.parse_args()
    if len(options.tag) > 256 or TAG.fullmatch(options.tag) is None:
        raise PreflightError()
    if re.fullmatch(r'[0-9a-f]{40}', options.sha) is None:
        raise PreflightError()
    if (len(options.main_ref) > 512
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', options.main_ref) is None):
        raise PreflightError()
    git('check-ref-format', '--allow-onelevel', options.main_ref)
    main_ref = git('rev-parse', '--symbolic-full-name', '--verify', options.main_ref)
    if not main_ref.startswith(('refs/heads/', 'refs/remotes/')):
        raise PreflightError()
    head = git('rev-parse', '--verify', 'HEAD^{commit}')
    tagged = git('rev-parse', '--verify', 'refs/tags/' + options.tag + '^{commit}')
    approved_main = git('rev-parse', '--verify', main_ref + '^{commit}')
    if head != options.sha or tagged != options.sha:
        raise PreflightError()
    git('merge-base', '--is-ancestor', options.sha, approved_main)
    git('diff', '--quiet', '--exit-code', '--')
    git('diff', '--cached', '--quiet', '--exit-code', '--')
    if git('rev-parse', '--verify', 'HEAD^{commit}') != options.sha:
        raise PreflightError()
    print(json.dumps({'tag': options.tag, 'version': options.tag[1:], 'sha': options.sha}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('secretwright: release tag preflight failed', file=sys.stderr)
        sys.exit(1)
