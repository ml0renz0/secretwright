#!/usr/bin/env python3
"""Select a candidate or stable source from the reviewed release policy.

The policy is a deliberately small YAML subset: exactly two unquoted, flat
scalars named next_version and promote_candidate, with blank lines and comments.
Documents, aliases, collections, indentation and additional keys are rejected.
"""

from pathlib import Path
import argparse
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote


POLICY = '.github/release.yaml'
NUMERIC = r'(?:0|[1-9][0-9]{0,17})'
VERSION = re.compile(NUMERIC + r'\.' + NUMERIC + r'\.' + NUMERIC)
CANDIDATE = re.compile(r'v(' + VERSION.pattern + r')-rc\.([1-9][0-9]{0,17})')
SHA = re.compile(r'[0-9a-f]{40}')
REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*')


class PlanError(Exception):
    pass


def require(condition):
    if not condition:
        raise PlanError()


def git(root, environment, *arguments, strip=True):
    result = subprocess.run(
        ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', *arguments],
        cwd=root, env=environment, capture_output=True, check=False, timeout=15,
    )
    require(result.returncode == 0 and len(result.stdout) <= 1 << 20)
    text = result.stdout.decode('utf-8')
    return text.strip() if strip else text


def read_policy(text):
    """Parse only the documented flat YAML release-policy subset."""
    require(isinstance(text, str) and len(text.encode('utf-8')) <= 4096)
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'(next_version|promote_candidate): +([^\s#]+) *(?: +#.*)?', line)
        require(match is not None)
        name, value = match.groups()
        require(name not in result)
        result[name] = None if value == 'null' else value
    require(set(result) == {'next_version', 'promote_candidate'})
    require(isinstance(result['next_version'], str) and VERSION.fullmatch(result['next_version']) is not None)
    require(result['promote_candidate'] is None or CANDIDATE.fullmatch(result['promote_candidate']) is not None)
    return result


def committed_policy(root, environment, commit):
    entry = git(root, environment, 'ls-tree', commit, '--', POLICY)
    if not entry:
        return None
    match = re.fullmatch(r'100(?:644|755) blob ([0-9a-f]{40})\t' + re.escape(POLICY), entry)
    require(match is not None)
    require(int(git(root, environment, 'cat-file', '-s', match.group(1))) <= 4096)
    return read_policy(git(root, environment, 'cat-file', 'blob', match.group(1), strip=False))


def checkout_policy(root):
    selected = Path(root) / POLICY
    before = selected.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 4096)
    descriptor = os.open(selected, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'r', encoding='utf-8') as source:
        after = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size))
        return read_policy(source.read(4097))


def first_parent(root, environment, sha):
    parents = git(root, environment, 'rev-list', '--parents', '-n', '1', sha).split()
    require(parents and parents[0] == sha)
    return parents[1] if len(parents) > 1 else None


def version_order(version):
    return tuple(int(part) for part in version.split('.'))


def transition(root, environment, current, previous, base, *, checkout=False):
    """Return a newly requested stable candidate, or None for normal development."""
    require(current is not None)
    if previous is None:
        require(current['promote_candidate'] is None)
        return None
    require(version_order(current['next_version']) >= version_order(previous['next_version']))
    candidate = current['promote_candidate']
    if candidate is None or candidate == previous['promote_candidate']:
        return None
    match = CANDIDATE.fullmatch(candidate)
    require(match is not None)
    require(match.group(1) == previous['next_version'])
    require(version_order(current['next_version']) > version_order(match.group(1)))
    if checkout:
        changed = git(root, environment, 'diff', '--name-only', base, '--').splitlines()
    else:
        changed = git(root, environment, 'diff-tree', '--no-commit-id', '--name-only', '-r', base, 'HEAD').splitlines()
    require(changed == [POLICY])
    return candidate


def publication_module():
    spec = importlib.util.spec_from_file_location('secretwright_plan_publication', Path(__file__).with_name('publish_release.py'))
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_published_candidate(root, environment, repository, candidate, sha):
    token = environment.get('GH_TOKEN', '')
    require(bool(token.strip()) and not any(character in token for character in '\r\n\0'))
    publication = publication_module()
    with tempfile.TemporaryDirectory(prefix='secretwright-release-plan-gh-') as temporary:
        selected = dict(environment)
        for name in ('SECRETWRIGHT_SIGNING_KEY', 'SECRETWRIGHT_SIGNING_PASSWORD', 'GITHUB_TOKEN',
                     'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
            selected.pop(name, None)
        selected.update(GH_HOST='github.com', GH_PROMPT_DISABLED='1', GH_CONFIG_DIR=temporary)
        publication.require_remote_tag(repository, candidate, sha, cwd=root, environment=selected)
        code, release = publication.api_get(f'repos/{repository}/releases/tags/{quote(candidate, safe="")}',
                                           cwd=root, environment=selected)
        require(code == 200 and release.get('tag_name') == candidate and release.get('draft') is False
                and release.get('prerelease') is True and isinstance(release.get('published_at'), str)
                and bool(release['published_at'].strip()))


def plan(root, environment):
    root, environment = Path(root).resolve(), dict(environment)
    control = environment.get('GITHUB_SHA', '')
    number = environment.get('GITHUB_RUN_NUMBER', '')
    repository = environment.get('GITHUB_REPOSITORY', '')
    require(environment.get('GITHUB_EVENT_NAME') == 'push' and environment.get('GITHUB_REF') == 'refs/heads/main')
    require(SHA.fullmatch(control) is not None and re.fullmatch(r'[1-9][0-9]{0,17}', number) is not None)
    require(REPOSITORY.fullmatch(repository) is not None)
    require(git(root, environment, 'rev-parse', '--verify', 'HEAD^{commit}') == control)
    git(root, environment, 'merge-base', '--is-ancestor', control, 'refs/remotes/origin/main')
    git(root, environment, 'diff', '--quiet', '--exit-code', '--')
    git(root, environment, 'diff', '--cached', '--quiet', '--exit-code', '--')
    previous_sha = first_parent(root, environment, control)
    current = committed_policy(root, environment, control)
    previous = committed_policy(root, environment, previous_sha) if previous_sha else None
    candidate = transition(root, environment, current, previous, previous_sha)
    if candidate:
        source = git(root, environment, 'rev-parse', '--verify', 'refs/tags/' + candidate + '^{commit}')
        require(SHA.fullmatch(source) is not None and previous_sha is not None)
        git(root, environment, 'merge-base', '--is-ancestor', source, previous_sha)
        require_published_candidate(root, environment, repository, candidate, source)
        version = CANDIDATE.fullmatch(candidate).group(1)
        result = {'mode': 'stable', 'tag': 'v' + version, 'version': version, 'sha': source,
                  'candidate': candidate, 'control_sha': control}
    else:
        version = current['next_version'] + '-rc.' + number
        result = {'mode': 'rc', 'tag': 'v' + version, 'version': version, 'sha': control,
                  'candidate': '', 'control_sha': control}
    require(git(root, environment, 'rev-parse', '--verify', 'HEAD^{commit}') == control)
    return result


def check(root, environment, base_ref=None):
    root, environment = Path(root).resolve(), dict(environment)
    head = git(root, environment, 'rev-parse', '--verify', 'HEAD^{commit}')
    if base_ref is None:
        base = first_parent(root, environment, head)
    else:
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,511}', base_ref) is not None)
        git(root, environment, 'check-ref-format', '--allow-onelevel', base_ref)
        canonical = git(root, environment, 'rev-parse', '--symbolic-full-name', '--verify', base_ref)
        require(canonical.startswith(('refs/heads/', 'refs/remotes/')))
        base = git(root, environment, 'merge-base', head, canonical)
    previous = committed_policy(root, environment, base) if base else None
    transition(root, environment, checkout_policy(root), previous, base, checkout=True)
    return {'valid': True}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise PlanError()


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--check', action='store_true')
        parser.add_argument('--base-ref')
        options = parser.parse_args()
        require(options.check or options.base_ref is None)
        result = check(Path.cwd(), os.environ, options.base_ref) if options.check else plan(Path.cwd(), os.environ)
        if not options.check and os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='ascii') as output:
                output.write(''.join(f'{name}={value}\n' for name, value in result.items()))
    except Exception:
        print('secretwright: release plan rejected', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
