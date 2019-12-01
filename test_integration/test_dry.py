from helpers import run, config, repo, issue_assignees, issue_labels, issue_set_labels, contains_exactly


def test_incorrect_token():
    # This test might end up well even if repo does not exist
    cp = run(f'--config-rules "{config("rules.empty.cfg")}" '
             f'--config-auth "{config("auth.fff.cfg")}" '
             f'{repo}')
    assert cp.returncode == 10
    assert len(cp.stdout) == 0
    assert f'ERROR: Could not list issues for repository {repo}' in cp.stderr


def test_nonexisting_repo():
    cp = run(f'--config-rules "{config("rules.empty.cfg")}" '
             f'--config-auth "{config("auth.real.cfg")}" '
             'MarekSuchanek/NonExistingRepository')
    assert cp.returncode == 10
    assert len(cp.stdout) == 0
    assert 'ERROR: Could not list issues for repository MarekSuchanek/NonExistingRepository' in cp.stderr


def test_forbidden_repo_nochange():
    cp = run(f'--config-rules "{config("rules.empty.cfg")}" '
             f'--config-auth "{config("auth.real.cfg")}" '
             'ghia-anna/awesome')
    assert cp.returncode == 0
    assert len(cp.stderr) == 0
    assert f'-> ghia-anna/awesome#1 (https://github.com/ghia-anna/awesome/issues/1)\n' \
           '   = ghia-anna\n' in cp.stdout


def test_forbidden_repo_dry_run_append():
    cp = run(f'--config-rules "{config("rules.forbidden_repo.cfg")}" '
             f'--config-auth "{config("auth.real.cfg")}" '
             '--dry-run ghia-anna/awesome')
    assert cp.returncode == 0
    assert len(cp.stderr) == 0
    assert '-> ghia-anna/awesome#1 (https://github.com/ghia-anna/awesome/issues/1)\n' \
           '   = ghia-anna\n' \
           '   + MarekSuchanek\n' in cp.stdout


def test_forbidden_repo_dry_run_set():
    cp = run(f'--config-rules "{config("rules.forbidden_repo.cfg")}" '
             f'--config-auth "{config("auth.real.cfg")}" '
             '--strategy set --dry-run ghia-anna/awesome')
    assert cp.returncode == 0
    assert len(cp.stderr) == 0
    assert '-> ghia-anna/awesome#1 (https://github.com/ghia-anna/awesome/issues/1)\n' \
           '   = ghia-anna\n' in cp.stdout


def test_forbidden_repo_dry_run_change():
    cp = run(f'--config-rules "{config("rules.forbidden_repo.cfg")}" '
             f'--config-auth "{config("auth.real.cfg")}" '
             '--strategy change --dry-run ghia-anna/awesome')
    assert cp.returncode == 0
    assert len(cp.stderr) == 0
    assert '-> ghia-anna/awesome#1 (https://github.com/ghia-anna/awesome/issues/1)\n' \
           '   - ghia-anna\n' \
           '   + MarekSuchanek\n' in cp.stdout
