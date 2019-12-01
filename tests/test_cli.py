import pytest
import click
import os
import ghia.cli as cl
import ghia.configreader as creader
import ghia.rule as rule


@pytest.mark.parametrize('repo', ('user/repo', 'petr/repo-with-dash', 'user-dash/repo', 'user-dash/repo-dash'))
def test_validate_reposlug(repo):
    result = cl.validate_reposlug(None, None, repo)
    assert(repo == result)


@pytest.mark.parametrize('repo', ('user', '/repo', '98878754/repo', '.', ' ', '/', 'user/484545'))
def test_validate_notvalid_reposlug(repo):
    with pytest.raises(click.BadParameter):
        cl.validate_reposlug(None, None, repo)

# -------------------------------------------------------------------------------


def test_validate_config_auth_not_valid_path(monkeypatch):
    def path_exists(path):
        return False
    monkeypatch.setattr(os.path, "exists", path_exists)

    with pytest.raises(click.BadParameter):
        cl.validate_config_auth(None, None, "not/existing/path/conf.auth")


def test_validate_config_auth_invalid_config_format(monkeypatch):
    def path_exists(path):
        return True

    def read_auth(value):
        raise Exception("Invalid foramt")

    monkeypatch.setattr(os.path, "exists", path_exists)
    monkeypatch.setattr(creader, "read_auth", read_auth)

    with pytest.raises(click.BadParameter):
        cl.validate_config_auth(None, None, "fake/config.auth")


def test_validate_config_auth(monkeypatch):
    def path_exists(path):
        return True

    def read_auth(value):
        return ('123-Abc', None)

    monkeypatch.setattr(os.path, "exists", path_exists)
    monkeypatch.setattr(creader, "read_auth", read_auth)

    result = cl.validate_config_auth(None, None, "fake/config.auth")
    assert result == '123-Abc'

# ------------------------------------------------------------------------


def test_validate_config_rules_not_valid_path(monkeypatch):
    def path_exists(path):
        return False
    monkeypatch.setattr(os.path, "exists", path_exists)

    with pytest.raises(click.BadParameter):
        cl.validate_config_auth(None, None, "not/existing/path/rules.cfg")


def test_validate_config_rules_invalid_config_format(monkeypatch):
    def path_exists(path):
        return True

    def read_rules(value):
        raise Exception("Invalid foramt")

    monkeypatch.setattr(os.path, "exists", path_exists)
    monkeypatch.setattr(creader, "read_rules", read_rules)

    with pytest.raises(click.BadParameter):
        cl.validate_config_auth(None, None, "fake/rules.cfg")


def test_validate_config_rules(monkeypatch):
    rules = rule.RuleSet('user')
    rules.add(rule.Rule('title', 'test'))

    expected = ([rules], 'fallback')

    def path_exists(path):
        return True

    def read_rules(value):
        return expected

    monkeypatch.setattr(os.path, "exists", path_exists)
    monkeypatch.setattr(creader, "read_rules", read_rules)

    result = cl.validate_config_rules(None, None, "fake/rules.cfg")
    assert result == expected
