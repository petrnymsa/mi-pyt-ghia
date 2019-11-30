import pytest
import click
import os
import pathlib
import ghia.configreader as creader
import ghia.rule as rule


def config(name):
    return pathlib.Path(__file__).parent / 'fixtures' / name


def test_read_auth_empty_file():
    with pytest.raises(Exception):
        creader.read_auth(config('auth.invalid.cfg'))


def test_read_auth_only_token():
    result = creader.read_auth(config('auth.no-secret.cfg'))
    assert result == ('abc', None)


def test_read_auth():
    result = creader.read_auth(config('auth.cfg'))
    assert result == ('abc', 'passwd')

# ------------------------------------------------------------------


def test_read_rules_empty_file():
    with pytest.raises(Exception):
        creader.read_auth(config('rules.invalid.cfg'))


def test_read_rules_empty():
    result = creader.read_rules(config('rules.empty.cfg'))
    assert result != None
    assert result == ([], None)


def test_read_rules_fallback():
    result = creader.read_rules(config('rules.fallback.cfg'))
    assert result != None
    assert result == ([], 'fallback')


def test_read_rules_fallback_invalid():
    with pytest.raises(Exception):
        creader.read_rules(config('rules.fallback.invalid.cfg'))


def test_read_rules_only_one():
    rules = rule.RuleSet('GhUser')
    rules.add(rule.Rule('title', 'test'))
    rules.add(rule.Rule('text', 'protocol'))
    expected = ([rules], 'fallback')

    result = creader.read_rules(config('rules.one.cfg'))

    assert result == expected


def test_read_rules_multiple():

    a = rule.RuleSet('AB')
    a.add(rule.Rule('title', 'protocol'))
    a.add(rule.Rule('text', 'secret'))

    b = rule.RuleSet('GhUser')
    b.add(rule.Rule('title', 'test'))
    b.add(rule.Rule('text', 'protocol'))

    result = creader.read_rules(config('rules.multiple.cfg'))

    assert result == ([a, b], 'fallback')
