import ghia.issue as iss
from ghia.rule import Rule, RuleSet


def test_validate_title():
    i = iss.Issue('10', 'url', 'protocol', 'test protocol', [], [])

    result = Rule('title', 'protocol').validate(i)
    assert result


def test_validate_title_no_match():
    i = iss.Issue('10', 'url', 'protocol', 'test protocol', [], [])

    result = Rule('title', 'nomatch').validate(i)
    assert not result


def test_validate_title_regex():
    i = iss.Issue('10', 'url', 'protocol',
                  'http://localhost:8080', [], [])

    result = Rule('text', 'http[s]{0,1}://localhost:[0-9]{2,5}').validate(i)
    assert result
