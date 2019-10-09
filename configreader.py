import configparser
from rule import RuleSet, Rule


def read_auth(auth_path):
    parser = configparser.ConfigParser()
    parser.optionxform = str  # ! preserve case sensitive
    parser.read(auth_path)

    if not parser.has_option('github', 'token'):
        raise Exception('token option missing')

    github_section = parser.items('github')
    return github_section[0][1]


def read_rules(rules_path):
    parser = configparser.ConfigParser()
    parser.optionxform = str  # ! preserve case sensitive
    parser.read(rules_path)
    patterns = parser.items('patterns')
    rules = []
    for pat in patterns:
        rule_set = RuleSet(pat[0])

        lines = list(filter(None, pat[1].split('\n')))
        for line in lines:
            r = line.split(':', 1)
            rule_set.add(Rule(r[0], r[1]))
        rules.append(rule_set)

    if parser.has_section('fallback'):
        if not parser.has_option('fallback', 'label'):
            raise Exception(
                'Fallback section is present but has no `label` configuration')
        return (rules, parser.get('fallback', 'label'))
    rules.sort(key=lambda x: x.owner)
    return (rules, None)
