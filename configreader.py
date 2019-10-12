import configparser
from rule import RuleSet, Rule


class Configuration:
    def __init__(self):
        self.token = ''
        self.secret = ''
        self.rules = []


def read_auth(auth_path):
    parser = configparser.ConfigParser()
    parser.optionxform = str  # ! preserve case sensitive
    parser.read(auth_path)

    if not parser.has_option('github', 'token'):
        raise Exception('token option missing')

    token = parser.get('github', 'token')

    if parser.has_option('github', 'secret'):
        secret = parser.get('github', 'secret')
        print(f'secret: {secret}')
        return (token, secret)

    return (token, None)


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
    rules.sort(key=lambda x: x.owner)

    if parser.has_section('fallback'):
        if not parser.has_option('fallback', 'label'):
            raise Exception(
                'Fallback section is present but has no `label` configuration')
        return (rules, parser.get('fallback', 'label'))

    return (rules, None)


def read_from_multiple_files(files):
    config = Configuration()
