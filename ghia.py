import configparser
import os.path
import click
import re
# --------------------------------------------------------------
from issue import Issue, IssueChange
from rule import Rule, RuleSet
from assigner import GitHubIssueAssigner
# --------------------------------------------------------------


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
        print(f'Processing rule for {pat[0]}')
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


def validate_reposlug(ctx, param, value):
    m = re.match('^[a-zA-Z,-]+/[a-zA-Z,-]+$', value)
    if m is None:
        raise click.BadParameter(f'not in owner/repository format')
    return value


def validate_config_auth(ctx, param, value):
    if not os.path.exists(value):
        raise click.BadParameter('incorrect configuration format')

    try:
        token = read_auth(value)
        return token
    except:
        raise click.BadParameter('incorrect configuration format')


def validate_config_rules(ctx, param, value):
    if not os.path.exists(value):
        raise click.BadParameter('incorrect configuration format')

    try:
        rules = read_rules(value)
        return rules
    except:
        raise click.BadParameter('incorrect configuration format')


@click.command()
@click.option('-s', '--strategy', type=click.Choice(['append', 'set', 'change'], case_sensitive=False), default='append', show_default=True, help='How to handle assignment collisions.')
@click.option('-a', '--config-auth', callback=validate_config_auth, metavar='FILENAME', required=True, help='File with authorization configuration.')
@click.option('-r', '--config-rules', callback=validate_config_rules, metavar='FILENAME', required=True, help='File with assignment rules configuration.')
@click.option('-d', '--dry-run', is_flag=True, help='Run without making any changes.')
@click.argument('reposlug', callback=validate_reposlug)
def main(dry_run, strategy, config_auth, config_rules, reposlug):
    '''CLI tool for automatic issue assigning of GitHub issues'''
    (rules, fallback) = config_rules
    ghia = GitHubIssueAssigner(config_auth, reposlug, strategy)
    ghia.load_issues()
    ghia.proces_issues(rules, fallback, dry_run)


if __name__ == '__main__':
    main()
