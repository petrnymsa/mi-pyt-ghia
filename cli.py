import click
import configreader
import re
import os

from assigner import GitHubIssueAssigner


def validate_reposlug(ctx, param, value):
    m = re.match('^[a-zA-Z,-]+/[a-zA-Z,-]+$', value)
    if m is None:
        raise click.BadParameter(f'not in owner/repository format')
    return value


def validate_config_auth(ctx, param, value):
    if not os.path.exists(value):
        raise click.BadParameter('incorrect configuration format')

    try:
        token = configreader.read_auth(value)[0]
        return token
    except:
        raise click.BadParameter('incorrect configuration format')


def validate_config_rules(ctx, param, value):
    if not os.path.exists(value):
        raise click.BadParameter('incorrect configuration format')

    try:
        rules = configreader.read_rules(value)
        return rules
    except:
        raise click.BadParameter('incorrect configuration format')


@click.command()
@click.option('-s', '--strategy', type=click.Choice(['append', 'set', 'change'], case_sensitive=False), default='append', show_default=True, help='How to handle assignment collisions.')
@click.option('-a', '--config-auth', callback=validate_config_auth, metavar='FILENAME', required=True, help='File with authorization configuration.')
@click.option('-r', '--config-rules', callback=validate_config_rules, metavar='FILENAME', required=True, help='File with assignment rules configuration.')
@click.option('-d', '--dry-run', is_flag=True, default=False, help='Run without making any changes.')
@click.argument('reposlug', callback=validate_reposlug)
def run(dry_run, strategy, config_auth, config_rules, reposlug):
    '''CLI tool for automatic issue assigning of GitHub issues'''
    (rules, fallback) = config_rules
    ghia = GitHubIssueAssigner(config_auth, reposlug, strategy)
    ghia.load_issues()
    ghia.proces_issues(rules, fallback, dry_run)
