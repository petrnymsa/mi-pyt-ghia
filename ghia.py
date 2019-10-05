import click
import re
import configparser
import requests
import json
# --------------------------------------------------------------


class IssueChange:
    def __init__(self, change_type, name):
        self.change_type = change_type
        self.name = name
        if(self.change_type == '+'):
            self.color = 'green'
        elif(self.change_type == '-'):
            self.color = 'red'
        else:
            self.color = 'blue'

    def echo(self):
        click.secho(f'   {self.change_type}', fg=self.color, nl=False)
        click.echo(f' {self.name}')
# --------------------------------------------------------------


class Issue:
    def __init__(self, number, url, title, body, labels, assignees):
        self.number = number
        self.url = url
        self.title = title
        self.body = body
        self.labels = labels
        self.assignees = assignees
        self.freezed = []

    def append(self, names):
        changes = list(map(lambda x: IssueChange('=', x), self.assignees))
        for name in names:
            self.assignees.append(name)
            self.freezed.append(name)
            changes.append(IssueChange('+', name))
        return changes

    def clear_add_reapply(self, names):
        changes = []
        tmp = []
        # reapply freezed
        for a in self.assignees:
            if a in self.freezed or a in names:  # remain
                changes.append(IssueChange('=', a))
                tmp.append(a)
            else:  # name was deleted
                changes.append(IssueChange('-', a))

        self.assignees = tmp
        names = list(filter(lambda x: x not in self.assignees, names))
        for name in names:
            self.assignees.append(name)
            self.freezed.append(name)
            changes.append(IssueChange('+', name))

        return changes

    def replace(self, name):
        changes = []
        if self.assignees:
            for a in self.assignees:
                changes.append(IssueChange('=', a))
        else:
            for a in self.assignees:
                changes.append(IssueChange('-', a))
            self.assignees = [name]
            changes.append(IssueChange('+', name))
        return changes
# --------------------------------------------------------------


class Rule:
    def __init__(self, scope, pattern):
        self.scope = scope
        self.pattern = pattern

    def _validate(self, input_text):
        return re.search(self.pattern, input_text) is not None

    def validate(self, issue: Issue):
        if self.scope == 'title':
            return self._validate(issue.title)
        elif self.scope == 'text':
            return self._validate(issue.body)
        elif self.scope == 'label':
            return any(self._validate(label) for label in issue.labels)
        elif self.scope == 'any':
            return self._validate(issue.title) or self._validate(issue.body) or any(self._validate(label) for label in issue.labels)
        else:
            raise Exception(f'Unknown scope {self.scope}')

    def __str__(self):
        return f'{self.scope}:{self.pattern}'
# --------------------------------------------------------------


class RuleSet:
    def __init__(self, owner):
        self.owner = owner
        self.rules = []

    def add(self, rule):
        self.rules.append(rule)

    def validate(self, issue: Issue):
        for rule in self.rules:
            if rule.validate(issue):
                return True
        return False

    def __str__(self):
        s = self.owner + '{'
        for r in self.rules:
            s += r.scope + ':' + r.pattern + ';'
        s += ' }'
        return s
# --------------------------------------------------------------


class GitHubApi:
    def __init__(self, token, repo, strategy):
        self.strategy = strategy
        self.token = token
        self.repo = repo
        self.session = requests.Session()
        self.session.auth = self.req_token_auth
        self.issues = []

    def req_token_auth(self, req):
        req.headers['Authorization'] = f'token {self.token}'
        return req

    def load_issues(self):
        try:
            # todo replace with reposlug
            r = self.session.get(
                'http://api.github.com/repos/mi-pyt-ghia/petrnymsa/issues?state=open')
            r.raise_for_status()

            loaded_issues = json.loads(r.text)
            self.issues = []
            for issue in loaded_issues:
                labels = list(map(lambda x: x['name'], issue['labels']))
                assignees = list(map(lambda x: x['login'], issue['assignees']))
                self.issues.append(Issue(
                    issue['number'], issue['url'], issue['title'], issue['body'], labels, assignees))
        except:
            click.secho('ERROR', fg='red', bold=True, nl=False)
            click.echo(f': Could not list issues for repository {self.repo}')
            #    'Using fake data. TODO REMOVE IN PRODUCTION :) I am sitting in the train without wifi :( ')
            # for i in range(1, 3):
            #    self.issues.append(Issue(i, f'https://github.com/fake/issue#{i}', 'Dummy', 'Dummy body', [], []))
            # self.issues.append(Issue(100, f'https://github.com/fake/issue#123',
            #                         'Network', 'Network body', [], ['joe', 'noob']))

    def patch_issue(self, issue: Issue):
        # todo call PATCH with changes within issue
        encoded = json.dumps(issue.__dict__)
        pass

    def apply_strategy(self, issue: Issue, owners):
        if self.strategy == 'append':
            return issue.append(owners)
        elif self.strategy == 'set':
            return issue.replace(owners)
        elif self.strategy == 'change':
            return issue.clear_add_reapply(owners)
        else:
            raise Exception(f'Unknown strategy {self.strategy}')

    def proces_issues(self, rules, fallback):
        for issue in self.issues:
            changes = []
            applies = []
            for rule in rules:
                if rule.validate(issue):
                    applies.append(rule.owner)

            changes = self.apply_strategy(issue, applies)
            changes.sort(key=lambda x: x.name)
            print_result(self.repo, issue.number, issue.url, changes)
# --------------------------------------------------------------


def print_result(reposlug: str, issue_id: str, url: str, changes=[], fallback=False):
    click.echo('-> ', nl=False)
    click.secho(f'{reposlug}#{issue_id}', bold=True, nl=False)
    click.secho(f' {url}')
    for change in changes:
        change.echo()
    if fallback:
        click.secho('FALLBACK', bold=True, fg='yellow', nl=False)
        click.echo(': TODO')


def read_auth(auth_path):
    parser = configparser.ConfigParser()
    parser.read(auth_path)

    github_section = parser.items('github')
    return github_section[0][1]


def read_rules(rules_path):
    parser = configparser.ConfigParser()
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

# todo validate strategy
# todo validate config-auth
# todo validate config-rules
# todo validate repo
@click.command()
@click.option('-s', '--strategy', type=click.Choice(['append', 'set', 'change'], case_sensitive=False), default='append', show_default=True, help='How to handle assignment collisions.')
@click.option('-a', '--config-auth', metavar='FILENAME', required=True, help='File with authorization configuration.')
@click.option('-r', '--config-rules', metavar='FILENAME', required=True, help='File with assignment rules configuration.')
@click.option('-d', '--dry-run', is_flag=True, help='Run without making any changes.')
@click.argument('reposlug')
def main(dry_run, strategy, config_auth, config_rules, reposlug):
    '''CLI tool for automatic issue assigning of GitHub issues'''

    token = read_auth('credentials.cfg')  # todo use parameter
    (rules, fallback) = read_rules('rules.cfg')


if __name__ == '__main__':
    (rules, fallback) = read_rules('rules.cfg')
    token = read_auth('credentials.cfg')
    api = GitHubApi(token, 'mi-pyt-ghia/petrnymsa', 'append')
    api.load_issues()
    api.proces_issues(rules, fallback)
