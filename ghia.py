import click
import re
import configparser
import requests
import json
import os.path
# --------------------------------------------------------------
CHANGE_ADD = '+'
CHANGE_REMOVE = '-'
CHANGE_REMAIN = '='
CHANGE_FALLBACK = '?'
CHANGE_ERROR = 'x'


class IssueChange:
    def __init__(self, change_type, name):
        self.change_type = change_type
        self.name = name
        if self.change_type == CHANGE_ADD:
            self.color = 'green'
        elif self.change_type == CHANGE_REMOVE:
            self.color = 'red'
        elif self.change_type == CHANGE_REMAIN:
            self.color = 'blue'
        elif self.change_type == CHANGE_FALLBACK:
            self.color = 'yellow'
        elif self.change_type == CHANGE_ERROR:
            self.color = 'red'

    def echo(self):
        if self.change_type == CHANGE_FALLBACK:
            click.secho(f'   FALLBACK', fg=self.color, nl=False)
            click.echo(f': {self.name}')
        elif self.change_type == CHANGE_ERROR:
            click.secho(f'   ERROR', fg=self.color, nl=False, err=True)
            click.echo(f': {self.name}', err=True)
        else:
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
        changes = list(map(lambda x: IssueChange(
            CHANGE_REMAIN, x), self.assignees))
        for name in names:
            self.assignees.append(name)
            self.freezed.append(name)
            changes.append(IssueChange(CHANGE_ADD, name))
        return changes

    def clear_add_reapply(self, names):
        changes = []
        tmp = []
        # reapply freezed
        for a in self.assignees:
            if a in self.freezed or a in names:  # remain
                changes.append(IssueChange(CHANGE_REMAIN, a))
                tmp.append(a)
            else:  # name was deleted
                changes.append(IssueChange(CHANGE_REMOVE, a))

        self.assignees = tmp
        names = list(filter(lambda x: x not in self.assignees, names))
        for name in names:
            self.assignees.append(name)
            self.freezed.append(name)
            changes.append(IssueChange(CHANGE_ADD, name))

        return changes

    def replace(self, name):
        changes = []
        if self.assignees:
            for a in self.assignees:
                changes.append(IssueChange(CHANGE_REMAIN, a))
        else:
            for a in self.assignees:
                changes.append(IssueChange(CHANGE_REMOVE, a))
            self.assignees = [name]
            changes.append(IssueChange(CHANGE_ADD, name))
        return changes

    def apply_label(self, label):
        if label not in self.labels:
            self.labels.append(label)
            return [IssueChange(CHANGE_FALLBACK, f'added label "{label}"')]
        else:
            return [IssueChange(CHANGE_FALLBACK, f'already has label "{label}"')]
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


class GitHubIssueAssigner:
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
            r = self.session.get(
                f'http://api.github.com/repos/{self.repo}/issues?state=open')
            r.raise_for_status()

            loaded_issues = json.loads(r.text)
            self.issues = []
            for issue in loaded_issues:
                labels = list(map(lambda x: x['name'], issue['labels']))
                assignees = list(map(lambda x: x['login'], issue['assignees']))
                self.issues.append(Issue(
                    issue['number'], issue['html_url'], issue['title'], issue['body'], labels, assignees))

        except:
            click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
            click.echo(
                f': Could not list issues for repository {self.repo}', err=True)
            exit(10)
            # for i in range(1, 3):
            #     self.issues.append(
            #         Issue(i, f'https://github.com/fake/issue#{i}', 'Dummy', 'Dummy body', [], []))
            # self.issues.append(Issue(100, f'https://github.com/fake/issue#123',
            #                          'Netwfsdafdsafork', 'Netasdfaswork body', [], ['joe', 'noob']))

    def patch_issue(self, issue: Issue):
        # todo call PATCH with changes within issue
        encoded = json.dumps(issue.__dict__)
        pass

    def apply_strategy(self, issue: Issue, owners, fallback):
        # apply fallback if needed
       # if not issue.assignees and not owners and fallback is not None:
       #     return issue.apply_label(fallback)

        if self.strategy == 'append':
            return issue.append(owners)
        elif self.strategy == 'set':
            return issue.replace(owners)
        elif self.strategy == 'change':
            return issue.clear_add_reapply(owners)
        else:
            raise Exception(f'Unknown strategy {self.strategy}')

    def check_fallback(self, issue: Issue, fallback):
         # apply fallback if needed
        if not issue.assignees and fallback is not None:
            return issue.apply_label(fallback)
        return []

    def proces_issues(self, rules, fallback, dry_run: bool):
        for issue in self.issues:
            changes = []
            applies = []
            for rule in rules:
                if rule.validate(issue):
                    applies.append(rule.owner)

            changes = self.apply_strategy(issue, applies, fallback)
            # todo apply it via api
            c = self.check_fallback(issue, fallback)
            for i in c:
                changes.append(i)
            changes.sort(key=lambda x: x.name.lower())
            print_result(self.repo, issue.number, issue.url, changes)
# --------------------------------------------------------------


def print_result(reposlug: str, issue_id: str, url: str, changes=[], fallback=False):
    click.echo('-> ', nl=False)
    click.secho(f'{reposlug}#{issue_id}', bold=True, nl=False)
    click.secho(f' ({url})')
    for change in changes:
        change.echo()
    if fallback:
        click.secho('FALLBACK', bold=True, fg='yellow', nl=False)
        click.echo(': TODO')


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
# todo validate strategy
# todo validate config-auth
# todo validate config-rules
# todo validate repo
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
    # (rules, fallback) = read_rules('rules.cfg')
    # token = read_auth('credentials.cfg')
    # api = GitHubApi(token, 'mi-pyt-ghia/petrnymsa', 'append')
    # api.load_issues()
    # api.proces_issues(rules, fallback)
