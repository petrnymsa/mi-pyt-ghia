import requests
import click
import json
from issue import Issue, IssueChange
from rule import Rule, RuleSet


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
            self.print_result(issue.number, issue.url, changes)

    def print_result(self, issue_id: str, url: str, changes=[]):
        click.echo('-> ', nl=False)
        click.secho(f'{self.repo}#{issue_id}', bold=True, nl=False)
        click.secho(f' ({url})')
        for change in changes:
            change.echo()
# --------------------------------------------------------------
