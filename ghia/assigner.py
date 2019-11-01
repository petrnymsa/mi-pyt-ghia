import requests
import click
import json
import ghia.issue as iss
from .rule import Rule, RuleSet


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

    def parse_issues(self, response):
        loaded_issues = json.loads(response)

        for json_issue in loaded_issues:
            self.issues.append(iss.Issue.from_json(json_issue))

    def load_issues(self):
        try:
            self.issues = []
            url = f'https://api.github.com/repos/{self.repo}/issues?state=open'
            r = self.session.get(url)
            r.raise_for_status()

            while 'next' in r.links:
                self.parse_issues(r.text)

                url = r.links['next']['url']
                r = self.session.get(url)
                r.raise_for_status()

            self.parse_issues(r.text)
        except:
            click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
            click.echo(
                f': Could not list issues for repository {self.repo}', err=True)
            exit(10)

    def patch_issue(self, issue: iss.Issue):
        try:
            encoded = json.dumps(issue.patched_dict())
            r = self.session.patch(
                f'https://api.github.com/repos/{self.repo}/issues/{issue.number}', data=encoded)
            r.raise_for_status()
            return True
        except:
            return False

    def apply_strategy(self, issue: iss.Issue, owners, fallback):
        if self.strategy == 'append':
            return issue.append(owners)
        elif self.strategy == 'set':
            return issue.replace(owners)
        elif self.strategy == 'change':
            return issue.clear_add_reapply(owners)
        else:
            raise Exception(f'Unknown strategy {self.strategy}')

    def check_fallback(self, issue: iss.Issue, fallback):
         # apply fallback if needed
        if not issue.assignees and fallback is not None:
            return issue.apply_label(fallback)
        return []

    def has_changes(self, changes):
        return any(x.change_type != iss.CHANGE_REMAIN for x in changes)

    def proces_issues(self, rules, fallback, dry_run: bool):
        for issue in self.issues:
            changes = []
            applies = []
            for rule in rules:
                if rule.validate(issue):
                    applies.append(rule.owner)

            changes = self.apply_strategy(issue, applies, fallback)
            c = self.check_fallback(issue, fallback)
            for i in c:
                changes.append(i)

            changes.sort(key=lambda x: x.name.lower())

            if not dry_run and self.has_changes(changes) and not self.patch_issue(issue):
                changes = [iss.IssueChange(
                    iss.CHANGE_ERROR, f'Could not update issue {self.repo}#{issue.number}')]

            self.print_result(issue.number, issue.url, changes)

    def print_result(self, issue_id: str, url: str, changes=[]):
        click.echo('-> ', nl=False)
        click.secho(f'{self.repo}#{issue_id}', bold=True, nl=False)
        click.secho(f' ({url})')
        for change in changes:
            change.echo()
# --------------------------------------------------------------
