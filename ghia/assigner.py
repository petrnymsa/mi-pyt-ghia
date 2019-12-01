import requests
import click
import json
import ghia.issue as iss


class GitHubIssueAssigner:
    def __init__(self, token, repo, session=None, strategy='append'):
        self.strategy = strategy
        self.token = token
        self.repo = repo
        self.session =  session or requests.Session()
        self.session.auth = self._req_token_auth
        self.issues = []

    def _req_token_auth(self, req):
        req.headers['Authorization'] = f'token {self.token}'
        return req

    def _parse_issues(self, response):
        loaded_issues = json.loads(response)

        for json_issue in loaded_issues:
            self.issues.append(iss.Issue.from_json(json_issue))

    def _patch_issue(self, issue: iss.Issue):
        try:
            encoded = json.dumps(issue.patched_dict())
            r = self.session.patch(
                f'https://api.github.com/repos/{self.repo}/issues/{issue.number}', data=encoded)
            r.raise_for_status()
            return True
        except:
            return False

    def _apply_strategy(self, issue: iss.Issue, owners):
        if self.strategy == 'append':
            return issue.append(owners)
        elif self.strategy == 'set':
            return issue.replace(owners)
        elif self.strategy == 'change':
            return issue.clear_add_reapply(owners)
        else:
            raise Exception(f'Unknown strategy {self.strategy}')

    def _check_fallback(self, issue: iss.Issue, fallback):
         # apply fallback if needed
        if not issue.assignees and fallback is not None:
            return issue.apply_label(fallback)
        return []

    def _has_changes(self, changes):
        return any(x.change_type != iss.CHANGE_REMAIN for x in changes)

    def set_strategy(self, strategy):
        self.strategy = strategy

    def load_issues(self):
        try:
            self.issues = []
            url = f'https://api.github.com/repos/{self.repo}/issues?state=open'
            r = self.session.get(url)
            r.raise_for_status()

            while 'next' in r.links:
                self._parse_issues(r.text)

                url = r.links['next']['url']
                r = self.session.get(url)
                r.raise_for_status()

            self._parse_issues(r.text)
        except:
            click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
            click.echo(
                f': Could not list issues for repository {self.repo}', err=True)
            exit(10)

    def process(self, rules, fallback, dry_run: bool):
        for issue in self.issues:
            applies = []
            for rule in rules:
                if rule.validate(issue):
                    applies.append(rule.owner)

            changes = self._apply_strategy(issue, applies)
            c = self._check_fallback(issue, fallback)
            for i in c:
                changes.append(i)

            changes.sort(key=lambda x: x.name.lower())

            if not dry_run and self._has_changes(changes) and not self._patch_issue(issue):
                changes = [iss.IssueChange(
                    iss.CHANGE_ERROR, f'Could not update issue {self.repo}#{issue.number}')]

            self._print_result(issue.number, issue.url, changes)

    def _print_result(self, issue_id: str, url: str, changes=[]):
        click.echo('-> ', nl=False)
        click.secho(f'{self.repo}#{issue_id}', bold=True, nl=False)
        click.secho(f' ({url})')
        for change in changes:
            change.echo()
# --------------------------------------------------------------
