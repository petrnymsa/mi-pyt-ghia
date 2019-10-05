import click
import re
import configparser
import requests
import json
# --------------------------------------------------------------
class Issue:
    def __init__(self,number,url, title, body, labels, assignees):
        self.number = number
        self.url = url
        self.title = title
        self.body = body
        self.labels = labels
        self.assignees = assignees
        self.freezed = []
    
    def add_assignee(self, name):
        self.assignees.append(name)
        self.freezed.append(name)

    def clear_add_reapply(self, name):
        self.assignees = []
        self._reapply_freezed()
        self.add_assignee(name)

    def _reapply_freezed(self):
        for f in self.freezed:
            self.assignees.append(f)
# --------------------------------------------------------------    
class IssueChange:
    def __init__(self, change_type, name):
        self.change_type=change_type
        self.name=name
        if(self.change_type == '+'):
            self.color='green'
        elif(self.change_type == '-'):
            self.color='red'
        else:
            self.color='blue'
    
    def echo(self):
        click.secho(f'   {self.change_type}', fg=self.color, nl=False)       
        click.echo(f' {self.name}')
# --------------------------------------------------------------
class Rule:
    def __init__(self,scope, pattern):        
        self.scope=scope
        self.pattern=pattern

    def _validate(self, input_text):
        return re.search(self.pattern, input_text) is not None
    
    def validate(self, issue:Issue):
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
        self.owner=owner
        self.rules=[]
    
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
        s+= ' }'
        return s    
# --------------------------------------------------------------
class GitHubApi:
    def __init__(self, token, repo, strategy):
        self.strategy = strategy
        self.token=token
        self.repo=repo
        self.session=requests.Session()
        self.session.auth = self.req_token_auth
        self.issues = []
    
    def req_token_auth(self, req):
        req.headers['Authorization'] = f'token {self.token}'
        return req
    def load_issues(self):        
        r = self.session.get('http://api.github.com/repos/mi-pyt-ghia/petrnymsa/issues?state=open') #todo replace with reposlug
        r.raise_for_status()

        loaded_issues = json.loads(r.text)
        self.issues = []
        for issue in loaded_issues:            
            labels = list(map(lambda x: x['name'], issue['labels']))
            assignees = list(map(lambda x: x['login'], issue['assignees']))
            self.issues.append(Issue(issue['number'],issue['url'], issue['title'], issue['body'], labels, assignees))
    
    def patch_issue(self, issue:Issue):
        #todo call PATCH with changes within issue
        encoded = json.dumps(issue.__dict__)
        pass
    
    def apply_strategy(self, issue: Issue, owner):
        if self.strategy == 'append':
            issue.add_assignee(owner)
        elif self.strategy == 'set':
            if not issue.assignees:
                issue.assignees = [owner]            
        elif self.strategy == 'change':
            issue.clear_add_reapply(owner)            
        else:
            raise Exception(f'Unknown strategy {self.strategy}')
    def proces_issues(self, rules, fallback):      
        print(f'Number of issues: {len(self.issues)}')  
        for issue in self.issues:
            changes = []
            for rule in rules:
                if rule.validate(issue):
                    change = self.apply_strategy(issue, rule.owner)
                    changes.append(change)
                #else:
                #    print(f'{issue.title}\trule {rule} not valid')
            print_result(self.repo, issue.number, issue.url, changes)

# --------------------------------------------------------------
def print_result(reposlug: str, issue_id: str, url: str, changes = [], fallback = False):
    click.echo('-> ',nl=False)
    click.secho(f'{reposlug}#{issue_id}', bold=True, nl=False)
    click.secho(f' {url}')
    for change in changes:
        change.echo()
    if fallback:
        click.secho('FALLBACK', bold=True, fg='yellow', nl=False)
        click.echo(': TODO')

def read_auth(auth_path):
    parser= configparser.ConfigParser()
    parser.read(auth_path)

    github_section=parser.items('github')
    return github_section[0][1]

def read_rules(rules_path):
    parser= configparser.ConfigParser()
    parser.read(rules_path)
    patterns=parser.items('patterns')
    rules=[]
    for pat in patterns:
        rule_set=RuleSet(pat[0])

        lines=list(filter(None, pat[1].split('\n')))
        for line in lines:
            r=line.split(':')
            rule_set.add(Rule(r[0], r[1]))
        rules.append(rule_set)
    
    if parser.has_section('fallback'):
        if not parser.has_option('fallback', 'label'):
            raise Exception('Fallback section is present but has no `label` configuration')        
        return (rules, parser.get('fallback', 'label'))      
    rules.sort(key=lambda x: x.owner)  
    return (rules, None)

@click.command()
@click.option('-s', '--strategy', type=click.Choice(['append', 'set', 'change'], case_sensitive=False),default='append',show_default=True, help='How to handle assignment collisions.')
@click.option('-a', '--config-auth',metavar='FILENAME', required=True, help='File with authorization configuration.')
@click.option('-r', '--config-rules',metavar='FILENAME',required=True, help='File with assignment rules configuration.')
@click.option('-d', '--dry-run', is_flag=True,help='Run without making any changes.')
@click.argument('reposlug')
def main(dry_run,strategy, config_auth, config_rules, reposlug):
    '''CLI tool for automatic issue assigning of GitHub issues'''
    print_result(reposlug, 'http://fakeurl', [IssueChange('+','petr'), IssueChange('-', 'martin'), IssueChange('=', 'mirek')], fallback=True)

    token = read_auth('credentials.cfg') #todo use parameter
    (rules, fallback) = read_rules('rules.cfg')

    

if __name__ == '__main__':
    (rules, fallback) = read_rules('rules.cfg')
    token = read_auth('credentials.cfg')
    api = GitHubApi(token, 'mi-pyt-ghia/petrnymsa', 'append')
    api.load_issues()
    api.proces_issues(rules, fallback)