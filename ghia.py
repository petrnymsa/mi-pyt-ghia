import click
import re
import configparser
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
        click.secho(self.change_type, fg=self.color, nl=False)       
        click.echo(f' {self.name}')
# --------------------------------------------------------------
class Rule:
    def __init__(self,scope, pattern):        
        self.scope=scope
        self.pattern=pattern

    def _validate_title(self, title):
        return re.match(self.pattern, title)

    def validate(self, input):
        if(self.scope == 'title'):
            pass
        elif(self.scope == 'text'):
            pass
        elif(self.scope == 'label'):
            pass
        elif(self.scope == 'any'):
            pass
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

    def validate(self, input):
        for rule in self.rules:
            if rule.validate():
                pass
    
    def __str__(self):
        s = self.owner + '\n'
        for r in self.rules:
            s += r.scope + ':' + r.pattern + '\n'
        return s
# --------------------------------------------------------------
def print_result(reposlug, url, changes = [], fallback = False):
    click.echo('-> ',nl=False)
    click.secho(reposlug, bold=True, nl=False)
    click.secho(f' {url}')
    for change in changes:
        change.echo()
    if fallback:
        click.secho('FALLBACK', bold=True, fg='yellow', nl=False)
        click.echo(': TODO')

def read_auth(auth_path):
    pass
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

    print(rules)
    return rules

@click.command()
@click.option('-s', '--strategy', type=click.Choice(['append', 'set', 'change'], case_sensitive=False),default='append',show_default=True, help='How to handle assignment collisions.')
@click.option('-a', '--config-auth',metavar='FILENAME', required=True, help='File with authorization configuration.')
@click.option('-r', '--config-rules',metavar='FILENAME',required=True, help='File with assignment rules configuration.')
@click.option('-d', '--dry-run', is_flag=True,help='Run without making any changes.')
@click.argument('reposlug')
def main(dry_run,strategy, config_auth, config_rules, reposlug):
    '''CLI tool for automatic issue assigning of GitHub issues'''
    print_result(reposlug, 'http://fakeurl', [IssueChange('+','petr'), IssueChange('-', 'martin'), IssueChange('=', 'mirek')], fallback=True)

if __name__ == '__main__':
    read_rules('rules.cfg')