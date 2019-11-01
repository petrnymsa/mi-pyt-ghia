from .issue import Issue
import re


class Rule:
    def __init__(self, scope, pattern):
        self.scope = scope
        self.pattern = pattern

    def _validate(self, input_text):
        return re.search(self.pattern, input_text,  re.IGNORECASE) is not None

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
        return f'{self.scope}={self.pattern}'
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
