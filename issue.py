import click

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
            if name not in self.assignees:
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

    def replace(self, names):
        changes = []
        if self.assignees:
            for a in self.assignees:
                changes.append(IssueChange(CHANGE_REMAIN, a))
        else:
            for a in self.assignees:
                changes.append(IssueChange(CHANGE_REMOVE, a))
            self.assignees = []
            for name in names:
                self.assignees.append(name)
                changes.append(IssueChange(CHANGE_ADD, name))
        return changes

    def apply_label(self, label):
        if label not in self.labels:
            self.labels.append(label)
            return [IssueChange(CHANGE_FALLBACK, f'added label "{label}"')]
        else:
            return [IssueChange(CHANGE_FALLBACK, f'already has label "{label}"')]

    def patched_dict(self):
        return {
            'labels': self.labels,
            'assignees': self.assignees
        }

    @staticmethod
    def from_json(json_data):
        labels = list(map(lambda x: x['name'], json_data['labels']))
        assignees = list(
            map(lambda x: x['login'], json_data['assignees']))
        return Issue(
            json_data['number'], json_data['html_url'], json_data['title'], json_data['body'], labels, assignees)
