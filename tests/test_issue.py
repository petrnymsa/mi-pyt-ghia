import ghia.issue as iss


def create_issue(labels, assignees):
    return iss.Issue(10, 'url', 'title', 'body', labels, assignees)


def test_append_no_one_assigned():
    i = create_issue([], [])
    changes = i.append(['a', 'b'])
    assert changes == [iss.IssueChange(
        iss.CHANGE_ADD, 'a'), iss.IssueChange(iss.CHANGE_ADD, 'b')]
    assert i.assignees == ['a', 'b']


def test_append_already_assigned():
    i = create_issue([], ['a'])
    changes = i.append(['a', 'b'])
    assert changes == [iss.IssueChange(
        iss.CHANGE_REMAIN, 'a'), iss.IssueChange(iss.CHANGE_ADD, 'b')]
    assert i.assignees == ['a', 'b']


def test_append_empty_input():
    i = create_issue([], ['a'])
    changes = i.append([])
    assert changes == [iss.IssueChange(
        iss.CHANGE_REMAIN, 'a')]
    assert i.assignees == ['a']


def test_issue_replace_no_one():
    i = create_issue([], [])

    result = i.replace(['a'])
    assert result == [iss.IssueChange(iss.CHANGE_ADD, 'a')]
    assert i.assignees == ['a']


def test_issue_replace_already_assigned():
    assignees = ['a']
    i = create_issue([], assignees)

    result = i.replace(['b'])
    assert result == [iss.IssueChange(iss.CHANGE_REMAIN, 'a')]
    assert i.assignees == assignees


def test_issue_replace_empty_input():
    i = create_issue([], ['a'])

    result = i.replace([])
    assert result == [iss.IssueChange(iss.CHANGE_REMAIN, 'a')]
    assert i.assignees == ['a']


def test_clear_add_reapply_no_one_assigned():
    i = create_issue([], [])
    i.append(['a'])  # by rules should be assigned

    result = i.clear_add_reapply(['b'])
    assert result == [iss.IssueChange(iss.CHANGE_REMAIN, 'a'),
                      iss.IssueChange(iss.CHANGE_ADD, 'b')]
    assert i.assignees == ['a', 'b']


def test_clear_add_reapply_already_assigned():
    i = create_issue([], ['a'])
    i.append(['b'])  # by rules should be assigned

    result = i.clear_add_reapply(['c'])
    assert result == [iss.IssueChange(iss.CHANGE_REMOVE, 'a'),
                      iss.IssueChange(iss.CHANGE_REMAIN, 'b'),
                      iss.IssueChange(iss.CHANGE_ADD, 'c')]
    assert i.assignees == ['b', 'c']


def test_clear_add_reapply_empty_input():
    i = create_issue([], ['a'])
    i.append(['b'])  # by rules should be assigned

    result = i.clear_add_reapply([])
    assert result == [iss.IssueChange(iss.CHANGE_REMOVE, 'a'),
                      iss.IssueChange(iss.CHANGE_REMAIN, 'b')]

    assert i.assignees == ['b']


def test_apply_label_add():
    i = create_issue([], [])
    result = i.apply_label('test')
    assert result == [iss.IssueChange(
        iss.CHANGE_FALLBACK, f'added label "test"')]
    assert i.labels == ['test']


def test_apply_label_add_second():
    i = create_issue(['test'], [])
    result = i.apply_label('important')
    assert result == [iss.IssueChange(
        iss.CHANGE_FALLBACK, f'added label "important"')]
    assert i.labels == ['test', 'important']


def test_apply_label_already_have():
    i = create_issue(['test'], [])
    result = i.apply_label('test')
    assert result == [iss.IssueChange(
        iss.CHANGE_FALLBACK, f'already has label "test"')]
    assert i.labels == ['test']
