import configparser
import os.path
import click
import re
# --------------------------------------------------------------
from issue import Issue, IssueChange
from rule import Rule, RuleSet
from assigner import GitHubIssueAssigner
import configreader
import cli
# --------------------------------------------------------------


# ---------------------------------------------------------------------


if __name__ == '__main__':
    cli.run()
