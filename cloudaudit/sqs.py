from cloudaudit import BaseCheck
from cloudaudit.common.arn import ARN
import logging


class CheckWideOpen(BaseCheck):
    """
    # Original Issue:
    # An SQS policy where { 'Principal': { 'AWS': '*' } } must also
    #  have a {'Condition': {'ArnEquals': { 'AWS:SourceArn': '<ARN>' } } }
    # or it is open to the world. In this case, anyone is allowed to perform
    # this action(s): SQS:*
    """
    id = '9e274ff5-835a-4c1e-ac57-6732516314e4'
    text = 'Internet Accessible SQS Queue.'
    remedy = "An SQS policy where { 'Principal': { 'AWS': '*' } } must also have a {'Condition': {'ArnEquals': { 'AWS:SourceArn': '<ARN>' } } } or it is open to the world."
    default_score = 10

    # @staticmethod
    # def fields():
    #     return [fields.Policy]

    @classmethod
    def check_statement(cls, statement):
        principal = statement.get("Principal", None)
        if isinstance(principal, dict):
            principal = principal.get("AWS") or principal.get("Service")

        logging.warn('Principal: {}'.format(principal))

        if principal == "*":
            condition = statement.get('Condition', {})
            arns = ARN.extract_arns_from_statement_condition(condition)
            if not arns:
                return True
        return False


    @classmethod
    def check(cls, item):
        """
        alert when an SQS Queue is Internet Accessible.
        """
        notes = []
        for statement in item.get("Statement", []):
            if cls.check_statement(statement):
                notes.append('No Mitigating Condition ARNs')
                break

        return cls.from_notes(notes)
