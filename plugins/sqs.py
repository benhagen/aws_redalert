from plugins import plugin, send_slack_message
from cloudaudit.sqs import CheckWideOpen
from cloudaux import CloudAux
import logging
import json


@plugin()
class sqs_policy_updates(object):
    CLOUDWATCH_RULE_NAME = "sec_alerts_sqs"
    CLOUDWATCH_FILTER = {
        "EventPattern": {
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["sqs.amazonaws.com"],
                "eventName": ["SetQueueAttributes"]
            }
        }
    }

    def __init__(self, config):
        self.config = config

    def match(self, event):
        queue_url = event['detail']['requestParameters']['queueUrl']
        if queue_url in self.config.get('SQS_IGNORE_LIST', []):
            return False
        if event.get('detail', {}).get('errorCode'):
            return False
        role_arn_substr = "{role}/{session}".format(
            role=self.config.get('ENFORCE_ROLE'), session=self.config.get('SQS_ENFORCE_SESSION'))
        if role_arn_substr in event['detail']['userIdentity']['arn']:
            return False
        return True

    def queue_is_wide_open(self, event):
        policy = self.policy_from_event(event)
        if not policy:
            return False

        check = CheckWideOpen.check(policy)
        return bool(check)

    def create_policy(self, event):
        policy = self.policy_from_event(event)
        statements = []
        for statement in policy.get("Statement", []):
            if CheckWideOpen.check_statement(statement):
                continue
            statements.append(statement)

        if not statements:
            return ""

        policy['Statement'] = statements
        return policy

    def policy_from_event(self, event):
        policy = event['detail']['requestParameters']['attributes']['Policy']
        if policy:
            return json.loads(policy)
        return None

    def region_from_event(self, event):
        return event['detail']['awsRegion']

    def account_number_from_event(self, event):
        return event['account']

    def queue_url_from_event(self, event):
        return event['detail']['requestParameters']['queueUrl']

    def queue_name_from_event(self, event):
        return self.queue_url_from_event(event).split('/')[-1]

    def conn_details_from_event(self, event):
        return dict(
            account_number=self.account_number_from_event(event),
            assume_role=self.config.get('ENFORCE_ROLE'),
            session_name=self.config.get('SQS_ENFORCE_SESSION'),
            region=self.region_from_event(event)
        )

    def set_sqs_policy(self, event, policy):
        conn_details = self.conn_details_from_event(event)
        ca = CloudAux(**conn_details)
        if policy:
            policy = json.dumps(policy)
        ca.call('sqs.client.set_queue_attributes',
                QueueUrl=self.queue_url_from_event(event),
                Attributes=dict(Policy=policy))

    def notify(self, event, removed=None, total=None):
        text = "Who: `{who}`\nQueue Name: `{name}`\nRegion: `{region}`".format(
            name=self.queue_name_from_event(event),
            region=self.region_from_event(event),
            who=json.dumps(event.get('detail', {}).get('userIdentity', {}).get('arn')))

        title = "Found Wide-Open SQS Queue - {account_name} ({account_number})".format(
            account_name=self.config['ACCOUNTS'][event['account']]['name'],
            account_number=event['account'])

        if self.config.get('SQS_ENFORCE'):
            title = "Fixed Wide-Open SQS Queue. - {account_name} ({account_number})".format(
                account_name=self.config['ACCOUNTS'][event['account']]['name'],
                account_number=event['account'])
            rmv = "Removed {removed} of {total} statements.\n".format(removed=removed, total=total)
            text = rmv + text

        message = {
            "channel": self.config['SLACK_CHANNEL'],
            "username": "Security-Otter Bot",
            "icon_url": "http://d.hx.io/1NeN/2oFhQrsA.png",
            "attachments": [
                {
                    "fallback": text,
                    "color": "#36a64f",
                    "title": title,
                    "text": text,
                    "mrkdwn_in": ["text", "pretext"]
                }
            ]
        }
        logging.warn('SENDING SLACK MESSAGE')
        send_slack_message(message, self.config['SLACK_WEBHOOK'])

    def process(self, event):
        if not self.queue_is_wide_open(event):
            return

        original_statements = len(self.policy_from_event(event).get('Statement', []))
        final_statements = 0

        if self.config.get('SQS_ENFORCE'):
            policy = self.create_policy(event)
            if policy:
                final_statements = len(policy.get('Statement', ''))
            self.set_sqs_policy(event, policy)

        removed_statements = original_statements - final_statements
        self.notify(event, removed=removed_statements, total=original_statements)