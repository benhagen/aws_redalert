from plugins import plugin, send_slack_message
import json


@plugin()
class securitygroup_writes(object):
	CLOUDWATCH_RULE_NAME = "sec_alerts_ec2"
	CLOUDWATCH_FILTER = {
		"EventPattern": {
			"detail-type": ["AWS API Call via CloudTrail"],
			"detail": {
				"eventSource": ["ec2.amazonaws.com"],
				"eventName": ["AuthorizeSecurityGroupIngress", "ModifySnapshotAttribute"]
			}
		}
	}

	def __init__(self, config):
		self.config = config

	def match(self, event):
		if event['detail']['eventName'] == "AuthorizeSecurityGroupIngress" and "errorCode" not in event['detail']:
			if len(event['detail']['requestParameters']['ipPermissions']) != 0:
				return True
		return False

	def process(self, event):
		text = "The securitygroup `{}` in account *{}/{}* ({}) was modified by `{}` from IP address `{}`. The following JSON describes the changes: ```{}```".format(
			event['detail']['requestParameters']['groupId'],
			self.config['ACCOUNTS'][event['account']]['name'],
			event['region'],
			event['account'],
			event['detail']['userIdentity']['arn'],
			event['detail']['sourceIPAddress'],
			json.dumps(event['detail']['requestParameters']['ipPermissions'], indent=4, sort_keys=True)
		)
		message = {
			"channel": self.config['SLACK_CHANNEL'],
			"username": "Security-Otter Bot",
			"icon_url": "http://d.hx.io/1NeN/2oFhQrsA.png",
			"attachments": [
				{
					"fallback": text,
					"color": "#36a64f",
					"title": "AWS SecurityGroup Modification",
					"text": text,
					"mrkdwn_in": ["text", "pretext"]
				}
			]
		}
		send_slack_message(message, self.config['SLACK_WEBHOOK'])
