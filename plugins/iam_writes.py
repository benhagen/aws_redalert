from plugins import plugin, send_slack_message, startswithany
import json


@plugin()
class securitygroup_writes(object):
	CLOUDWATCH_RULE_NAME = "sec_alerts_iam"
	CLOUDWATCH_FILTER = {
		"EventPattern": {
			"detail-type": ["AWS API Call via CloudTrail"],
			"detail": {
				"eventSource": ["iam.amazonaws.com"]
			}
		}
	}

	def __init__(self, config):
		self.config = config

	def match(self, event):
		if event.get("source") == "aws.iam":
			if not startswithany(event['detail']['eventName'], ["List", "Get", "Delete", "Detach", "Generate", "Remove"]) and "jenkins" not in event['detail']['userIdentity']['arn'] and "gitlamb" not in event['detail']['userIdentity']['arn'] and ".com" not in event['detail']['sourceIPAddress']:
				return True
		return False

	def process(self, event):
		text = "```{}```".format(json.dumps(event, indent=4, sort_keys=True))
		message = {
			"channel": "#sec-alerts",
			"username": "Security-Otter Bot",
			"icon_url": "http://d.hx.io/1NeN/2oFhQrsA.png",
			"attachments": [
				{
					"fallback": text,
					"color": "#36a64f",
					"title": "AWS IAM Modification - {} {} ({})".format(event['detail']['eventName'], self.config['ACCOUNTS'][event['account']]['name'], event['account']),
					"text": text,
					"mrkdwn_in": ["text", "pretext"]
				}
			]
		}
		send_slack_message(message, self.config['SLACK_WEBHOOK'])
