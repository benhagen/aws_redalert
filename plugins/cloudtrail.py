from plugins import plugin, send_slack_message, startswithany
import json


@plugin()
class cloudtrail(object):
	CLOUDWATCH_RULE_NAME = "sec_alerts_cloudtrail"
	CLOUDWATCH_FILTER = {
		"EventPattern": {
			"detail-type": ["AWS API Call via CloudTrail"],
			"detail": {
				"eventSource": ["cloudtrail.amazonaws.com"]
			}
		}
	}

	def __init__(self, config):
		self.config = config

	def match(self, event):
		if event.get("source") == "aws.cloudtrail":
			if not startswithany(event['detail']['eventName'], ["Create", "Lookup"]):
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
					"title": "AWS CloudTrail Modification - {} {} ({})".format(event['detail']['eventName'], self.config['ACCOUNTS'][event['account']]['name'], event['account']),
					"text": text,
					"mrkdwn_in": ["text", "pretext"]
				}
			]
		}
		send_slack_message(message, self.config['SLACK_WEBHOOK'])
