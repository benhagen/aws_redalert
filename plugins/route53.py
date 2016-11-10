from plugins import plugin, send_slack_message, startswithany
import json


@plugin()
class route53(object):
	CLOUDWATCH_RULE_NAME = "sec_alerts_route53"
	CLOUDWATCH_FILTER = {
		"EventPattern": {
			"detail-type": ["AWS API Call via CloudTrail"],
			"detail": {
				"eventSource": ["route53.amazonaws.com"]
			}
		}
	}

	def __init__(self, config):
		self.config = config

	def match(self, event):
		if event.get("source") == "aws.route53":
			if not startswithany(event['detail']['eventName'], ["Create", "Associate"]):
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
					"title": "AWS Route53 Modification - {} {} ({})".format(event['detail']['eventName'], self.config['ACCOUNTS'][event['account']]['name'], event['account']),
					"text": text,
					"mrkdwn_in": ["text", "pretext"]
				}
			]
		}
		send_slack_message(message, self.config['SLACK_WEBHOOK'])
