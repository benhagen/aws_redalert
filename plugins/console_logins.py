from plugins import plugin, send_slack_message, ElasticSearchQuery
import logging

@plugin()
class console_logins(object):
	CLOUDWATCH_RULE_NAME = "sec_alerts_console_login"
	CLOUDWATCH_FILTER = {
		"EventPattern": {
			"detail-type": ["AWS Console Sign In via CloudTrail"]
		}
	}

	def __init__(self, config):
		self.config = config

	def match(self, event):
		if event.get("detail-type") == "AWS Console Sign In via CloudTrail" and event['detail']['eventName'] == "ConsoleLogin" and event['detail']['responseElements'].get('ConsoleLogin') != "Failure":
			query = ElasticSearchQuery(self.config['ELASTICSEARCH_SERVER'], self.config['ELASTICSEARCH_SERVER_REGION'], "cloudtrail-*")
			query.add_time_window((60 * 24 * 7))
			query.must.append({"term": {"userIdentity.arn": event['detail']['userIdentity']['arn']}})
			query.must.append({"term": {"sourceIPAddress": event['detail']['sourceIPAddress']}})
			query.must.append({"term": {"eventName": 'ConsoleLogin'}})
			query.must.append({"term": {"responseElements.ConsoleLogin": 'Success'}})
			query.must_not.append({"exists": {"field": "errorCode"}})
			result = query.query(count=True)
			print result
			if result:
				logging.warn("ES query for user console login returned {} results in the last week; not alerting.".format(result))
				return False
			else:
				logging.warn("ES query for user console login returned {} results in the last week; alerting.".format(result))
				return True
		return False

	def process(self, event):
		text = "*{}* (MFA: {}) logged in to the AWS console for *{}* ({}) from `{}` using: ```{}```".format(
			event['detail']['userIdentity']['arn'],
			event['detail']['additionalEventData']['MFAUsed'],
			self.config['ACCOUNTS'][event['account']]['name'],
			event['account'],
			event['detail']['sourceIPAddress'],
			event['detail']['userAgent']
		)
		message = {
			"channel": self.config['SLACK_CHANNEL'],
			"username": "Security-Otter Bot",
			"icon_url": "http://d.hx.io/1NeN/2oFhQrsA.png",
			"attachments": [
				{
					"fallback": text,
					"color": "#36a64f",
					"title": "AWS Console Login",
					"text": text,
					"mrkdwn_in": ["text", "pretext"]
				}
			]
		}
		send_slack_message(message, self.config['SLACK_WEBHOOK'])
