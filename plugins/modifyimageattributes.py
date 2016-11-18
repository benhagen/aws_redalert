from plugins import plugin, send_slack_message
import logging


@plugin()
class modifyimageattributes(object):
	# This is covered in the securitygroup_writes plugin's ec2 filter
	CLOUDWATCH_RULE_NAME = None
	CLOUDWATCH_FILTER = None

	def __init__(self, config):
		self.config = config

	def match(self, event):
		if "errorCode" not in event['detail'] and event['detail']['eventName'] == "ModifySnapshotAttribute" and event['detail']['requestParameters']['attributeType'] == "CREATE_VOLUME_PERMISSION":
			for item in event['detail']['requestParameters']['createVolumePermission']['add']['items']:
				if item.get("userId") not in self.config['ACCOUNTS']:
					logging.warn("Snapshot has been shared with an untrusted account; alerting.")
					return True
		return False

	def process(self, event):
		for item in event['detail']['requestParameters']['createVolumePermission']['add']['items']:
			if item.get("userId") not in self.config['ACCOUNTS']:
				text = "Snapshot `{}` has been shared with untrusted AWS account `{}` by `{}` from IP address `{}`".format(
					event['detail']['requestParameters']['snapshotId'],
					item.get("userId"),
					event['detail']['userIdentity']['arn'],
					event['detail']['sourceIPAddress'],
				)
				message = {
					"channel": self.config['SLACK_CHANNEL'],
					"username": "Security-Otter Bot",
					"icon_url": "http://d.hx.io/1NeN/2oFhQrsA.png",
					"attachments": [
						{
							"fallback": text,
							"color": "#36a64f",
							"title": "AWS snapshot shared from {} ({}/{})".format(self.config['ACCOUNTS'][event['account']]['name'], event['account'], event['region']),
							"text": text,
							"mrkdwn_in": ["text", "pretext"]
						}
					]
				}
				send_slack_message(message, self.config['SLACK_WEBHOOK'])
