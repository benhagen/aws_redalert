#!/usr/bin/env python

import json
import boto3
import logging
from plugins import securitygroup_writes, console_logins, iam_writes, modifyimageattributes, cloudtrail, route53
from plugins import *


# Load the configuration file
with open("./config.json") as fh:
	CONFIG = json.load(fh)
Session = boto3.Session()
# Pull in the current account number
CONFIG['CURRENT_ACCOUNT'] = Session.client("sts").get_caller_identity()['Account']


def lambda_handler(event, context=None):
	logging.warn(json.dumps(event))

	if event.get("action") == "configure":
		if context:
			region = context.invoked_function_arn.split(":")[3]
		else:
			region = "us-east-1"
		configure_events(region)
		return

	if 'detail' in event:
		for plugin in PLUGINS:
			plugin_instance = plugin['class'](CONFIG)
			if plugin_instance.match(event):
				logging.warn("Event matched plugin '{}'".format(plugin['plugin_name']))
				plugin_instance.process(event)
	return


def configure_events(region):
	events_client = boto3.client('events', region_name=region)
	response = events_client.list_rules(NamePrefix='sec_alerts')
	current_rules = {}

	cloudwatch_event_rules = {}
	for plugin in PLUGINS:
		plugin_instance = plugin['class'](CONFIG)
		if plugin_instance.CLOUDWATCH_FILTER:
			cloudwatch_event_rules[plugin_instance.CLOUDWATCH_RULE_NAME] = plugin_instance.CLOUDWATCH_FILTER

	for rule in response['Rules']:
		current_rules[rule['Name']] = {'EventPattern': json.loads(rule['EventPattern'])}
	for rule_name, rule in current_rules.items():
		if rule_name not in cloudwatch_event_rules:
			logging.warn("[-] Deleting extraneous rule'{}'".format(rule_name))
			events_client.delete_rule(Name=rule_name)
		else:
			if json.dumps(rule['EventPattern'], sort_keys=True) != json.dumps(cloudwatch_event_rules[rule_name]['EventPattern'], sort_keys=True):
				logging.warn("[~] Updating rule '{}'".format(rule_name))
				events_client.put_rule(Name=rule_name, EventPattern=json.dumps(cloudwatch_event_rules[rule_name]['EventPattern'], sort_keys=True), State='ENABLED')
	for rule_name, rule in cloudwatch_event_rules.items():
		if rule_name not in current_rules:
			logging.warn("[+] Creating missing rule'{}'".format(rule_name))
			events_client.put_rule(Name=rule_name, EventPattern=json.dumps(rule['EventPattern'], sort_keys=True), State='ENABLED')

	function_arn = "arn:aws:lambda:{}:{}:function:sec_alerts".format(region, CONFIG['CURRENT_ACCOUNT'])
	lambda_client = boto3.client('lambda', region_name=region)
	try:
		response = lambda_client.get_policy(FunctionName="sec_alerts")
	except:
		policy = None
	else:
		policy = json.loads(response['Policy'])

	for rule_name, rule in cloudwatch_event_rules.items():
		has_target = False
		response = events_client.list_targets_by_rule(Rule=rule_name)
		for target in response['Targets']:
			if target['Arn'] == function_arn:
				has_target = True
		if not has_target:
			logging.warn("[+] Adding target to event '{}'".format(rule_name))
			events_client.put_targets(Rule=rule_name, Targets=[{'Id': 'string', 'Arn': function_arn}])
		has_permission = False
		rule_arn = "arn:aws:events:{}:{}:rule/{}".format(region, CONFIG['CURRENT_ACCOUNT'], rule_name)
		if policy:
			for statement in policy['Statement']:
				if statement.get('Condition', {}).get('ArnLike', {}).get('AWS:SourceArn') == rule_arn:
					has_permission = True
		if not has_permission:
			logging.warning("[+] Adding rule permission for event '{}'".format(rule_name))
			lambda_client.add_permission(FunctionName="sec_alerts", StatementId=rule_name, Action='lambda:InvokeFunction', Principal="events.amazonaws.com", SourceArn="arn:aws:events:{}:{}:rule/{}".format(region, CONFIG['CURRENT_ACCOUNT'], rule_name))


if __name__ == '__main__':
	print "Howdy"
