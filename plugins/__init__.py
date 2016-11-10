import botocore.vendored.requests as requests
import json
from botocore.credentials import Credentials
from requests_aws_signer import AWSV4Sign
import time
from collections import OrderedDict
import os


PLUGINS = []


class plugin(object):
	# def __init__(self, regex=None, channels=None, hide_help=False):
	# 	self.channels = channels
	# 	self.regex = regex
	# 	self.hide_help = hide_help

	def __call__(self, func):
		def func_wrapper(*args, **kwargs):
			return func(*args, **kwargs)
		PLUGINS.append({"class": func_wrapper, "plugin_name": func.__name__})
		return func_wrapper


def send_slack_message(message, hook_url):
	response = requests.post(hook_url, data=json.dumps(message))
	return response


def startswithany(input_string, terms):
	for term in terms:
		if input_string.startswith(term):
			return True
	return False


class ElasticSearchQuery():

	def __init__(self, server, region, index):
		self.server = server
		self.index = index
		self.time_window_start = None
		self.time_window_stop = None

		self.must = []
		self.must_not = []
		self.aggregations = None
		if 'AWS_ACCESS_KEY_ID' in os.environ:
			self.credentials = Credentials(os.environ['AWS_ACCESS_KEY_ID'], os.environ['AWS_SECRET_ACCESS_KEY'], os.environ.get('AWS_SESSION_TOKEN'))
			self.awsauth = AWSV4Sign(self.credentials, region, "es")
		else:
			self.awsauth = None

	def add_time_window(self, duration, stop=None):
		if not stop:
			stop = int(time.time() * 1000)
		start = stop - (duration * 1000 * 60)
		self.must.append({"range": {"eventTime": {"gte": start, "lte": stop}}})

	def build_query(self):
		query = {
			"query": {
				"bool": {
					"must_not": self.must_not,
					"must": self.must
				}
			}
		}
		if self.aggregations:
			query['aggregations'] = self.aggregations
		return query

	def query(self, timeout=3, count=False):
		if count or self.aggregations:
			if self.awsauth:
				response = requests.post("https://{}/{}/_search?search_type=count&timeout={}m".format(self.server, self.index, timeout), data=json.dumps(self.build_query()), auth=self.awsauth)
			else:
				response = requests.post("https://{}/{}/_search?search_type=count&timeout={}m".format(self.server, self.index, timeout), data=json.dumps(self.build_query()))
			if count:
				response = response.json()
				if response.get("hits"):
					return int(response['hits']['total'])
				else:
					return None
		else:
			if self.awsauth:
				response = requests.post("https://{}/{}/_search?timeout={}m".format(self.server, self.index, timeout), data=json.dumps(self.build_query()), auth=self.awsauth)
			else:
				response = requests.post("https://{}/{}/_search?timeout={}m".format(self.server, self.index, timeout), data=json.dumps(self.build_query()))
		return response.json()

	def clean_aggregate_query(self, timeout=3):
		result = self.query(timeout=timeout)
		return clean_aggregate_values(result['aggregations'])


def clean_aggregate_values(aggregate):
	output = OrderedDict()
	for key, buckets in aggregate.items():
		output[key] = OrderedDict()
		for bucket in buckets['buckets']:
			output[key][bucket['key']] = {}
			output[key][bucket['key']]['_total'] = bucket['doc_count']
			for bucket_key, bucket_value in bucket.items():
				if isinstance(bucket_value, dict):
					nest = clean_aggregate_values({bucket_key: bucket_value})
					for nest_key, nest_value in nest.items():
						output[key][bucket['key']][nest_key] = nest_value
	return output
