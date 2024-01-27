#!/usr/bin/env python
import configparser
from deepdiff import DeepDiff
import json
from junit_xml import TestSuite, TestCase
import os
from pprint import pprint
import subprocess
import sys
from typing import Any
from jinja2 import Template
import yaml

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

def run_lambda_get_response(lambda_name: str, event_string: str) -> dict[str, Any]:
  with open('request.json', 'w') as fp:
    fp.write(event_string)
  json_out = subprocess.check_output([
    'awslocal', 'lambda', 'invoke',
    '--function-name', lambda_name,
    '--invocation-type', 'RequestResponse',
    '--payload', 'fileb://request.json',
    './response.json'
  ])

  with open('response.json', 'r') as fp:
    return json.load(fp)


def run_tests(lambda_name: str):
  print(f'Initializing tests for lambda: {lambda_name}')
  # Read in the tests YAML file
  try:
    with open(f'{SCRIPT_DIR}/tests.yaml', 'r') as fp:
      tests = yaml.full_load(fp)
      #for key, value in yaml.load(fp).iteritems():
  except FileNotFoundError:
    print('Failed to find tests.yaml file in script directory')
    sys.exit(1)

  # Load the testing default values
  config = configparser.ConfigParser()
  config.read(f'{SCRIPT_DIR}/testing.ini')
  conf = {s:dict(config.items(s)) for s in config.sections()}

  # Load the event JINJA template
  try:
    with open(f'{SCRIPT_DIR}/event_template.json', 'r') as fp:
      event_template = fp.read()
  except FileNotFoundError:
    print('Failed to find event_template.json file in script directory')
    sys.exit(3)


  # Run each test by transforming the template based on the testing values,
  # executing the Lambda, then checking the results. Fill out any missing field 
  # values with default field values. Store the output as JUnit test results.
  failed = False
  junit_tests = []
  for test_name, tv in tests.items():
    print(f'Executing test: {test_name}')
    vals = {f: tv[f] if f in tv else conf['rewrite_defaults'][f] for f in conf['required_fields']['rewrite'].split(',')}
    t = Template(event_template) 
    test_event = t.render(vals)
    test_case = TestCase(name=test_name, classname=tv['uri'])

    # Run the lambda and get the result
    r_dict = run_lambda_get_response(lambda_name, test_event)

    # Check the actual results against the desired results
    diff = DeepDiff(tv['response'], r_dict)
    if diff:
      print('Test failed:')
      pprint(diff)
      pprint(r_dict)
      failed = True
      test_case.add_failure_info(message='Rewrite test failed', output=(f'{str(diff)}\n{str(r_dict)}'))
    else:
      print('Test passed')

    junit_tests.append(test_case)

  # Write the JUnit tests to a file
  test_output_dir = os.path.abspath(f'{SCRIPT_DIR}/../testing_output')
  if not os.path.exists(test_output_dir):
    os.mkdir(test_output_dir)
  with open(f'{test_output_dir}/tests.xml', 'w') as fp:
    TestSuite.to_file(fp, [TestSuite(name='Rewrite Lambda tests', test_cases=junit_tests)])

  if failed:
    sys.exit(99)


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print(f'Usage: tester.py <lambda name>')
    sys.exit(1)
  run_tests(sys.argv[1])