# Copyright (c) 2017 LAYER4
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: oozie_coordinator
short_description: Sets attributes of files stored in HDFS.
description:
    - Sets attributes of files and directories, or removes files/directories.
author: "Vincent Devillers (@treydone)"
options:
    state:
        description:
          - Desired state of the target
        choices: ['present', 'absent']
    other_param:
        description:
          - What does this do?
notes:
    - TODO
requirements:
  - "python >= 2.6"
'''

EXAMPLES = '''
# ensure coordinator is deployed
- oozie_coordinator:
    path=files/worflow.xml.j2 state=present
'''

#
# python core, ansible imports
#
import os
from ansible.module_utils.basic import *

#
# custom imports
#

DEPENDENCIES_OK = True  # use flag as we want to use module.fail_json for errors
try:
    import requests
except ImportError, e:
    DEPENDENCIES_OK = False

def run(module):
  url = module.params['url']
  user = module.params['user']
  password = module.params['password']

  state = module.params['state']

  # TODO

  module.fail_json(changed=False)

def main():
  module = AnsibleModule(
      argument_spec = dict(
        state = dict(required=True, type='string', choices=['directory', 'absent']),
        url=dict(required=True, type='string'),
        user=dict(required=True, type='string'),
        password=dict(required=True, type='string'),
      required_together = (),
      mutually_exclusive = (),
      required_one_of = (),
      supports_check_mode=True
  )

  # validations and checks
  # note: module.fail_json stops execution of the module
  if not DEPENDENCIES_OK:
      module.fail_json(msg='`requests` library required for this module (`pip install requests`)')

  # Run logic, manage errors
  try:
      run(module)
  except Exception as e:
      import traceback
      module.fail_json(msg=str(e) + str(traceback.format_exc()))

if __name__ == '__main__':
    main()
