#!/usr/bin/python

# Copyright: (c) 2022, Julian Ortel <julian@ortel.tech>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: splunkbase

short_description: This module downloads apps from splunkbase.com

description: This module authenticates on splunkbase.com and downloads an specified app

options:
    app:
        description: This is the app which should get downloaded. Needs to be either the id or complete splunkbase url
        required: true
        type: str
    version:
        description: Version of the app listed on splunkbase.com. If none is specified latest version will be downloaded.
        required: false
        type: str
    dest:
        description: Absolute path of where to download the file to.
        required: true
        type: str
    username:
        description: splunkbase username for authentication
        required: true
        type: str
    password:
        description: splunkbase password for authentication
        required: true
        type: str

author:
    - Julian Ortel (@M3NIX)
'''

EXAMPLES = r'''
# download latest app with id
- name: download app
  splunkbase:
    app: 3435
    dest: /tmp/
    username: my_user
    password: my_password

# download latest app with url
- name: download app
  splunkbase:
    app: "https://splunkbase.splunk.com/app/3435/"
    dest: /tmp/
    username: my_user
    password: my_password

# download specific version of app with id
- name: download app
  splunkbase:
    app: 3435
    version: 3.5.0
    dest: /tmp/
    username: my_user
    password: my_password

'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
'''

import re
import os
import requests
import datetime
import tempfile
from ansible.module_utils.basic import AnsibleModule

def run_module():
    module_args = dict(
        dest=dict(type='path', required=True),
        app=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        version=dict(type='str'),
        tmp_dest=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        add_file_common_args=True,
        supports_check_mode=True,
        mutually_exclusive=[['checksum', 'sha256sum']],
    )

    if module.check_mode:
        module.exit_json(**result)

    splunkbase_url = "https://splunkbase.splunk.com"
    dest = module.params['dest']
    app = module.params['app']
    username = module.params['username']
    password = module.params['password']
    version = module.params['version']
    tmp_dest = module.params['tmp_dest']

    result = dict(
        changed=False,
        checksum_dest=None,
        checksum_src=None,
        dest=dest,
        elapsed=0,
        url=app,
    )

    # authenticate
    token_request = requests.post(f"{splunkbase_url}/api/account:login", data={ "username": username, "password": password})
    if token_request.status_code != 200:
        module.fail_json(msg='Authentication failed', **result)
    token = re.search("<id>(.*)<\/id>", token_request.text).group(1)

    # check if splunkbase url or single id
    app_id = app
    if re.match("https:\/\/splunkbase\.splunk\.com\/app\/[0-9]+", app_id):
        app_id = re.search("https:\/\/splunkbase\.splunk\.com\/app\/([0-9]+)",app_id).group(1)

    # get app info
    app_info_request = requests.get(f"{splunkbase_url}/api/v1/app/{app_id}/?include=all")
    if app_info_request.status_code != 200:
        module.fail_json(msg='Could not find an app with supplied id', **result)
    app_info = app_info_request.json()

    # get latest version if none is specified
    if version is None:
        version = app_info["releases"][0]["title"]

    # check if specified version exists
    if version not in list((i["title"]) for i in app_info["releases"]):
        module.fail_json(msg='Could not find the app with supplied version', **result)

    # download app
    start = datetime.datetime.utcnow()
    download_url = f"{splunkbase_url}/app/{app_id}/release/{version}/download"
    result['url'] = download_url
    rsp = requests.get(download_url, headers={ "X-Auth-Token": token})
    elapsed = (datetime.datetime.utcnow() - start).seconds
    result['elapsed'] = elapsed

    # create a temporary file and copy content to do checksum-based replacement
    if tmp_dest:
        # tmp_dest should be an existing dir
        tmp_dest_is_dir = os.path.isdir(tmp_dest)
        if not tmp_dest_is_dir:
            if os.path.exists(tmp_dest):
                module.fail_json(msg="%s is a file but should be a directory." % tmp_dest, elapsed=elapsed)
            else:
                module.fail_json(msg="%s directory does not exist." % tmp_dest, elapsed=elapsed)
    else:
        tmp_dest = module.tmpdir

    fd, tempname = tempfile.mkstemp(dir=tmp_dest)
    f = os.fdopen(fd, 'wb')
    try:
        f.write(rsp.content)
    except Exception as e:
        os.remove(tempname)
        module.fail_json(msg="failed to create temporary content file: %s" % to_native(e), elapsed=elapsed, exception=traceback.format_exc())
    f.close()

    result['src'] = tempname

    # copy tempfile to dest
    dest_is_dir = os.path.isdir(dest)
    last_mod_time = None
    if dest_is_dir:
        filename = app_info["appid"]
        dest = os.path.join(dest, f"{filename}_{version}.tar.gz")
        result['dest'] = dest

    tmpsrc = tempname
    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        os.remove(tmpsrc)
        module.fail_json(msg="Request failed", status_code=rsp.status_code, **result)
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        module.fail_json(msg="Source %s is not readable" % (tmpsrc), **result)
    result['checksum_src'] = module.sha1(tmpsrc)

    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination %s is not writable" % (dest), **result)
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination %s is not readable" % (dest), **result)
        result['checksum_dest'] = module.sha1(dest)
    else:
        if not os.path.exists(os.path.dirname(dest)):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination %s does not exist" % (os.path.dirname(dest)), **result)
        if not os.access(os.path.dirname(dest), os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination %s is not writable" % (os.path.dirname(dest)), **result)

    if result['checksum_src'] != result['checksum_dest']:
        try:
            module.atomic_move(tmpsrc, dest, unsafe_writes=module.params['unsafe_writes'])
        except Exception as e:
            if os.path.exists(tmpsrc):
                os.remove(tmpsrc)
            module.fail_json(msg="failed to copy %s to %s: %s" % (tmpsrc, dest, to_native(e)),
                             exception=traceback.format_exc(), **result)
        result['changed'] = True
    else:
        result['changed'] = False
        if os.path.exists(tmpsrc):
            os.remove(tmpsrc)

    # allow file attribute changes
    file_args = module.load_file_common_arguments(module.params, path=dest)
    result['changed'] = module.set_fs_attributes_if_different(file_args, result['changed'])

    # Mission complete
    module.exit_json(status_code=rsp.status_code, **result)

def main():
    run_module()

if __name__ == '__main__':
    main()
