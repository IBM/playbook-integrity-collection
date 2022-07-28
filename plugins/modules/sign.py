#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sign

short_description: signing module for Ansible resources

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: A module to sign ansible playbook SCM repo / execution environment image.

options:
    type:
        description:
        - A type of the resource to be signed. ["playbook"]
        - default: "playbook"
        required: false
        type: str
    target:
        description:
        - A target name of singing. Directory path for playbook signing.
        required: true
        type: str
    signature_type:
        description:
        - Signature type which will be used for signing. ["gpg"/"sigstore"/"sigstore_keyless"]
        - default: "gpg"
        required: false
        type: str
    private_key:
        description:
        - A path to your private key for signing. Only when "signature_type" is "gpg" or "sigstore"
        required: false
        type: str
    public_key:
        description:
        - A path to your public key for verification. If specified, the signed entity can be verified without specifying public key. Only when "signature_type" is "gpg" or "sigstore"
        required: false
        type: str
    keyless_signer_id:
        description:
        - A signer id of keyless singing. If specified, the signed entity can be verified without specifying signer id. Only when "signature_type" is "sigstore_keyless"
        required: false
        type: str
    
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - playbook.integrity.my_doc_fragment_name

author:
    - Your Name (@yourGitHubHandle)
'''

EXAMPLES = r'''
# Sign a playbook SCM repo
- name: Sign a playbook SCM repo
  playbook.integrity.sign:
    type: playbook
    target: path/to/playbookrepo
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

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.playbook.integrity.plugins.module_utils.sign import Signer

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        pwd=dict(type='str', required=False, default=""),
        type=dict(type='str', required=False, default="playbook"),
        target=dict(type='str', required=True),
        signature_type=dict(type='str', required=False, default="gpg"),
        private_key=dict(type='str', required=False, default=""),
        keyid=dict(type='str', required=False, default=""),
        passphrase=dict(type='str', required=False, default=""),
        keyless_signer_id=dict(type='str', required=False, default=""),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    signer = Signer(module.params)
    try:
        sign_result = signer.sign()
    except Exception:
        sign_result = {"failed": True}
        sign_result["traceback"] = traceback.format_exc()
    result['detail'] = sign_result

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    result['changed'] = True

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if sign_result.get("failed", False):
        module.fail_json(msg='Signing failed', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
