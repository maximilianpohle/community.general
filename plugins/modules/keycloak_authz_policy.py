#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Eike Frost <ei@kefro.st>
# Copyright (c) 2021, Christophe Gilles <christophe.gilles54@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or
# https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function
import json
__metaclass__ = type

DOCUMENTATION = '''
---
module: keycloak_authz_policy

version_added: 8.6.0

short_description: Allows administration of Keycloak client authorization resources via Keycloak API

description:
    - This module allows the administration of Keycloak client authorization resources via the Keycloak REST
      API. Authorization resources are only available if a client has Authorization enabled.

    - This module requires access to the REST API via OpenID Connect; the user connecting and the realm
      being used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate realm definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase options used by Keycloak.
      The Authorization Services paths and payloads have not officially been documented by the Keycloak project.
      U(https://www.puppeteers.net/blog/keycloak-authorization-services-rest-api-paths-and-payload/)

attributes:
    check_mode:
        support: full
    diff_mode:
        support: full

options:
    state:
        description:
            - State of the authorization resource.
            - On V(present), the authorization resource will be created (or updated if it exists already).
            - On V(absent), the authorization resource will be removed if it exists.
        choices: ['present', 'absent']
        default: 'present'
        type: str
    name:
        description:
            - Name of the authorization resource to create.
        type: str
        required: true
    displayName:
        description:
            - The displayName of the authorization resource.
        type: str
        required: false
    client_id:
        description:
            - The clientId of the keycloak client that should have the authorization scope.
            - This is usually a human-readable name of the Keycloak client.
        type: str
        required: true
    realm:
        description:
            - The name of the Keycloak realm the Keycloak client is in.
        type: str
        required: true
    icon_uri:
        description:
            - A URI pointing to an icon.
        type: str
        required: false
    uris:
        description:
            - Set of URIs which are protected by resource.
        type: list
        elements: str
        required: false
        default: []
    type:
        description:
            - OpenID Connect allows Clients to verify the identity of the End-User based on the
              authentication performed by an Authorization Server.
            - SAML enables web-based authentication and authorization scenarios including cross-domain
              single sign-on (SSO) and uses security tokens containing assertions to pass information.
        type: str
        required: false
    attributes:
        description:
            - The attributes associated wth the resource.
        type: dict
        required: false
        default: {}
    ownerManagedAccess:
        description:
            - If enabled, the access to this resource can be managed by the resource owner.
        type: bool
        required: false
        default: false

extends_documentation_fragment:
    - community.general.keycloak
    - community.general.attributes

author:
    - Maximilian Pohle (@mattock)
'''

EXAMPLES = '''
- name: Manage scope-based Keycloak authorization resource
  community.general.keycloak_authz_resource:
    name: test-resource
    state: present
    displayName: test-resource
    client_id: myclient
    realm: myrealm
    auth_keycloak_url: http://localhost:8080/auth
    auth_username: keycloak
    auth_password: keycloak
    auth_realm: master
'''

RETURN = '''
msg:
    description: Message as to what action was taken.
    returned: always
    type: str

end_state:
    description: Representation of the authorization resource after module execution.
    returned: on success
    type: complex
    contains:
        _id:
            description: ID of the authorization resource.
            type: str
            returned: when O(state=present)
            sample: 9da05cd2-b273-4354-bbd8-0c133918a454
        attributes:
            description: The attributes associated wth the resource.
            type: dict
            returned: when O(state=present)
            sample: {"foo": "bar"}
        displayName:
            description: Name of the authorization resource to create.
            type: dict
            returned: when O(state=present)
            sample: test-resource
        owner:
            description: Owner of the authorization resource.
            type: str
            returned: when O(state=present)
            sample: {"id": "003-nc.003", "name": "nc.003"}
        ownerManagedAccess:
            description: If enabled, the access to this resource can be managed by the resource owner.
            type: str
            returned: when O(state=present)
            sample: false
        uris:
            description: Set of URIs which are protected by resource.
            type: str
            returned: when O(state=present)
            sample: ["http://localhost:8080"]

'''

from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import KeycloakAPI, \
    keycloak_argument_spec, get_token, KeycloakError
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = keycloak_argument_spec()

    meta_args = dict(
        state=dict(type='str', default='present',
                   choices=['present', 'absent']),
        client_id=dict(type='str', required=True),
        realm=dict(type='str', required=True),
        name=dict(type='str', required=True),
        type=dict(type='str', required=True, choices=['group']),
        groups=dict(type='list', elements='dict', default=[], required=False),
        logic=dict(type='str', required=True, choices=['POSITIVE', 'NEGATIVE']),
        decisionStrategy=dict(type='str', required=True),
        description=dict(type='str', required=False),
        groupsClaim=dict(type='str', required=False),

    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=(
                               [['token', 'auth_realm', 'auth_username', 'auth_password']]),
                           required_together=([['auth_realm', 'auth_username', 'auth_password']]))

    attributes = module.params.get('attributes')
    client_id = module.params.get('client_id')
    name = module.params.get('name')
    realm = module.params.get('realm')
    state = module.params.get('state')
    type = module.params.get('type')
    groups = module.params.get('groups')
    logic = module.params.get('logic')
    decisionStrategy = module.params.get('decisionStrategy')
    description = module.params.get('description')
    groupsClaim = module.params.get('groupsClaim')

    result = dict(changed=False, msg='', end_state={})

    # Obtain access token, initialize API
    try:
        connection_header = get_token(module.params)
    except KeycloakError as e:
        module.fail_json(msg=str(e))

    kc = KeycloakAPI(module, connection_header)

    # Get id of the client based on client_id
    cid = kc.get_client_id(client_id, realm=realm)
    if not cid:
        module.fail_json(msg='Invalid client %s for realm %s' %
                         (client_id, realm))

    # Get current state of the permission using its name as the search
    # filter. This returns False if it is not found.
    policy = kc.get_authz_policy_by_type_by_name(
        name=name, client_id=cid, realm=realm, policy_type=type)[0]
    # Generate a JSON payload for Keycloak Admin API. This is needed for
    # "create" and "update" operations.
    payload = {}
    payload['name'] = name
    if description:
        payload['description'] = description
    if type:
        payload['type'] = type
    if type == 'group':
        payload['groups'] = []
        for group in groups:
            payload['groups'].append({
                'id': kc.get_group_by_name(name=group['name'], realm=realm)['id'],
                'extendChildren': group['extendChildren']
            })
        if groupsClaim:
            payload['groupsClaim'] = groupsClaim
        policy['groups'] = json.loads((policy['config']['groups']))
        del policy['config']
    payload['decisionStrategy'] = decisionStrategy
    payload['logic'] = logic

    # Add "id" to payload for update operations
    if policy:
        payload['id'] = policy['id']

    if policy and state == 'present':
        result['diff'] = {
            'after': payload,
            'before': policy
        }

        if result['diff']['before'] != result['diff']['after']:
            if not module.check_mode:
                kc.update_authz_policy(payload=payload, id=payload['id'], client_id=cid, realm=realm, policy_type=type)
            else:
                result['msg'] = 'Would update policy'
            result['changed'] = True
        result['end_state'] = payload

    elif not policy and state == 'present':
        result['diff'] = {
            'after': payload,
            'before': {}
        }

        if not module.check_mode:
            kc.create_authz_policy(payload=payload, client_id=cid, realm=realm, policy_type=type)
            result['msg'] = 'Policy created'

        result['changed'] = True
        result['end_state'] = payload
    elif policy and state == 'absent':
        result['diff'] = {
            'after': {},
            'before': policy
        }

        if module.check_mode:
            result['msg'] = 'Would remove permission'
        else:
            kc.remove_authz_policy(id=policy['id'], client_id=cid, realm=realm)
            result['msg'] = 'Policy removed'

        result['changed'] = True

    elif not policy and state == 'absent':
        result['changed'] = False
    else:
        module.fail_json(msg='Unable to determine what to do with policy %s of client %s in realm %s' % (
            name, client_id, realm))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
