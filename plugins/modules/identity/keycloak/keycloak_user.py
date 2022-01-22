#!/usr/bin/python

__metaclass__ = type

DOCUMENTATION = '''
module: keycloak_user

short_description: Allows administration of Keycloak users via Keycloak API


description:
    - This module allows the administration of Keycloak users via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.


options:
    state:
        description:
            - State of the client
            - On C(present), the client will be created (or updated if it exists already).
            - On C(absent), the client will be removed if it exists
        choices: ['present', 'absent']
        default: 'present'
        type: str

    realm:
        description:
            - The realm to create the user in.
        type: str
        default: master

    the_username:
        description:
            - The username to be worked on [required]
        type: str

    email:
        description:
            - The email address of the user.
        type: str

    enabled:
        description:
            - If the user account is enabled. (default is false)
        type: bool

    first_name:
        description:
            - The first_name of the user.
        type: str

    last_name:
        description:
            - The lastname_name of the user.
        type: str

    password_reset_value:
        description:
            - The password
        type: str

    password_reset_when:
        description:
            - When should the password be set.
        choices: ['on-create', 'always']
        type: str

    password_reset_is_temporary:
        description:
            - When the password is reset should it be marked temporary (i.e. it requires resetting)
        type: bool

    group_memberships:
        description:
            - Determines the groups the user must be in.
        type: list
        elements: str

extends_documentation_fragment:
- community.general.keycloak

author:
    - Pierre Dumuid
'''

EXAMPLES = '''
- name: Create or update Keycloak user (minimal example), authentication with credentials
  community.general.keycloak_client:
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD

    realm: test
    the_username: testuser

    state: present
  delegate_to: localhost

'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "User testuser has been updated"

'''

from copy import deepcopy
from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import KeycloakAPI, camel, \
    keycloak_argument_spec, get_token, KeycloakError
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = keycloak_argument_spec()

    # Note: The username was named `the_username` because the existing argument, `auth_username` has `username` as an alias.
    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        the_username=dict(type='str'),
        email=dict(type='str'),
        enabled=dict(type='bool', default=False),
        first_name=dict(type='str'),
        last_name=dict(type='str'),

        password_reset_value=dict(type='str', no_log=True),
        password_reset_when=dict(type='str', choices=['on-create', 'always'], default='on-create', no_log=False),
        password_reset_is_temporary=dict(type='bool', default=True, no_log=True),

        group_memberships=dict(type='list', elements='str', default=[]),
    )
    argument_spec.update(meta_args)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=([['realm'],
                          ['the_username'],
                          ['token', 'auth_realm', 'auth_username', 'auth_password']]),
        required_together=([['auth_realm', 'auth_username', 'auth_password']])
    )

    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    # Obtain access token, initialize API
    try:
        connection_header = get_token(module.params)
    except KeycloakError as e:
        module.fail_json(msg=str(e))

    kc = KeycloakAPI(module, connection_header)

    state = module.params.get('state')

    # convert module parameters to client representation parameters (if they belong in there)
    password_reset_params = ['password_reset_value', 'password_reset_when', 'password_reset_is_temporary']

    non_resource_params_names = list(keycloak_argument_spec().keys()) + ['state', 'realm'] + password_reset_params + ['group_memberships']

    resource_params = [x for x in module.params
                       if x not in non_resource_params_names
                       and module.params.get(x) is not None]

    # See whether the user already exists in Keycloak
    before_user = kc.get_user_by_username(username=module.params.get('the_username'), realm=module.params.get('realm'))
    user_id = before_user['id'] if before_user else None

    if before_user:
        current_user_group_memberships = kc.get_group_memberships_for_user(user_id, realm=module.params.get('realm'))
        before_user['group_memberships'] = [x['name'] for x in current_user_group_memberships]

    # Build a proposed changeset from parameters given to this module
    changeset = dict()
    for resource_param in resource_params:
        new_param_value = module.params.get(resource_param)

        if resource_param == 'the_username':
            resource_param = 'username'

        changeset[camel(resource_param)] = new_param_value

    desired_user = before_user.copy() if before_user else dict()
    desired_user.update(changeset)
    desired_user['group_memberships'] = module.params.get('group_memberships', [])

    # Handle when the user does not exist:
    if before_user is None:
        if state == 'absent':
            return _handle_not_present_and_not_required(module, result)
        return _handle_not_present_but_required(module, result, kc, desired_user)

    if state == 'absent':
        return _handle_present_and_not_required(module, result, kc, before_user)
    return _handle_present_and_required(module, result, kc, before_user, desired_user)


def _handle_not_present_and_not_required(module, result):
    # do nothing and exit
    if module._diff:
        result['diff'] = dict(before=dict(), after=dict())
        result['msg'] = 'User does not exist, doing nothing.'
    return module.exit_json(**result)


def _handle_not_present_but_required(module, result, kc, desired_user):
    realm = module.params.get('realm')

    result['changed'] = True
    if module._diff:
        result['diff'] = dict(before=dict(), after=desired_user)

    if module.check_mode:
        return module.exit_json(**result)

    desired_group_names = desired_user.pop('group_memberships')
    kc.create_user(desired_user, realm=realm)
    after_user = kc.get_user_by_username(username=module.params.get('the_username'), realm=realm)

    after_user['group_memberships'] = []
    realm_groups = kc.get_groups(realm=realm)
    for group_name in desired_group_names:
        realm_group = [x for x in realm_groups if x['name'] == group_name]
        if realm_group:
            user_id = after_user['id']
            group_id = realm_group[0]['id']
            kc.add_group_membership(user_id, group_id, realm=realm)
            after_user['group_memberships'].append(group_name)
        else:
            raise Exception("The group, with the name, %s does not exist" % group_name)

    result['end_state'] = after_user
    result['msg'] = 'User, `%s` has been created.' % desired_user['username']

    new_password = module.params.get('password_reset_value')
    is_temporary = module.params.get('password_reset_is_temporary')
    if new_password:
        kc.reset_user_password(after_user['id'], new_password, is_temporary, realm=realm)

    return module.exit_json(**result)


def _handle_present_and_not_required(module, result, kc, before_user):
    realm = module.params.get('realm')

    result['changed'] = True
    if module._diff:
        result['diff'] = dict(before=before_user, after=dict())

    if module.check_mode:
        return module.exit_json(**result)

    kc.delete_user(before_user['id'], realm=realm)

    result['end_state'] = dict()
    result['msg'] = 'User, `%s` has been deleted.' % before_user['username']

    return module.exit_json(**result)


def _handle_present_and_required(module, result, kc, before_user, desired_user):
    realm = module.params.get('realm')

    before_norm = normalise_rep(before_user)
    desired_norm = normalise_rep(desired_user)

    # Only worry about groups we want the user to be in.
    before_norm['group_memberships'] = [x for x in before_norm['group_memberships'] if x in desired_user['group_memberships']]

    result['changed'] = (before_norm != desired_norm)

    if module.check_mode:
        # We can only compare the current client with the proposed updates we have
        if module._diff:
            result['diff'] = dict(before=before_norm, after=desired_norm)
        result['changed'] = (before_norm != desired_norm)

        return module.exit_json(**result)

    if not result['changed']:
        result['msg'] = 'User, `%s` did not require updating.' % before_norm['username']
        return module.exit_json(**result)

    desired_group_names = desired_user.pop('group_memberships')
    kc.update_user(before_norm['id'], desired_user, realm=realm)

    updated_user = kc.get_user_by_username(username=module.params.get('the_username'), realm=realm)
    updated_user['group_memberships'] = before_user['group_memberships']

    realm_groups = kc.get_groups(realm=realm)
    for group_name in desired_group_names:
        if group_name in before_user['group_memberships']:
            continue
        realm_group = [x for x in realm_groups if x['name'] == group_name]
        if realm_group:
            user_id = updated_user['id']
            group_id = realm_group[0]['id']
            kc.add_group_membership(user_id, group_id, realm=realm)
            updated_user['group_memberships'].append(group_name)
        else:
            raise Exception("The group, with the name, %s does not exist" % group_name)

    updated_norm = normalise_rep(updated_user)

    if module._diff:
        result['diff'] = dict(before=before_norm, after=updated_norm)

    result['end_state'] = updated_norm
    result['msg'] = 'User, `%s` has been updated.' % before_norm['username']
    return module.exit_json(**result)


def normalise_rep(user_rep, remove_ids=False):
    """ Re-sorts any properties where the order so that diff's is minimised, and adds default values where appropriate so that the
    the change detection is more effective.

    :param clientrep: the clientrep dict to be sanitized
    :return: normalised clientrep dict
    """

    # Keycloak ignores the case-sensitivity of emails.
    if 'email' in user_rep:
        user_rep['email'] = user_rep['email'].lower()

    return user_rep


if __name__ == '__main__':
    main()
