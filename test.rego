package authz.test
import data.role_resources.policy_resources
import data.role_resources.role_policies
import data.role_resources.user_roles
import rego.v1

default allow := false

allow if {
	roles := user_roles[input.user]
	some role in roles
	some role_policy in role_policies[role]
	service_request_match(role_policy)
    policy := role_policy.policy
	some policy_resource in policy_resources[policy]
	policy_resource.method == input.method
	regex.match(policy_resource.resource, input.resource)
}

service_request_match(role_policy) if {
	not role_policy.service
}

service_request_match(role_policy) if {
	role_policy.service
	input.service
	role_policy.service == input.service
}