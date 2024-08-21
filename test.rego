package authz.test
import data.role_resources.policy_resources
import data.role_resources.role_policies
import data.role_resources.user_roles
import rego.v1

default allow := false

allow if {
	is_read_method
	roles := user_roles[input.user]
	some role in roles
	some role_policy in {p | p := role_policies[role][_]}
	policy := role_policy.policy
	some policy_resource in policy_resources[policy]
	policy_resource.method == input.method
	regex.match(policy_resource.resource, input.resource)
}

allow if {
	is_not_service_request
	roles := user_roles[input.user]
	some role in roles
	some role_policy in {p | p := role_policies[role][_]}
	policy := role_policy.policy
	some policy_resource in policy_resources[policy]
	policy_resource.method == input.method
	regex.match(policy_resource.resource, input.resource)
}

allow if {
	roles := user_roles[input.user]
	some role in roles
	some role_policy in {p | p := role_policies[role][_]; p.service == input.service}
	policy := role_policy.policy
	some policy_resource in policy_resources[policy]
	policy_resource.method == input.method
	regex.match(policy_resource.resource, input.resource)
}

is_not_service_request if{
    not input.service
}

is_read_method if{
    input.method == "GET"
}
