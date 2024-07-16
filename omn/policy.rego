package auth.omn

import rego.v1

default allow := false

#allow if user is admin for FIN client
allow if {
	"admin" in input.roles
}

#allow if user is checker
allow if {
	is_user_checker
    roles := input.roles

    some role in roles
    role_grants := data.omn[role]

	#filter all role grants to keep only checker grants
	checker_grants := [any_grant | any_grant := role_grants[_]; any_grant.checker == true]

    #try to match resource and action in filtered grants
    some checker_grant in checker_grants
    input.resource == checker_grant.resource
    input.action == checker_grant.action
}

#allow if user is maker
allow if {
	is_user_maker
	roles := input.roles

	some role in roles
	role_grants := data.omn[role]

	#filter all role grants to keep only maker grants
	maker_grants := [any_grant | any_grant := role_grants[_]; any_grant.maker == true]

    #try to match resource and action in filtered grants
    some maker_grant in maker_grants
    input.resource == maker_grant.resource
    input.action == maker_grant.action
}

#allow if normal case
allow if {
    roles := input.roles
    some role in roles
    role_grants := data.omn[role]

    #filter out all maker and checker grants
    no_cheker_grants := [any_grant | any_grant := role_grants[_]; not any_grant.checker == true]
    normal_grants := [any_grant | any_grant := no_cheker_grants[_]; not any_grant.maker == true]

    #try to match resoruce and action
    some normal_grant in normal_grants
    input.resource == normal_grant.resource
    input.action == normal_grant.action
}

#allow for wildcard actions
allow if {
    roles := input.roles
    some role in roles
    role_grants := data.omn[role]

    #filter out all maker and checker grants
    no_cheker_grants := [any_grant | any_grant := role_grants[_]; not any_grant.checker == true]
    normal_grants := [any_grant | any_grant := no_cheker_grants[_]; not any_grant.maker == true]

    #try to match resoruce and action
    some normal_grant in normal_grants
    input.resource == normal_grant.resource
    "*" == normal_grant.action
}

is_user_checker if {
    "checker" == input.actor_type
}

is_user_maker if {
    "maker" == input.actor_type
}