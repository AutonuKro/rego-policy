package com.auth

default allow := false

# Allow if user is admin
allow if {
    user := data.users[input.user]
    some role in user.roles
    "admin" == user
}

# Allow if user has required permission and resource
allow if {
    user := data.users[input.user]

    some permission in user.permissions
    input.permission == permission

    some resource in user.resources
    input.resource == resource
}
