package com.auth

default allow := false

# Allow if user is admin
allow if {
    user := data.users[input.user]
    "admin" == user.roles[_]
}

# Allow if user has required permission and resource
allow if {
    user := data.users[input.user]
    input.permission == user.permissions[_]
    input.resource == user.resources[_]
}
