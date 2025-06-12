package com.auth

default allow := false

# Allow if user is admin
allow if {
    is_admin
}

# Allow if user has required permission and resource
allow if {
    user := data[input.user]
    input.permission == user.permissions[_]
    input.resource == user.resources[_]
}

# Admin check
is_admin {
    user := data[input.user]
    "admin" == user.roles[_]
}
