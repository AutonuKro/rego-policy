package com.auth

default allow := false

# Allow if user is admin
allow {
    is_admin
}

# Allow if user has required permission and resource
allow {
    user := data.users[input.user]
    input.permission == user.permissions[_]
    input.resource == user.resources[_]
}

# Admin check
is_admin {
    user := data.users[input.user]
    "admin" == user.roles[_]
}
