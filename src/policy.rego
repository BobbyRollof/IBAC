# package and rule used by the Python app: data.example.allow
package example

default allow = false

# Simple policy: only alice can read documents
allow {
    input.user == "alice"
input.action == "read"
input.resource == "documents"
}
