# Deliberately hostile noninteractive Bash startup fixture. The named-FD
# conformance test receives this through CTest's BASH_ENV environment but must
# clear it before every baseline Bash invocation.
shopt -s lastpipe
