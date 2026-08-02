# Security policy

Shellclave processes hostile command text, but it is not a security boundary
or a replacement for operating-system sandboxing. Until 1.0, treat all parser,
policy, and anomaly verdicts as defense-in-depth signals and fail closed when
an API reports invalid input, truncation, allocation failure, or a format
error.

Do not open a public issue for a suspected vulnerability. Use GitHub's private
**Security → Report a vulnerability** flow for this repository. If that flow
is unavailable, contact the repository owner privately through the contact
route on the `panz-r` GitHub profile and request a secure reporting channel;
do not include exploit details in the first message.

Only the latest release and the current `main` branch receive security fixes.
No response-time or embargo guarantee is currently offered. Reports should
include the affected revision, platform, minimal reproducer, expected impact,
and sanitizer output when available.

