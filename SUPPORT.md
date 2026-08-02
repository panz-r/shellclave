# Support and versioning

Shellclave is pre-1.0. Minor releases may change C APIs, ABI, CMake options,
policy syntax, and serialized formats. Patch releases aim to remain source and
format compatible within their minor line, except where a security fix
requires a breaking correction. A stable compatibility promise will be
defined before 1.0.

The project supports the latest release and current `main`. Supported builds
use maintained GCC or Clang versions on POSIX systems with CMake 3.20 or newer.
Other compilers and platforms are welcome but are not release gates.

Use GitHub issues for reproducible bugs and feature requests. Use the private
route in `SECURITY.md` for vulnerabilities. Support is best-effort with no SLA.

