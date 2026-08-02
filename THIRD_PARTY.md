# Third-party software

Shellclave uses two pinned Git submodules. Recursive clones retain their full
license files and upstream history.

| Dependency | Revision | Purpose | License |
|---|---|---|---|
| [draugr](https://github.com/panz-r/draugr-repo) | `acd2c0ff6a25f29aa81c4cdf2d9e72e89efe6ed8` | anomaly-model hash tables and Shelltype vacuum filter | MIT (`deps/draugr/LICENSE`) |
| [xxHash](https://github.com/Cyan4973/xxHash) | `e573d4d2aaeaba0f3e5a0a9a54144a1f2b4b56e7` | XXH3 hashing | BSD-2-Clause (`deps/xxhash/LICENSE`) |

These revisions are changed only by reviewed submodule updates. Normal CMake
configuration performs no network access. Installed Shellclave archives may
contain compiled portions of these dependencies; distributors must preserve
the corresponding license notices.
