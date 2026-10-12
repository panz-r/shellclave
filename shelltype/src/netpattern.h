#ifndef SHELLTYPE_NETPATTERN_INTERNAL_H
#define SHELLTYPE_NETPATTERN_INTERNAL_H

#include "shelltype.h"

/* Compare canonical views. Absent data sorts before present data. Malformed
 * framing has deterministic bytewise fallback ordering. */
int st_netpattern_compare_view(st_netpattern_view_t left,
                               st_netpattern_view_t right);

#endif
