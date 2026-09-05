#ifndef SHELLTYPE_NETPATTERN_INTERNAL_H
#define SHELLTYPE_NETPATTERN_INTERNAL_H

#include "shelltype.h"

/* Inputs must already be validated canonical netpatterns. */
int st_netpattern_compare(const char *left, const char *right);
int st_netpattern_compare_view(st_netpattern_view_t left,
                               st_netpattern_view_t right);

#endif
