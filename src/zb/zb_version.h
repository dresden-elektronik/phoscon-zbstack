#ifndef ZB_VERSION_H
#define ZB_VERSION_H

/*
 * The stack's version, semantic versioning: before 1.0.0 a minor version may change the API. The build reads its
 * project version from these three lines, so this header is the one place a release changes it.
 */

#define ZB_VERSION_MAJOR 0
#define ZB_VERSION_MINOR 7
#define ZB_VERSION_PATCH 1

#define ZB_VERSION_STRING "0.7.1"

#endif /* ZB_VERSION_H */
