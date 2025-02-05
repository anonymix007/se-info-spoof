/* Copyright (C) 2025 anonymix007
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* sha256_fingerprint is a hex string */
bool check_apk_signature(const char *path, const char *sha256_fingerprint);

#ifdef __cplusplus
}
#endif
