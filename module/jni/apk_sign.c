/* Copyright 2025 anonymix007
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#ifdef __ANDROID__
#include <android/log.h>
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "APKSignatureCheck", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "APKSignatureCheck", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "APKSignatureCheck", __VA_ARGS__)
#else
#include <stdio.h>
#define LOGD(...) printf("DEBUG: "  __VA_ARGS__)
#define LOGE(...) printf("ERROR: " __VA_ARGS__)
#define LOGW(...) printf("WARN: " __VA_ARGS__)
#endif

#include "alg-sha256.h"

struct eocd_header {
	uint32_t signature;
	uint16_t disk_num;
	uint16_t central_directory_disk;
    uint16_t central_directory_disk_records;
    uint16_t central_directory_total_records;
    uint32_t central_directory_size;
    uint32_t central_directory_offset;
    uint16_t comment_length;
} __attribute__((packed));

bool hash_check(uint8_t *buf, size_t len, const char *sha256_fingerprint) {
    uint8_t digest[32];
    SHA256_Buf(buf, len, digest);

    char str[32 * 2 + 1] = {};

    for (size_t i = 0; i < 32; i++) {
        snprintf(&str[2 * i], 3, "%02x", digest[i]);
    }

    LOGD("SHA256 fingerprint: %s", str);

    if (strcmp(str, sha256_fingerprint) == 0) {
        LOGD("Signature verification succeeded");
        return true;
    }
    LOGW("Signature verification failed");
    return false;
}

bool parse_v2(uint8_t *data, uint64_t len, const char *sha256_fingerprint) {
    uint32_t len_signers = *(uint32_t *)data;

    for (uint64_t i = 4; i < len_signers + 4;) {
        uint32_t len_signer = *(uint32_t *)&data[i]; i += 4;
        size_t end = i + len_signer;

        /* uint32_t len_signed_data = *(uint32_t *)&data[i];*/ i += 4;
        uint32_t len_digests = *(uint32_t *)&data[i]; i += 4 + len_digests;
        uint32_t len_certificates = *(uint32_t *)&data[i]; i += 4;

        for (uint64_t j = 0; j < len_certificates;) {
            uint32_t len_certificate = *(uint32_t *)&data[i + j]; j += 4;
            if (hash_check(&data[i + j], len_certificate, sha256_fingerprint)) return true;
            j += len_certificate;
        }
        i = end;
    }

    return false;
}

bool parse_v3(uint8_t *data, uint64_t len, const char *sha256_fingerprint) {
    uint32_t len_signers = *(uint32_t *)data;

    for (uint64_t i = 4; i < len_signers + 4;) {
        uint32_t len_signer = *(uint32_t *)&data[i]; i += 4;
        size_t end = i + len_signer;

        /* uint32_t len_signed_data = *(uint32_t *)&data[i]; */ i += 4;
        uint32_t len_digests = *(uint32_t *)&data[i]; i += 4 + len_digests;
        uint32_t len_certificates = *(uint32_t *)&data[i]; i += 4;

        for (uint64_t j = 0; j < len_certificates;) {
            uint32_t len_certificate = *(uint32_t *)&data[i + j]; j += 4;
            if (hash_check(&data[i + j], len_certificate, sha256_fingerprint)) return true;
            j += len_certificate;
        }

        i = end;
    }

    return false;
}

bool read_entire_file(const char *path, uint8_t **data, size_t *len) {
    bool result = true;
    FILE *f = fopen(path, "rb");
    if (f == NULL) { result = false; goto end; }

    if (fseek(f, 0, SEEK_END) < 0) { result = false; goto end; }
    long m = ftell(f);
    if (m < 0) { result = false; goto end; }
    if (fseek(f, 0, SEEK_SET) < 0) { result = false; goto end; }

    *data = malloc(m);
    *len = m;

    fread(*data, m, 1, f);
    if (ferror(f)) { result = false; }
end:
    if (!result) printf("Could not read file %s: %s", path, strerror(errno));
    if (f) fclose(f);
    return result;
}

#define APK_SIGNING_BLOCK_MAGIC "APK Sig Block 42"

bool check_apk_signature(const char *path, const char *sha256_fingerprint) {
    bool result = false;
    uint8_t *data = NULL;
    size_t len = 0;

    if (!read_entire_file(path, &data, &len)) return false;

    size_t eocd = -1;

    for (size_t i = len - 4; i > 4; i--) {
        uint32_t signature;
        memcpy(&signature, &data[i], sizeof(signature));
        if (signature == 0x06054b50) {
            eocd = i;
            break;
        }
    }

    if (eocd == -1) {
        LOGE("Cannot find EOCD in APK: %s", path);
        goto end;
    }

    LOGD("Found EOCD at offset %zu", eocd);
    struct eocd_header *hdr = (struct eocd_header *) &data[eocd];
    size_t central_dir = hdr->central_directory_offset;

    if (hdr->disk_num == 0xFFFF)
    assert(central_dir + hdr->central_directory_size == eocd);
    assert(central_dir >= 32);

    const char *apk_signing_block_magic = (const char *) &data[central_dir - 16];
    LOGD("APK signing block magic: %.*s", 16, apk_signing_block_magic);

    if (memcmp(apk_signing_block_magic, APK_SIGNING_BLOCK_MAGIC, strlen(APK_SIGNING_BLOCK_MAGIC)) != 0) {
        LOGE("APK signing block magic is wrong: \"%.*s\" != \"" APK_SIGNING_BLOCK_MAGIC "\"", 16, apk_signing_block_magic);
        goto end;
    }

    size_t apk_signing_block_size = *(uint64_t *) &data[central_dir - 24];
    LOGD("APK signature block size: %zu", apk_signing_block_size);

    uint8_t *apk_signing_pairs = (uint8_t *) &data[central_dir - apk_signing_block_size];
    for (uint64_t i = 0; i < apk_signing_block_size - 24;) {
        size_t len = *(uint64_t *)&apk_signing_pairs[i];
        uint32_t id = *(uint32_t *)&apk_signing_pairs[i + 8];

        if (id == 0x7109871a) {
            LOGD("APK signature scheme v2 block found (%zu)", len);
            if (parse_v2(&apk_signing_pairs[i + 12], len - 4, sha256_fingerprint)) {
                result = true;
                goto end;
            }
        } else if (id == 0xf05368c0) {
            LOGD("APK signature scheme v3 block found (%zu)", len);
            if (parse_v3(&apk_signing_pairs[i + 12], len - 4, sha256_fingerprint)) {
                result = true;
                goto end;
            }
        } else if (id == 0x1b93ad61) {
            LOGW("APK signature scheme v3.1 block found (%zu)", len);
        } else {
            LOGD("Unknown block 0x%08x (%zu)", id, len);
        }

        i += len + 8;
    }

end:
    free(data);
    return result;
}
