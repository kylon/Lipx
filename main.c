/*
* This file is part of Lipx.
 * Copyright (C) 2025 kylon
 *
 * Lipx is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Lipx is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "IPSPatch.h"

#define MAX_IPS_ROM_SIZE 0x1000000 // 16mb
#define LIPX_PRINT_ERR(msg) fprintf(stderr, "%s: %s [line: %d]\n", __func__, msg, __LINE__)

int makeTargetCopy(const char *target, FILE *patchedfd) {
    const int bufSz = 2048;
    char *buf = malloc(sizeof(char) * bufSz);
    FILE *targetfd;

    if (buf == NULL) {
        LIPX_PRINT_ERR("failed to allocate buf memory");
        return -1;
    }

    targetfd = fopen(target, "rb");
    if (targetfd == NULL) {
        LIPX_PRINT_ERR("failed to open target file");
        goto error;
    }

    while (feof(targetfd) == 0) {
        const size_t readSz = fread(buf, sizeof(char), bufSz, targetfd);

        if (readSz == -1) {
            LIPX_PRINT_ERR("failed to read target");
            goto error;
        }

        if (fwrite(buf, sizeof(char), readSz, patchedfd) != readSz) {
            LIPX_PRINT_ERR("failed to make copy");
            goto error;
        }
    }

    free(buf);
    return 0;

error:
    free(buf);
    return -1;
}

long getOffset(const unsigned char *offset) {
    return ((offset[0] << 16) & 0x00FF0000) | ((offset[1] << 8) & 0x0000FF00) | (offset[2] & 0x000000FF);
}

unsigned short getSize(const unsigned char *size) {
    return ((size[0] << 8) & 0xFF00) | (size[1] & 0x00FF);
}

bool isValidFile(const char *file, const long sizeLimitBytes) {
    struct stat sstat;

    printf("checking \"%s\" for validity..\n", file);

    if (stat(file, &sstat) != 0) {
        LIPX_PRINT_ERR("failed to stat file");
        return false;
    }

    if (!S_ISREG(sstat.st_mode)) {
        LIPX_PRINT_ERR("file is not a regular file");
        return false;
    }

    if (sstat.st_size > sizeLimitBytes) {
        char buf[50] = {0};

        snprintf(buf, sizeof(buf), "file is too large, size: %lu, limit: %lu", sstat.st_size, sizeLimitBytes);
        LIPX_PRINT_ERR(buf);
        return false;
    }

    return true;
}

long getFileEndOffset(FILE *file) {
    const long curPos = ftell(file);
    long endPos;

    if (fseek(file, 0, SEEK_END) != 0) {
        LIPX_PRINT_ERR("getIPSEndPosition: failed to seek ips end offset");
        return -1;
    }

    endPos = ftell(file);

    if (fseek(file, curPos, SEEK_SET) != 0) {
        LIPX_PRINT_ERR("getIPSEndPosition: failed to seek back ips offset");
        return -1;
    }

    return endPos;
}

bool isValidIPS(const char *ips) {
    return isValidFile(ips, MAX_IPS_ROM_SIZE); // 16 megabytes
}

bool isValidTarget(const char *target) {
    return isValidFile(target, 0x3FFFFFF); // rom size limit from https://www.romhacking.net
}

char *getApplyPatchedPath(const char *target) {
    const size_t patchedLen = strlen("_patched");
    const size_t targetLen = strlen(target);
    const size_t len = (targetLen + patchedLen + 1) * sizeof(char);
    const char *basename = strrchr(target, '/');
    const char *extension = strrchr(basename == NULL ? target:basename, '.');
    char *patched = malloc(len);

    if (patched == NULL) {
        LIPX_PRINT_ERR("failed to alloc memory for patched filename");
        return NULL;
    }

    memset(patched, 0, len);

    if (extension == NULL) {
        snprintf(patched, len, "%s_patched", target);

    } else {
        const size_t extLen = strlen(extension);
        const size_t baseLen = targetLen - extLen;

        strncpy(patched, target, baseLen);
        strncpy(patched + baseLen, "_patched", patchedLen);
        strncpy(patched + baseLen + patchedLen, extension, extLen);
    }

    return patched;
}

void showHelp() {
    printf("Lipx 2.0\n\n"
        "Usage: lipx [mode] <options>\n\n"
        "Options:\n"
        "\thelp\tShow help\n\n"
        "Mode:\n"
        "\tcreate\tCreate patch\n"
        "\tapply\tApply patch\n\n"
        "Get more help with: lipx <mode> help\n"
    );
}

void showCreateHelp() {
    printf("Usage: lipx create <original file> <patched file> <output ips filename>.ips\n");
}

void showApplyHelp() {
    printf("Usage: lipx apply <ips patch> <file to patch> [output mode]\n\n"
        "Output mode:\n"
        "\tlog\tPrint applied patches\n"
    );
}

int isRealEOF(const char *buf, const long curPos, const long endPos) {
    if (strncmp("EOF", buf, 3) != 0)
        return -1;

    return (endPos - curPos) <= 3 ? 0 : -1;
}

int applyRLEPatch(const long offset, FILE *ipsfd, FILE *patchedfd, const bool verbose) {
    char rleSize[2] = {0};
    unsigned short rleSizeI;
    unsigned char value;
    char *buf;

    if (verbose)
        printf("%s: target offset 0x%08lx\n", __func__, offset);

    if (fread(rleSize, sizeof(char), 2, ipsfd) != 2) {
        LIPX_PRINT_ERR("failed to read rle size");
        return -1;
    }

    rleSizeI = getSize(rleSize);
    if (rleSizeI == 0) {
        LIPX_PRINT_ERR("rle size is 0");
        return -1;
    }

    if (verbose)
        printf("%s: target size %u for offset %08lx\n", __func__, rleSizeI, offset);

    if (fread(&value, sizeof(char), 1, ipsfd) != 1) {
        LIPX_PRINT_ERR("failed to read value");
        return -1;
    }

    if (fseek(patchedfd, offset, SEEK_SET) != 0) {
        LIPX_PRINT_ERR("failed to seek offset");
        return -1;
    }

    buf = malloc(sizeof(char) * rleSizeI);
    if (buf == NULL) {
        LIPX_PRINT_ERR("failed to allocate memory for patch buffer");
        return -1;
    }

    memset(buf, value, rleSizeI);

    if (fwrite(buf, sizeof(char), rleSizeI, patchedfd) != rleSizeI) {
        LIPX_PRINT_ERR("failed to write patch");
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}

int applyPatch(const long offset, const unsigned short size, FILE *ipsfd, FILE *patchedfd, const bool verbose) {
    char *buf;

    if (fseek(patchedfd, offset, SEEK_SET) != 0) {
        LIPX_PRINT_ERR("failed to seek offset");
        return -1;
    }

    buf = malloc(sizeof(char) * size);
    if (buf == NULL) {
        LIPX_PRINT_ERR("failed to allocate memory for patch buffer");
        return -1;
    }

    if (verbose)
        printf("%s: target offset 0x%08lx, size %u\n", __func__, offset, size);

    if (fread(buf, sizeof(char), size, ipsfd) != size) {
        LIPX_PRINT_ERR("failed to read data");
        free(buf);
        return -1;
    }

    if (fwrite(buf, sizeof(char), size, patchedfd) != size) {
        LIPX_PRINT_ERR("failed to write data");
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}

int applyTruncate(FILE *ipsfd, const char *patchedPath, const bool verbose) {
    char offset[3] = {0};
    long offsetI;

    if (fread(offset, sizeof(char), 3, ipsfd) != 3) {
        LIPX_PRINT_ERR("failed to read offset");
        return -1;
    }

    offsetI = getOffset(offset);

    if (verbose)
        printf("%s: target offset 0x%08lx\n", __func__, offsetI);

    if (truncate(patchedPath, offsetI) != 0) {
        LIPX_PRINT_ERR("failed to apply truncate patch");
        return -1;
    }

    return 0;
}

void applyIPS(const char *ips, const char *target, const bool verbose) {
    if (!isValidIPS(ips) || !isValidTarget(target))
        return;

    FILE *ipsfd = NULL;
    FILE *patchedfd = NULL;
    char *patched = NULL;
    char buf[5] = {0};
    long ipsfdEnd;

    ipsfd = fopen(ips, "rb");
    if (ipsfd == NULL) {
        LIPX_PRINT_ERR("failed to open ips file");
        return;
    }

    if (fread(buf, sizeof(char), 5, ipsfd) != 5) {
        LIPX_PRINT_ERR("failed to read header from ips patch");
        goto exit;
    }

    if (strncmp("PATCH", buf, strlen("PATCH")) != 0) {
        LIPX_PRINT_ERR("invalid ips patch header");
        goto exit;
    }

    patched = getApplyPatchedPath(target);
    if (patched == NULL)
        goto exit;

    patchedfd = fopen(patched, "wb+");
    if (patchedfd == NULL) {
        LIPX_PRINT_ERR("failed to create output file");
        goto exit;
    }

    if (makeTargetCopy(target, patchedfd) != 0)
        goto exit;

    ipsfdEnd = getFileEndOffset(ipsfd);
    if (ipsfdEnd == -1)
        goto exit;

    while (ftell(ipsfd) < ipsfdEnd) {
        long offsetI;
        unsigned short sizeI;
        long curIPSPos;

        if (fread(buf, sizeof(char), 3, ipsfd) != 3) {
            LIPX_PRINT_ERR("failed to read record offset");
            break;
        }

        offsetI = getOffset(buf);
        curIPSPos = ftell(ipsfd);

        if (isRealEOF(buf, curIPSPos, ipsfdEnd) == 0) {
            if ((ipsfdEnd - curIPSPos) == 3) { // truncate extension
                fclose(patchedfd);
                patchedfd = NULL;

                if (applyTruncate(ipsfd, patched, verbose) != 0)
                    break;
            }

            printf("patched\n");
            break;
        }

        if (fread(buf, sizeof(char), 2, ipsfd) != 2) {
            LIPX_PRINT_ERR("failed to read record size");
            break;
        }

        sizeI = getSize(buf);

        if (sizeI == 0) {
            if (applyRLEPatch(offsetI, ipsfd, patchedfd, verbose) != 0)
                break;

        } else {
            if (applyPatch(offsetI, sizeI, ipsfd, patchedfd, verbose) != 0)
                break;
        }
    }

exit:
    fclose(ipsfd);
    if (patchedfd)  fclose(patchedfd);
    if (patched)    free(patched);
}

// ported from https://github.com/marcrobledo/RomPatcher.js/blob/master/rom-patcher-js/modules/RomPatcher.format.ips.js#L195
void createIPS(const char *original, const char *patched, const char *ips) {
    if (!isValidTarget(original) || !isValidTarget(patched))
        return;

    const size_t diffAllocSize = 100;
    unsigned char *diffData = NULL;
    unsigned diffDataLen = 0;
    size_t diffDataSz = diffAllocSize;
    FILE *originalfd = NULL;
    FILE *patchedfd = NULL;
    FILE *ipsfd = NULL;
    IPSRecord *prevRecord = NULL;
    IPSPatch *patch = NULL;
    long originalfdEnd;
    long patchedfdEnd;

    originalfd = fopen(original, "rb");
    if (originalfd == NULL) {
        LIPX_PRINT_ERR("failed to open original file");
        return;
    }

    patchedfd = fopen(patched, "rb");
    if (patchedfd == NULL) {
        LIPX_PRINT_ERR("failed to open patched file");
        goto exit;
    }

    ipsfd = fopen(ips, "wb+");
    if (ipsfd == NULL) {
        LIPX_PRINT_ERR("failed to create ips file");
        goto exit;
    }

    originalfdEnd = getFileEndOffset(originalfd);
    if (originalfdEnd == -1) {
        LIPX_PRINT_ERR("failed to get original file end offset");
        goto exit;
    }

    patchedfdEnd = getFileEndOffset(patchedfd);
    if (patchedfdEnd == -1) {
        LIPX_PRINT_ERR("failed to get patched file end offset");
        goto exit;
    }

    diffData = malloc(sizeof(char) * diffDataSz);
    if (diffData == NULL) {
        LIPX_PRINT_ERR("failed to allocate memory for diff buffer");
        goto exit;
    }

    patch = createIPSPatch();
    if (patch == NULL) {
        LIPX_PRINT_ERR("failed to alloc patch");
        goto exit;
    }

    if (fwrite("PATCH", sizeof(char), 5, ipsfd) != 5) {
        LIPX_PRINT_ERR("failed to write patch header");
        goto exit;
    }

    while (ftell(patchedfd) < patchedfdEnd) {
        unsigned char b1 = 0;
        unsigned char b2 = 0;
        bool rleMode = true;
        long startOffset;
        long distance;

        if (ftell(originalfd) < originalfdEnd && fread(&b1, sizeof(char), 1, originalfd) != 1) {
            LIPX_PRINT_ERR("failed to read data from original file");
            goto exit;
        }

        if (fread(&b2, sizeof(char), 1, patchedfd) != 1) {
            LIPX_PRINT_ERR("failed to read data from patched file");
            goto exit;
        }

        if (b1 == b2)
            continue;

        diffDataLen = 0;
        startOffset = ftell(patchedfd) - 1;
        distance = prevRecord == NULL ? 0 : startOffset - (prevRecord->offset + prevRecord->len);

        while (b1 != b2 && diffDataLen < MAX_RECORD_SIZE) {
            if ((diffDataLen + 1) >= diffDataSz) {
                diffDataSz += diffAllocSize;
                unsigned char *tmp = reallocarray(diffData, diffDataSz, sizeof(char));

                if (tmp == NULL) {
                    LIPX_PRINT_ERR("failed to realloc memory for buffer");
                    goto exit;
                }

                ++diffDataLen;
                diffData = tmp;
            }

            diffData[diffDataLen - 1] = b2;

            if (b2 != diffData[0])
                rleMode = false;

            if (ftell(patchedfd) >= patchedfdEnd || diffDataLen == MAX_RECORD_SIZE)
                break;

            if (ftell(originalfd) < originalfdEnd && fread(&b1, sizeof(char), 1, originalfd) != 1) {
                LIPX_PRINT_ERR("failed to read data from original file");
                goto exit;
            }

            if (fread(&b2, sizeof(char), 1, patchedfd) != 1) {
                LIPX_PRINT_ERR("failed to read data from patched file");
                goto exit;
            }
        }

        // ceck if this record is near the previous one
        if (prevRecord != NULL && !prevRecord->rle && distance < 6 && (prevRecord->len + distance + diffDataLen) < MAX_RECORD_SIZE) {
            if (rleMode && diffDataLen > 6) {
                // separate a potential RLE record
                if (fseek(originalfd, startOffset, SEEK_SET) != 0) {
                    LIPX_PRINT_ERR("failed to seek startOffset original file");
                    goto exit;
                }

                if (fseek(patchedfd, startOffset, SEEK_SET) != 0) {
                    LIPX_PRINT_ERR("failed to seek startOffset patched file");
                    goto exit;
                }

                prevRecord = NULL;

            } else { // merge both records
                const long curPatchedPos = ftell(patchedfd);
                const unsigned prevLen = prevRecord->len;
                const unsigned nlen = prevRecord->len + distance + diffDataLen;

                if (nlen >= prevRecord->size) {
                    const unsigned nsize = nlen + 20;
                    unsigned char *tmp = reallocarray(prevRecord->data, nsize, sizeof(char));

                    if (tmp == NULL) {
                        LIPX_PRINT_ERR("failed to realloc merge data");
                        goto exit;
                    }

                    prevRecord->len = nlen;
                    prevRecord->size = nsize;
                    prevRecord->data = tmp;
                }

                if (fseek(patchedfd, prevRecord->offset + prevLen, SEEK_SET) != 0) {
                    LIPX_PRINT_ERR("failed to seek patched file for merge");
                    goto exit;
                }

                if (fread(prevRecord->data + prevLen, sizeof(char), distance, patchedfd) != distance) {
                    LIPX_PRINT_ERR("failed to merge diff data from patched file");
                    goto exit;
                }

                if (fseek(patchedfd, curPatchedPos, SEEK_SET) != 0) {
                    LIPX_PRINT_ERR("failed to seek patched file back after merge");
                    goto exit;
                }

                memcpy(prevRecord->data + prevLen + distance, diffData, diffDataLen);
            }
        } else {
            if (startOffset >= MAX_IPS_ROM_SIZE) {
                LIPX_PRINT_ERR("rom offset limit exceeded");
                goto exit;
            }

            if (rleMode && diffDataLen > 2) {
                IPSRecord *rle = createRLERecord(startOffset, diffDataLen, diffData[0]);

                if (rle == NULL) {
                    LIPX_PRINT_ERR("failed to create rle record");
                    goto exit;
                }

                if (addIPSRecord(patch, rle) == -1) {
                    LIPX_PRINT_ERR("failed to add rle record to patch");
                    goto exit;
                }

            } else {
                IPSRecord *simple = createRecord(startOffset, diffDataLen);

                if (simple == NULL) {
                    LIPX_PRINT_ERR("failed to create simple record");
                    goto exit;
                }

                memcpy(simple->data, diffData, diffDataLen);

                if (addIPSRecord(patch, simple) == -1) {
                    LIPX_PRINT_ERR("failed to add simple record to patch");
                    goto exit;
                }
            }

            prevRecord = patch->records[patch->recordsLen - 1];
        }
    }

    // write records to ips file
    for (int i=0; i<patch->recordsLen; ++i) {
        if (writeIPSRecord(patch->records[i], ipsfd) == 0)
            continue;

        LIPX_PRINT_ERR("failed to write record");
        goto exit;
    }

    // edge case from lunarIPS, can be done with truncate but to avoid potential issues with other patchers,
    // let's follow them
    if (patchedfdEnd > originalfdEnd) {
        const IPSRecord *last = patch->records[patch->recordsLen - 1];
        const long lastOffset = last->offset + last->len;

        if (lastOffset < patchedfdEnd) {
            const IPSRecord *simple = createRecord(patchedfdEnd - 1, 1);

            if (simple == NULL) {
                LIPX_PRINT_ERR("failed to create record");
                goto exit;
            }

            *simple->data = 0;

            if (writeIPSRecord(simple, ipsfd) != 0) {
                LIPX_PRINT_ERR("failed to write record");
                goto exit;
            }
        }
    }

    if (fwrite("EOF", sizeof(char), 3, ipsfd) != 3) {
        LIPX_PRINT_ERR("failed to write eof to patch");
        goto exit;
    }

    if (patchedfdEnd < originalfdEnd && writeTruncateExtension(patchedfdEnd, ipsfd) == -1) {
        LIPX_PRINT_ERR("failed to write truncate offset");
        goto exit;
    }

    printf("success\n");

exit:
    fclose(originalfd);
    if (patchedfd)          fclose(patchedfd);
    if (ipsfd)              fclose(ipsfd);
    if (diffData)           free(diffData);
    if (patch)              freeIPSPatch(patch);
}

void parseCreateModeOptions(const int argc, char *argv[]) {
    if (argc < 3 || strncmp("help", argv[0], strlen("help")) == 0)
        return showCreateHelp();

    createIPS(argv[0], argv[1], argv[2]);
}

void parseApplyModeOptions(const int argc, char *argv[]) {
    if (argc < 2 || strncmp("help", argv[0], strlen("help")) == 0)
        return showApplyHelp();

    const bool verbose = !!(argc >= 3 && strncmp("log", argv[2], strlen("log")) == 0);

    applyIPS(argv[0], argv[1], verbose);
}

void parseMode(const int argc, char *argv[]) {
    if (strncmp("create", argv[0], strlen("create")) == 0) {
        parseCreateModeOptions(argc - 1, argv + 1);

    } else if (strncmp("apply", argv[0], strlen("apply")) == 0) {
        parseApplyModeOptions(argc - 1, argv + 1);

    } else {
        showHelp();
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        showHelp();
        return 1;
    }

    parseMode(argc - 1, argv + 1);
    return 0;
}
