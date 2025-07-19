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

#include "IPSPatch.h"

static void toIPSOffset(unsigned char *buf, const long offset) {
    buf[0] = (offset & 0x00FF0000) >> 16;
    buf[1] = (offset & 0x0000FF00) >> 8;
    buf[2] = offset & 0x000000FF;
}

static void toIPSSize(unsigned char *buf, const unsigned size) {
    buf[0] = (size & 0xFF00) >> 8;
    buf[1] = size & 0x00FF;
}

static int writeRLERecord(const IPSRecord *record, FILE *file) {
    const char size[2] = {0};
    char offset[3] = {0};
    char rleSize[2] = {0};

    toIPSOffset(offset, record->offset);
    toIPSSize(rleSize, record->len);

    if (fwrite(offset, sizeof(char), 3, file) != 3 ||
        fwrite(size, sizeof(char), 2, file) != 2 ||
        fwrite(rleSize, sizeof(char), 2, file) != 2 ||
        fwrite(record->data, sizeof(char), 1, file) != 1)
    {
        return -1;
    }

    return 0;
}

static int writeSimpleRecord(const IPSRecord *record, FILE *file) {
    char offset[3] = {0};
    char size[2] = {0};

    toIPSOffset(offset, record->offset);
    toIPSSize(size, record->len);

    if (fwrite(offset, sizeof(char), 3, file) != 3 ||
        fwrite(size, sizeof(char), 2, file) != 2 ||
        fwrite(record->data, sizeof(char), record->len, file) != record->len)
    {
        return -1;
    }

    return 0;
}

void freeIPSPatch(IPSPatch *patch) {
    for (int i=0; i<patch->recordsLen; ++i)
        freeIPSRecord(patch->records[i]);

    free(patch->records);
    free(patch);
}

void freeIPSRecord(IPSRecord *record) {
    free(record->data);
    free(record);
}

IPSPatch *createIPSPatch() {
    IPSPatch *patch = malloc(sizeof(IPSPatch));

    if (patch == NULL)
        return NULL;

    memset(patch, 0, sizeof(IPSPatch));

    patch->recordsSize = 10;
    patch->records = malloc(patch->recordsSize * sizeof(IPSRecord *));

    if (patch->records == NULL) {
        free(patch);
        return NULL;
    }

    return patch;
}

int addIPSRecord(IPSPatch *patch, IPSRecord *record) {
    if ((patch->recordsLen + 1) >= patch->recordsSize) {
        const int inc = 10;
        IPSRecord **list = reallocarray(patch->records, patch->recordsSize + inc, sizeof(IPSRecord *));

        if (list == NULL)
            return -1;

        ++patch->recordsLen;
        patch->recordsSize += inc;
        patch->records = list;
    }

    patch->records[patch->recordsLen - 1] = record;
    return 0;
}

IPSRecord *createRecord(const long offset, const unsigned short dataLen) {
    IPSRecord *record = malloc(sizeof(IPSRecord));

    if (record == NULL)
        return NULL;

    record->rle = false;
    record->offset = offset;
    record->len = dataLen;
    record->size = dataLen;
    record->data = malloc(sizeof(char) * dataLen);

    if (record->data == NULL) {
        free(record);
        return NULL;
    }

    return record;
}

IPSRecord *createRLERecord(const long offset, const unsigned short rleSize, const unsigned char data) {
    IPSRecord *record = malloc(sizeof(IPSRecord));

    if (record == NULL)
        return NULL;

    record->rle = true;
    record->offset = offset;
    record->len = rleSize;
    record->size = 1;
    record->data = malloc(sizeof(char));

    if (record->data == NULL) {
        free(record);
        return NULL;
    }

    *record->data = data;

    return record;
}

int writeIPSRecord(const IPSRecord *record, FILE *file) {
    return record->rle ? writeRLERecord(record, file) : writeSimpleRecord(record, file);
}

int writeTruncateExtension(const long offset, FILE *file) {
    char buf[3] = {0};

    toIPSOffset(buf, offset);

    if (fwrite(buf, sizeof(char), 3, file) != 3)
        return -1;

    return 0;
}
