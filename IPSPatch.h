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
#pragma once

#include <stdio.h>
#include <stdbool.h>

#define MAX_RECORD_SIZE 0xffff

typedef struct {
    long offset;
    bool rle;
    unsigned len; // data filled slots (for rle patch this is the uncompressed len, rle real len is always 1)
    unsigned char *data;
    unsigned size; // data allocated size
} IPSRecord;

typedef struct {
    IPSRecord **records;
    size_t recordsSize;
    size_t recordsLen;
} IPSPatch;

void freeIPSPatch(IPSPatch *patch);
void freeIPSRecord(IPSRecord *record);
IPSPatch *createIPSPatch();
int addIPSRecord(IPSPatch *patch, IPSRecord *record);
IPSRecord *createRecord(long offset, unsigned short dataLen);
IPSRecord *createRLERecord(long offset, unsigned short rleSize, unsigned char data);
int writeIPSRecord(const IPSRecord *record, FILE *file);
int writeTruncateExtension(long offset, FILE *file);
