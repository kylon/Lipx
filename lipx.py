#!/usr/bin/env python

import collections
import os
import struct
import sys

VERSION = '1.2'
_ntuple_diskusage = collections.namedtuple('usage', 'total used free')


def disk_usage(path):
    st = os.statvfs(path)
    free = st.f_bavail * st.f_frsize
    total = st.f_blocks * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize

    return _ntuple_diskusage(total, used, free)


def usage():
    this = os.path.basename(sys.argv[0])

    print('\nLipx v' + VERSION + ' - Linux IPS tool\n\n' +
           'Usage:\n\n' +
           '    == Apply patch\n' +
           '    ' + this + ' -a originalFile patchFile\n\n' +
           '    == Create a copy and apply the patch - original is untouched\n' +
           '    ' + this + ' -ab originalFile patchFile [outputFile]\n\n' +
           '    == Create IPS patch\n' +
           '    ' + this + ' -c originalFile modifiedFile [outputFile]\n\n' +
           'Arguments:\n' +
           '    [] optional argument\n')

    sys.exit(1)


# Helper function to get an integer from a bytearray (Big endian)
def get_uint16(data, index):
    return int((data[index] << 8) | data[index + 1])


# Helper function to get an integer from a bytearray (Big endian)
def get_uint24(data, index):
    return int((data[index] << 16) | (data[index + 1] << 8) | data[index + 2])


class IPS(object):
    def __init__(self, cmd, original_file, modified_file, patch_file):
        # 16MB Max size of an IPS file - 3byte int
        self.FILE_LIMIT = 0x1000000

        # Max size of an individual record - 2 byte int
        self.RECORD_LIMIT = 0xFFFF

        # IPS file header 'PATCH'
        self.PATCH_ASCII = b"\x50\x41\x54\x43\x48"

        # IPS file footer 'EOF'
        self.EOF_ASCII = b"\x45\x4f\x46"

        # Lipx Command
        self.cmd = cmd

        # Unmodified ROM File
        self.original_file = original_file

        # Modified ROM File
        self.modified_file = modified_file

        # IPS Patch File
        self.patch_file = patch_file

        # Accounting variables
        self.curr_offset = 0
        self.record_count = 0
        self.patch_size = 0

    def __call__(self):
        ret = False

        print('### Lipx v' + VERSION + ' - Linux IPS Tool ###\n')

        self._setup_files()

        if self.cmd == '-c':
            ret = self.create_ips()
        elif self.cmd == '-a' or self.cmd == '-ab':
            ret = self.apply_ips()

        if not ret:
            print('> Error - __call__ error!')
            sys.exit(1)

        return True

    def __check_disk_space(self, file_to_check):
        directory = os.path.dirname(os.path.abspath(file_to_check))

        if directory == '':
            directory = '.'

        if disk_usage(directory).free <= self.FILE_LIMIT:
            return False

        return True

    def _setup_files(self):
        if not self.__check_disk_space(self.patch_file):
            print('> Not enough space on this disk!\n')
            sys.exit(1)

        if self.cmd == '-ab':
            if not self.__check_disk_space(self.original_file):
                print('> Not enough space on this disk!\n')
                sys.exit(1)

        # File object containing the original (base) ROM data
        try:
            self.original_data = open(self.original_file, 'rb').read()
        except:
            print("> Cannot read %s" % self.original_file + '.\n')
            sys.exit(1)

        # File object containing the modified ROM data (To create IPS patch)
        if self.cmd != '-a' and self.cmd != '-ab':
            try:
                self.modified_data = open(self.modified_file, 'rb').read()
            except:
                print("> Cannot read %s" % self.modified_file + '.\n')
                sys.exit(1)

        # File object containing the IPS patch
        try:
            if self.cmd == '-a' or self.cmd == '-ab':
                self.patch_file_obj = bytearray(open(self.patch_file, 'rb').read())
            else:
                self.patch_file_obj = open(self.patch_file, 'wb')
        except:
            print("> Cannot read %s" % self.patch_file + '.\n')
            sys.exit(1)

        if self.cmd != '-a' and self.cmd != '-ab':
            # The IPS file format has a size limit of 16MB
            if len(self.modified_data) > self.FILE_LIMIT:
                print('File is too large! ( Max 16MB )\nThe patch could be broken!')

        return True

    def write_record(self, record_data, overide_size=0):
        """
        Method that takes relevant data and write an IPS record (non-RLE encoded)

        Format looks like (all integers in BIG endian):
        [OFFSET into file : 3bytes][SIZE of record : 2bytes][BYTES : SIZEbytes]
        """

        # Encode record's absolute offset into the original ROM,
        # (IPS file format uses big endian 3-byte int, hence a truncated long, yuck!)
        self.patch_file_obj.write(struct.pack(">L", self.curr_offset)[1:])

        # Encode size of record
        if not overide_size:
            self.patch_file_obj.write(struct.pack(">H", len(record_data)))
        else:
            self.patch_file_obj.write(struct.pack(">H", overide_size))

        # Write the data
        self.patch_file_obj.write(record_data)

        # Do some accounting
        self.record_count += 1
        self.patch_size += len(record_data) + 5

    def apply_ips(self):
        a = 5
        file_to_patch = self.original_file

        if self.cmd == '-ab':
            try:
                org_file_cont = bytearray(open(file_to_patch, 'rb').read())
                open(self.modified_file, 'wb').write(org_file_cont)
            except:
                print('> Error - Cannot create %s' % self.modified_file)
                sys.exit(1)

            file_to_patch = self.modified_file

        patched_file = bytearray(open(file_to_patch, 'rb').read())

        while a < len(self.patch_file_obj) - 3:
            # Get offset
            offset = get_uint24(self.patch_file_obj, a)
            a += 3

            # Get packet size
            size = get_uint16(self.patch_file_obj, a)
            a += 2

            if size == 0:
                # Get RLE repeat count
                rle_size = get_uint16(self.patch_file_obj, a)
                a += 2

                # Grow the patched file if needed
                if (offset + rle_size) > len(patched_file):
                    patched_file += bytearray((offset + rle_size) - len(patched_file))

                # Get repeat byte
                repeat = self.patch_file_obj[a]
                a += 1

                for x in range(rle_size):
                    try:
                        patched_file[offset + x] = repeat
                    except:
                        print('> Error - Unable to parse the patch!')
                        sys.exit(1)
            else:
                # Grow the patched file if needed
                if (offset + size) > len(patched_file):
                    patched_file += bytearray((offset + size) - len(patched_file))

                # Normal packet, copy from patch to file
                for x in range(size):
                    try:
                        patched_file[offset + x] = self.patch_file_obj[a]
                        a += 1
                    except:
                        print('> Error - Unable to parse the patch!')
                        sys.exit(1)

        try:
            # Write modified data
            open(file_to_patch, 'wb').write(patched_file)
        except:
            print('> Error - Cannot write to file!')
            sys.exit(1)

        print('> Success - Patch applied to %s' % file_to_patch)

        return True

    def create_ips(self):
        record_begun = False
        record = bytearray()
        original_data_len = len(self.original_data)

        # IPS file header
        self.patch_file_obj.write(self.PATCH_ASCII)
        self.patch_size += len(self.PATCH_ASCII)

        # Write the IPS record(s).
        # Format looks like (all integers in BIG endian):
        # [OFFSET into file : 3bytes][SIZE of record : 2bytes][BYTES : SIZEbytes]

        # Diff bytes between the new ROM and the base ROM, 1 byte at a time
        for pos in range(len(self.modified_data)):
            if not record_begun:

                if original_data_len <= pos or self.modified_data[pos] != self.original_data[pos]:
                    record_begun = True
                    record = bytearray()

                    # From http://romhack.wikia.com/wiki/IPS in 'Caveats' section:
                    #
                    # The number 0x454f46 looks like "EOF" in ASCII, which is why a patch record must never begin at
                    # offset 0x454f46. If your program generates a patch record at offset 0x454f46, then you have a bug,
                    # because IPS patchers will read the "EOF". One possible workaround is to start at offset 0x454f45
                    # and include the extra byte in the patch.
                    #
                    # If a patch provides multiple values for the same byte in the patched file, then the IPS patcher
                    # may use any of these overlapped values. Also, if the patch extends the size of the patched file,
                    # but does not provide values for all bytes in the extended area, then the IPS patcher may fill the
                    # gaps with any values. A better IPS file provides no such overlapped values and no such gaps,
                    # though this is not a requirement of the IPS format.
                    if pos == self.EOF_ASCII:
                        record.append(self.modified_data[pos - 1])

                    # Add the byte from the new ROM at address 'a' to the record
                    record.append(self.modified_data[pos])

                    # Save the absolute offset for this record
                    self.curr_offset = pos

                    # Corner case - should never hit for real ROMs
                    # If we're at the last address, close the record and write to the patch file
                    if pos == len(self.modified_data) - 1:
                        record_begun = False
                        self.write_record(record, overide_size=0x01)
            else:
                # Records have a max size of 0xFFFF as the size header is a short
                # Check our current position and if we at the max size end the record and start a new one
                if len(record) == self.RECORD_LIMIT - 1:
                    print("Truncating overlong record: %s %s" % (len(record), hex(len(record))))

                    record_begun = False
                    record.append(self.modified_data[pos])
                    self.write_record(record)

                # Append diff data to the record
                elif (original_data_len <= pos or
                              self.modified_data[pos] != self.original_data[pos]) and pos != len(self.modified_data) - 1:
                    # Continue Record
                    record.append(self.modified_data[pos])

                # END OF RECORD
                # If we're at the last address of the new ROM, the bytes at the address are identical in both ROMs,
                # or the base ROM  is longer than the address we are at in the modified ROM close the record
                else:
                    record_begun = False
                    self.write_record(record)

        # Add the footer to the IPS file and flush the data to disk & close entire IPS file
        self.patch_file_obj.write(self.EOF_ASCII)
        self.patch_size += len(self.EOF_ASCII)
        self.patch_file_obj.close()

        print("> Success - Patch file: %s" % self.patch_file)

        return True


if __name__ == '__main__':
    arg_len = len(sys.argv)

    if arg_len < 4:
        usage()

    if sys.argv[1] == '-a':
        ips = IPS(sys.argv[1], sys.argv[2], '', sys.argv[3])
        ips()

    elif sys.argv[1] == '-ab':
        # sys.argv[4] is user supplied _patched_ file name.
        # Keep the compability - note the order of arguments.
        patched_file_name = 'Patched_'+sys.argv[2] if arg_len == 4 else sys.argv[4]
        ips = IPS(sys.argv[1], sys.argv[2], patched_file_name, sys.argv[3])
        ips()

    elif sys.argv[1] == '-c':
        patch_file_name = sys.argv[3]+'.ips' if arg_len == 4 else sys.argv[4]
        ips = IPS(sys.argv[1], sys.argv[2], sys.argv[3], patch_file_name)
        ips()

    else:
        usage()

    sys.exit(0)
