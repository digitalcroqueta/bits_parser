#!/usr/bin/env python
"""
Extract BITS jobs from QMGR queue and store them as pipe-delimited records.

This is forked from `ANSSI bits_parser <https://github.com/ANSSI-FR/bits_parser>`_ to refactor as a simple Python 2.7
script.


Copyright (c) 2018 ANSSI
Copyright (c) 2018 Andrea Sancho (refactored project into simple Python2.7 script)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

import binascii
import csv
import logging
import struct
from datetime import datetime, timedelta
from os import path, walk
from sys import exit, argv
from uuid import UUID as _UUID

from construct import Struct, Array, Enum, Const, GreedyBytes, Int64ul, \
    Int32ul, Bytes, Byte, Pass, Padding, Embedded, Tell, Seek, this, Adapter,  Sequence, RepeatUntil, Computed, core


class UUID(Adapter):

    def _decode(self, obj, context):
        return str(_UUID(bytes_le=obj))


class _StripDelimiter(Adapter):

    def _decode(self, obj, context):
        return bytes(obj[1])


class _Utf16(Adapter):

    def _decode(self, obj, context):
        try:
            return obj[1].decode('utf16').strip('\x00')
        except UnicodeDecodeError:
            # TODO: improve that
            return 'unreadable data'


def DelimitedField(stop):

    return _StripDelimiter(Sequence(
        RepeatUntil(
            lambda x, lst, ctx: lst[-len(stop):] == [int(c) for c in stop],
            Byte
        ),
        Computed(this[0][:-len(stop)]),
        Seek(-len(stop), whence=1)
    ))


def PascalUtf16(size_type=Int32ul):
    """
    Parse a length-defined string in UTF-16.
    """

    return _Utf16(Sequence(
        size_type,
        Bytes(this[0] * 2),
    ))


class FileTime(Adapter):

    def _decode(self, obj, context):
        return datetime(1601, 1, 1) + timedelta(microseconds=(obj / 10))


class BITSParser:
    """
    Known constants.
    """

    FILE_HEADER = '13F72BC84099124A9F1A3AAEBD894EEA'
    QUEUE_HEADER = '47445F00A9BDBA449851C47BB6C07ACE'
    XFER_HEADER = '36DA56776F515A43ACAC44A248FFF34D'
    XFER_DELIMITER = '03000000'

    # each version of BITS has its own job delimiter.
    JOB_DELIMITERS = {
        1: '93362035A00C104A84F3B17E7B499CD7',
        2: '101370C83653B34183E581557F361B87',
        3: '8C93EA64030F6840B46FF97FE51D4DCD',
        4: 'B346ED3D3B10F944BC2FE8378BD31986',
    }

    QUEUE = Struct(
            'header' / DelimitedField(bytearray.fromhex(FILE_HEADER)),
            Const(bytearray.fromhex(FILE_HEADER)),
            Const(bytearray.fromhex(QUEUE_HEADER)),
            'job_count' / Int32ul,
            'jobs' / DelimitedField(bytearray.fromhex(QUEUE_HEADER)),
            Const(bytearray.fromhex(QUEUE_HEADER)),
            'unknown' / DelimitedField(bytearray.fromhex(FILE_HEADER)),
            Const(bytearray.fromhex(FILE_HEADER)),
            'remains' / GreedyBytes,
        )

    # CONTROL : job control information
    CONTROL_PART_0 = Struct(
        'type' / Enum(Int32ul, default=Pass,
                      download=0,
                      upload=1,
                      upload_reply=2),
        'priority' / Enum(Int32ul, default=Pass,
                          foreground=0,
                          high=1,
                          normal=2,
                          low=3),
        'state' / Enum(Int32ul, default=Pass,
                       queued=0,
                       connecting=1,
                       transferring=2,
                       suspended=3,
                       error=4,
                       transient_error=5,
                       transferred=6,
                       acknowleged=7,
                       cancelled=8),
        Int32ul,
        'job_id' / UUID(Bytes(16)),
    )

    CONTROL_PART_1 = Struct(
        'sid' / PascalUtf16(Int32ul),
        'flags' / Enum(Int32ul, default=Pass,
                       BG_NOTIFY_JOB_TRANSFERRED=1,
                       BG_NOTIFY_JOB_ERROR=2,
                       BG_NOTIFY_JOB_TRANSFERRED_BG_NOTIFY_JOB_ERROR=3,
                       BG_NOTIFY_DISABLE=4,
                       BG_NOTIFY_JOB_TRANSFERRED_BG_NOTIFY_DISABLE=5,
                       BG_NOTIFY_JOB_ERROR_BG_NOTIFY_DISABLE=6,
                       BG_NOTIFY_JOB_TRANSFERRED_BG_NOTIFY_JOB_ERROR_BG_NOTIFY_DISABLE=7,
                       BG_NOTIFY_JOB_MODIFICATION=8,
                       BG_NOTIFY_FILE_TRANSFERRED=16),
    )

    CONTROL = Struct(
        Embedded(CONTROL_PART_0),
        'name' / PascalUtf16(Int32ul),
        'desc' / PascalUtf16(Int32ul),
        'cmd' / PascalUtf16(Int32ul),
        'args' / PascalUtf16(Int32ul),
        Embedded(CONTROL_PART_1),
        'access_token' / DelimitedField(bytearray.fromhex(XFER_HEADER)),
    )

    # XFER : file transfer informations
    FILE_PART_0 = Struct(
        'download_size' / Int64ul,
        'transfer_size' / Int64ul,
        Byte,
        'drive' / PascalUtf16(Int32ul),
        'vol_guid' / PascalUtf16(Int32ul),
        'offset' / Tell,                     # required by carving
    )

    FILE = Struct(
        DelimitedField(bytearray.fromhex('3A00')),   # The ':' delimiter
        Seek(-6, whence=1),
        'dest_fn' / PascalUtf16(Int32ul),
        'src_fn' / PascalUtf16(Int32ul),
        'tmp_fn' / PascalUtf16(Int32ul),     # always ends with .tmp
        Embedded(FILE_PART_0),
    )

    ERROR = Struct(
         'code' / Int64ul,
         'stat1' / Int32ul,
         'stat2' / Int32ul,
         'stat3' / Int32ul,
         'stat4' / Int32ul,
         Byte
    )

    METADATA = Struct(
        'error_count' / Int32ul,
        'errors' / Array(this.error_count, ERROR),
        'transient_error_count' / Int32ul,
        'retry_delay' / Int32ul,
        'timeout' / Int32ul,
        'ctime' / FileTime(Int64ul),
        'mtime' / FileTime(Int64ul),
        'other_time0' / FileTime(Int64ul),
        Padding(14),
        'other_time1' / FileTime(Int64ul),
        'other_time2' / FileTime(Int64ul),
    )

    JOB = Struct(
        Embedded(CONTROL),
        Const(bytearray.fromhex(XFER_HEADER)),
        'file_count' / Int32ul,
        'files' / DelimitedField(bytearray.fromhex(XFER_HEADER)),
        Const(bytearray.fromhex(XFER_HEADER)),
        Embedded(METADATA),
    )

    def __init__(self, bits_files, output_file, thread_logger):
        """
        The normal init method for a k-engine parser

        :param bits_files:
        :param output_file:
        :param thread_logger:
        :return:
        """
        self.xfer_delimiter = bytearray.fromhex(self.XFER_DELIMITER)
        self.xfer_header = bytearray.fromhex(self.XFER_HEADER)
        self.thread_logger = thread_logger
        self.thread_logger.debug("Init BITS Parser")
        self.delimiter = ''
        self.parsed_queue = ''
        self.jobs = []
        self.headers = [u'job_number', u'in_queue', u'carved', u'name', u'job_id', u'desc', u'type', u'priority',
                        u'sid', u'state', u'cmd', u'args', u'flags', u'error_count', u'errors',
                        u'transient_error_count', u'retry_delay', u'timeout', u'file_count', u'ctime', u'mtime',
                        u'other_time0', u'other_time1', u'other_time2', u'file_id', u'dest_fn', u'src_fn', u'tmp_fn',
                        u'download_size', u'transfer_size', u'drive', u'vol_guid']

        for i in bits_files:
            if i is None or len(i) == 0:
                self.thread_logger.error("Invalid filepath")
                return
        self.ief_files = bits_files
        self.output_file = output_file

    def write_output(self):
        """

        :return:
        """
        file_names = []
        for bit_file in self.ief_files:
            try:
                with open(bit_file, 'rb') as read_file:

                    total_jobs = 0
                    output_jobs_data = []
                    read_data = read_file.read().strip(b'\x00')

                    self.delimiter = self.guess_info(read_data)
                    self.thread_logger.debug("Job delimiter found: {}".format(binascii.hexlify(self.delimiter)))
                    if not self.delimiter:
                        self.thread_logger.error("Delimiter could not be found to parse BITS file: {}".format(bit_file))
                        continue

                    try:
                        self.parsed_queue = self.QUEUE.parse(read_data)
                        # print parsed_queue
                        self.thread_logger.debug("Found {} jobs in queue for {}".format(self.parsed_queue.job_count, bit_file))
                        if int(self.parsed_queue.job_count) > 0:
                            temp = self.parsed_queue.jobs.replace("[", "").replace("]", "").split(", ")
                            all_queued_jobs_together = ''.join([chr(int(item)) for item in temp])
                            all_jobs = [x for x in all_queued_jobs_together.split(self.delimiter) if x.strip(b'\x00')]

                            for job in all_jobs:
                                # print "HEX DUMP for job {}:".format(total_jobs), "\n", binascii.hexlify(job)
                                self.thread_logger.debug("Attempting to parse job with length {}".format(len(job)))
                                parsed_jobs = self.carve_job(job, in_queue=True, job_number=total_jobs)
                                if parsed_jobs:
                                    for p_j in parsed_jobs:
                                        # self.thread_logger.debug("Successfully parsed job #{}\n\t{}".format(total_jobs, p_j))
                                        p_j[u'job_number'] = total_jobs
                                        output_jobs_data.append(p_j)
                                        total_jobs += 1

                    except (core.RangeError, core.FieldError) as e:
                        self.thread_logger.warning("The queue for {} could not be parsed. ERROR: {}"
                                                 "".format(bit_file, e.message))
                        continue

                    # Carved for other queues:
                    try:
                        if not self.parsed_queue:
                            data_to_carve = self.carve_queues(read_data)
                        else:
                            data_to_carve = self.carve_queues(self.parsed_queue.remains)

                        for cq in data_to_carve:
                            try:
                                carved_queue = self.QUEUE.parse(cq)
                                self.thread_logger.debug("Found {} jobs in queue for {}".format(carved_queue.job_count, bit_file))
                                if int(carved_queue.job_count) > 0:
                                    temp = carved_queue.jobs.replace("[", "").replace("]", "").split(", ")
                                    all_queued_jobs_together = ''.join([chr(int(item)) for item in temp])
                                    all_jobs = [x for x in all_queued_jobs_together.split(self.delimiter) if x.strip(b'\x00')]

                                    for job in all_jobs:
                                        # print "HEX DUMP for job {}:".format(total_jobs), "\n", binascii.hexlify(job)
                                        self.thread_logger.debug("Attempting to parse job with length {}".format(len(job)))
                                        parsed_jobs = self.carve_job(job, in_queue=True, job_number=total_jobs)
                                        if parsed_jobs:
                                            for p_j in parsed_jobs:
                                                # self.thread_logger.debug("Successfully parsed job #{}\n\t{}".format(total_jobs, p_j))
                                                p_j[u'job_number'] = total_jobs
                                                output_jobs_data.append(p_j)
                                                total_jobs += 1

                                queue_data_remaining = [x for x in carved_queue.remains.split(self.delimiter)]
                                if len(queue_data_remaining):
                                    for job in queue_data_remaining:
                                        # print "HEX DUMP for job {}:".format(total_jobs), "\n", binascii.hexlify(job)
                                        self.thread_logger.debug("Attempting to carve job from queue with length {}".format(len(job)))
                                        parsed_jobs = self.carve_job(job, in_queue=False, job_number=total_jobs)
                                        if parsed_jobs:
                                            for p_j in parsed_jobs:
                                                # self.thread_logger.debug("Successfully carved job #{} from queue\n\t{}".format(total_jobs, p_j))
                                                p_j[u'job_number'] = total_jobs
                                                output_jobs_data.append(p_j)
                                                total_jobs += 1
                            except core.ConstructError:
                                self.thread_logger.debug("Queue structure failure, proceeding to carve in raw data")
                                carve_queue_jobs = [j for j in cq.split(self.delimiter) if j.strip(b'\x00')]
                                self.thread_logger.debug("Potential jobs found: {}".format(len(carve_queue_jobs)))
                                for c_job in carve_queue_jobs:
                                    parsed_jobs = self.carve_job(c_job, in_queue=False, job_number=total_jobs)
                                    if parsed_jobs:
                                        for p_j in parsed_jobs:
                                            # self.thread_logger.debug("Successfully carved job #{} from queue\n\t{}".format(total_jobs, p_j))
                                            p_j[u'job_number'] = total_jobs
                                            output_jobs_data.append(p_j)
                                            total_jobs += 1

                    except (core.RangeError, core.FieldError) as e:
                        self.thread_logger.warning("The queue for {} could not be parsed. ERROR: {}"
                                                   "".format(bit_file, e.message))
            except IOError as ioe:
                print "Error accessing file: {0}. Error: {1}".format(bit_file, ioe.args)
                return
            output_file = self.output_path(bit_file)

            with open(output_file, 'wb') as f:
                self.thread_logger.debug("Output file for table: {}".format(output_file))
                writer = csv.writer(f, delimiter='|')

                # write the headers (column names)

                writer.writerow(self.headers)

                # print table_name, "Total: ", len(all_data), "\n\t", headers
                total = len(output_jobs_data)
                if total > 0:
                    for j in output_jobs_data:
                        if j[u'file_count'] > 0:
                            file_id = 0
                            for file_to_write in j[u'files']:
                                temp = [j[u'job_number'], j[u'in_queue'], j[u'carved'], j[u'name'], j[u'job_id'],
                                        j[u'desc'], j[u'type'], j[u'priority'], j[u'sid'], j[u'state'], j[u'cmd'],
                                        j[u'args'], j[u'flags'], j[u'error_count'], j[u'errors'],
                                        j[u'transient_error_count'], j[u'retry_delay'], j[u'timeout'], j[u'file_count'],
                                        j[u'ctime'], j[u'mtime'], j[u'other_time0'], j[u'other_time1'],
                                        j[u'other_time2'], file_id]

                                try:
                                    temp_k = file_to_write.keys()
                                    if u'dest_fn' in temp_k:
                                        temp.append(file_to_write[u'dest_fn'].encode('utf-8'))
                                    else:
                                        temp.append("n/a")

                                    if u'src_fn' in temp_k:
                                        temp.append(file_to_write[u'src_fn'].encode('utf-8'))
                                    else:
                                        temp.append("n/a")

                                    if u'tmp_fn' in temp_k:
                                        temp.append(file_to_write[u'tmp_fn'].encode('utf-8'))
                                    else:
                                        temp.append("n/a")

                                    if u'download_size' in temp_k:
                                        temp.append(file_to_write[u'download_size'])
                                    else:
                                        temp.append("n/a")

                                    if u'transfer_size' in temp_k:
                                        temp.append(file_to_write[u'transfer_size'])
                                    else:
                                        temp.append("n/a")

                                    if u'drive' in temp_k:
                                        temp.append(file_to_write[u'drive'].encode('utf-8'))
                                    else:
                                        temp.append("n/a")

                                    if u'vol_guid' in temp_k:
                                        temp.append(file_to_write[u'vol_guid'].encode('utf-8'))
                                    else:
                                        temp.append("n/a")

                                except Exception as e:
                                    self.thread_logger.warning("Files for job {} could not be parsed. ERROR: {}"
                                                               "".format(j[u'job_number'], e.message))
                                    temp.append("n/a")
                                    temp.append("n/a")
                                    temp.append("n/a")
                                    temp.append("n/a")
                                    temp.append("n/a")
                                    temp.append("n/a")
                                    temp.append("n/a")

                                final_row = []
                                for v in temp:
                                    if type(v) == str:
                                        final_row.append(v.encode('ascii', 'xmlcharrefreplace').replace('\n', '; ').replace('\r', ''))
                                    else:
                                        final_row.append(v)
                                writer.writerow(final_row)
                                file_id += 1
                        else:
                            temp = [j[u'job_number'], j[u'in_queue'], j[u'carved'], j[u'name'], j[u'job_id'],
                                    j[u'desc'], j[u'type'], j[u'priority'], j[u'sid'], j[u'state'], j[u'cmd'],
                                    j[u'args'], j[u'flags'], j[u'error_count'], j[u'errors'],
                                    j[u'transient_error_count'], j[u'retry_delay'], j[u'timeout'], j[u'file_count'],
                                    j[u'ctime'], j[u'mtime'], j[u'other_time0'], j[u'other_time1'],
                                    j[u'other_time2'], 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a']
                            writer.writerow(temp)
                    file_names.append(output_file)
        return file_names

    def output_path(self, name):
        """
        get output file name for k-engine processed files

        Args:
            name: base name for output file (will be used for artifact doc_type

        Returns: the output file name
        """
        name_arr = self.output_file.split('.')
        return name_arr[0] + '(' + path.basename(name).replace("/", "-").replace(" ", "_") + ').' + name_arr[-1]

    def carve_job(self, job, in_queue=False, job_number=0):
        """
        A valid job is comprised of 2 to 3 sections:

        - description and controls
        - file transfers (optional)
        - metadata

        When carving data, most of the time, the first available section is
        partially overwritten making it difficult to retrieve relevant data.
        The last available one is always the metadata section.

        header = [u'carved', u'job_number', u'job_id', u'name', u'desc', u'type', u'priority', u'sid', u'state',
                  u'cmd', u'args', u'file_count', u'file_id', u'dest_fn', u'src_fn', u'tmp_fn', u'download_size',
                  u'transfer_size', u'drive', u'vol_guid', u'ctime', u'mtime', u'other_time0', u'other_time1',
                  u'other_time2']

        parsed_job = [in_queue, j.job_id, j.name, j.desc, j.type, j.priority, j.sid, j.state, j.cmd, j.args, j.file_count]

        :param job:
        :param in_queue:
        :param job_number:
        :return:
        """
        jobs = []
        job_n = job_number
        h = [u'dest_fn', u'src_fn', u'tmp_fn', u'download_size', u'transfer_size', u'drive', u'vol_guid']
        # self.thread_logger.debug("Parsing job #{}".format(job_number))
        try:
            j = self.JOB.parse(job)
            parsed_job = {
                u'in_queue': in_queue,
                u'carved': not in_queue,
                u'job_id': j.job_id,
                u'name': j.name,
                u'desc': j.desc,
                u'type': j.type,
                u'priority': j.priority,
                u'sid': j.sid,
                u'state': j.state,
                u'cmd': j.cmd,
                u'args': j.args,
                u'flags':  j.flags,
                u'error_count': j.error_count,
                u'errors': str(j.errors).replace("\n", ", "),
                u'transient_error_count': j.transient_error_count,
                u'retry_delay': j.retry_delay,
                u'timeout': j.timeout,
                u'file_count': int(j.file_count),
                u'files': [],
                u'ctime': j.ctime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                u'mtime': j.mtime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                u'other_time0': j.other_time0.strftime("%Y-%m-%d %H:%M:%S.%f"),
                u'other_time1': j.other_time1.strftime("%Y-%m-%d %H:%M:%S.%f"),
                u'other_time2': j.other_time2.strftime("%Y-%m-%d %H:%M:%S.%f")
            }

            temp = j.files.replace("[", "").replace("]", "").split(", ")
            t = ''.join([chr(int(item)) for item in temp])

            xfers = (x for x in t.split(self.xfer_delimiter))

            files_in_job = int(j.file_count)

            count = files_in_job
            for i in xfers:
                if count > 0:
                    try:
                        fil = self.FILE.parse(i)
                        parsed_file = {}
                        for hh in h:
                            try:
                                parsed_file[hh] = fil[hh]
                            except (KeyError, AttributeError):
                                parsed_file[hh] = 'n/a'

                        if parsed_file not in parsed_job[u'files']:
                            parsed_job[u'files'].append(parsed_file)
                    except (core.RangeError, core.FieldError):
                        self.thread_logger.warning('%d bytes of unknown data' % len(i))
                    count -= 1
            # print parsed_job
            if parsed_job not in jobs and parsed_job.values().count('n/a') <= 14:
                jobs.append(parsed_job)
                job_n += 1
        except (core.RangeError, core.FieldError, OverflowError) as e:
            self.thread_logger.warning('Error when parsing job #%d, attempting to carve from raw data \n%s' %
                                     (job_number, e.message))

            sections = [s for s in job.split(self.xfer_header) if s.strip(b'\x00')]
            carved_job = {
                        u'in_queue': in_queue,
                        u'carved': True,
                        u'job_id': 'n/a',
                        u'name': 'n/a',
                        u'desc': 'n/a',
                        u'type': 'n/a',
                        u'priority': 'n/a',
                        u'sid': 'n/a',
                        u'state': 'n/a',
                        u'cmd': 'n/a',
                        u'args': 'n/a',
                        u'flags': 'n/a',
                        u'error_count': 'n/a',
                        u'errors': 'n/a',
                        u'transient_error_count': 'n/a',
                        u'retry_delay': 'n/a',
                        u'timeout': 'n/a',
                        u'file_count': 0,
                        u'files': [],
                        u'ctime': 'n/a',
                        u'mtime': 'n/a',
                        u'other_time0': 'n/a',
                        u'other_time1': 'n/a',
                        u'other_time2': 'n/a',
                    }

            for section in reversed(sections):
                if len(section) >= 4:
                    self.thread_logger.debug('Searching for file transfers in job #{}'.format(job_number))
                    # file_count = int(section[:4].encode('hex'), byteorder='little')
                    files = []

                    # Carved in section:
                    carved_xfers = (x for x in section.split(self.xfer_delimiter))
                    for i in carved_xfers:
                        try:
                            fi = self.FILE.parse(i)
                            parsed_file = {}
                            for hh in h:
                                try:
                                    parsed_file[hh] = fi[hh]
                                except (KeyError, AttributeError):
                                    parsed_file[hh] = 'n/a'
                            if parsed_file not in carved_job[u'files']:
                                carved_job[u'files'].append(parsed_file)
                                carved_job[u'file_count'] += 1
                        except (core.RangeError, core.FieldError, OverflowError):
                            # self.thread_logger.warning('%d bytes of unknown data' % len(i))
                            pass

                    file_count = struct.unpack("<i", section[:4])[0]
                    if file_count * 37 < len(section):
                        offset = 4
                        while file_count > len(files) and section[offset:]:
                            self.thread_logger.debug('Trying to carve %d transfers' % file_count)
                            try:
                                recfile = self.FILE.parse(section[offset:])
                                # print recfile
                                if any(v for k, v in recfile.items() if k != 'offset'):
                                    files.append(recfile)

                                # remove invalid transfer_size
                                if recfile['transfer_size'] == 0xFFFFFFFFFFFFFFFF:
                                    recfile['transfer_size'] = ''

                            except (UnicodeDecodeError, core.ConstructError, OverflowError):
                                offset += 1
                                if offset == 16:   # don't waste time on irrelevant data.
                                    break          # 16 is an arbitrary high value
                            else:
                                if files:
                                    self.thread_logger.debug('new transfer found!')
                                    # print 'new transfer found!'
                                    offset += recfile.offset  # the offset is now after the
                                                              # newly carved file transfer
                    if files:
                        for t_f in files:
                            parsed_file = {}
                            for hh in h:
                                try:
                                    parsed_file[hh] = t_f[hh]
                                except (KeyError, AttributeError):
                                    parsed_file[hh] = 'n/a'
                            if parsed_file not in carved_job[u'files']:
                                carved_job[u'files'].append(parsed_file)
                                carved_job[u'file_count'] += 1

                    remains = self.deep_carving(section)
                    if remains:
                        # print remains.keys()
                        for key in remains.keys():
                            if not carved_job[unicode(key)] or carved_job[unicode(key)] == 'n/a':
                                carved_job[unicode(key)] = remains[key]
                            elif carved_job[unicode(key)] and carved_job[unicode(key)] == remains[key]:
                                pass
                            elif carved_job[unicode(key)] and carved_job[unicode(key)] != remains[key] and \
                                key == u'files':
                                # print len(remains[u'files'])
                                for temp_f in remains[u'files']:
                                    parsed_file = {}
                                    for hh in h:
                                        try:
                                            parsed_file[hh] = temp_f[hh]
                                        except (KeyError, AttributeError):
                                            parsed_file[hh] = 'n/a'
                                    if parsed_file not in carved_job[u'files']:
                                        # print temp_f
                                        carved_job[u'files'].append(parsed_file)
                                        carved_job[u'file_count'] += 1
                                        # print carved_job[u'file_count'], len(carved_job[u'files'])

                            else:
                                if key == u'file_count':
                                    pass
                                else:
                                    self.thread_logger.warning("While carving data found two entries for carved job "
                                                               "property: carved_job[unicode({})]={}, "
                                                               "and remains[{}]={}".format(key,
                                                                                           carved_job[unicode(key)],
                                                                                           key, remains[key]))
                    try:
                        m = self.METADATA.parse(section)
                        # print "METADATA UPDATE CALLED:", job_number
                        # print m
                        carved_job[u'error_count'] = m.error_count
                        carved_job[u'errors'] = str(m.errors).replace("\n", ", ")
                        carved_job[u'transient_error_count'] = m.transient_error_count
                        carved_job[u'retry_delay'] = m.retry_delay
                        carved_job[u'timeout'] = m.timeout
                        for i in [u'ctime', u'mtime', u'other_time0', u'other_time1', u'other_time2']:
                            try:
                                carved_job[i] = m[i].strftime("%Y-%m-%d %H:%M:%S.%f")
                                # print str(carved_job[i])
                            except ValueError:
                                carved_job[i] = str(m[i])
                                # print str(carved_job[i])
                        # carved_job[u'ctime'] = m.ctime.strftime("%Y-%m-%d %H:%M:%S.%f")
                        # carved_job[u'mtime'] = m.mtime.strftime("%Y-%m-%d %H:%M:%S.%f")
                        # carved_job[u'other_time0'] = m.other_time0.strftime("%Y-%m-%d %H:%M:%S.%f")
                        # carved_job[u'other_time1'] = m.other_time1.strftime("%Y-%m-%d %H:%M:%S.%f")
                        # carved_job[u'other_time2'] = m.other_time2.strftime("%Y-%m-%d %H:%M:%S.%f")

                    except (OverflowError, core.ConstructError):
                        self.thread_logger.debug('Metadata could not be parsed for job # {}, and section x'.format(job_number))
                    else:
                        continue

                    if carved_job not in jobs and carved_job.values().count('n/a') <= 14:
                        jobs.append(carved_job)
                        job_n += 1
        return jobs

    def carve_queues(self, data):
        """
        Carve binary queue fragments, by looking for queue delimiters

        :param data:
        """
        delimiter = bytearray.fromhex(self.QUEUE_HEADER)
        queues = [q for q in data.split(delimiter) if q.strip(b'\x00')]
        self.thread_logger.debug('queues: %d non-empty candidates' % len(queues))
        return queues

    def deep_carving(self, data):
        """
        Try to carve bytes for recognizable data.

        :param data:
        """

        rv = {}

        if data.startswith(bytearray.fromhex(self.FILE_HEADER)):
            data = data[16:]

        # Search for an SID (always starts with S-1- in utf16)
        pattern = b'S\x00-\x001\x00-\x00'
        sid_index = data.find(pattern)

        pattern = b'.\x00t\x00m\x00p\x00'
        bittmp_index = data.find(pattern)

        if sid_index > -1:
            rv.update(self.control_deep_carving(data, sid_index - 4))

        elif bittmp_index > -1:
            files = self.files_deep_carving(data, bittmp_index + 10)
            if files:
                rv['file_count'] = len(files)
                rv['files'] = files

        return rv

    def files_deep_carving(self, data, pivot_offset):
        """
        Carve partial file information from bytes.

        :param data:
        :param pivot_offset:
        """
        carved_files = []

        # the data is split in two parts on the pivot offset to separate stable
        # data from truncated data.
        partial = data[:pivot_offset]
        remains = data[pivot_offset:]

        # process the first bytes for relevant data
        rv, _ = self.rcarve_pascal_utf16(partial, u'tmp_fn', u'src_fn', u'dest_fn')
        if rv:
            carved_files.append(rv)
        else:
            return carved_files

        # update file #0 informations
        try:
            rv = self.FILE_PART_0.parse(remains)
        except (core.ConstructError, OverflowError):
            return carved_files
        else:
            carved_files[0].update(rv)
            remains = remains[rv.offset:]

        # insert files #1 and others if any
        while remains:
            try:
                new_file = self.FILE.parse(remains)
            except (core.ConstructError, OverflowError):
                break
            else:
                carved_files.append(dict(new_file))
                remains = remains[new_file.offset:]

        return carved_files

    def control_deep_carving(self, data, pivot_offset):
        """
        Carve partial file information from bytes.
        """
        # the data is split in two parts on the pivot offset to separate stable
        # data from truncated data.
        partial = data[:pivot_offset]
        remains = data[pivot_offset:]

        rv, sub_data = self.rcarve_pascal_utf16(partial, 'args', 'cmd', 'desc', 'name')
        if sub_data and len(sub_data) == 32:
            try:
                rv.update(self.CONTROL_PART_0.parse(sub_data))
            except core.ConstructError:
                pass

        try:
            rv.update(self.CONTROL_PART_1.parse(remains))
        except core.ConstructError as e:
            pass

        return rv

    def rcarve_pascal_utf16(self, data, *fields):
        """
        Search for utf16 fields in bytes.
        """
        rv = {}
        remaining_data = None

        for field in fields:
            valid_string = None

            for i in range(len(data) - 4, -1, -2):
                try:
                    valid_string = PascalUtf16().parse(data[i:])
                except (core.ConstructError, OverflowError):
                    pass    # invalid data
                else:
                    rv[field] = valid_string
                    data = data[:i]
                    remaining_data = data
                    break

            if valid_string is None:
                remaining_data = None
                # UGLY: extraction tentative of the remaining bytes
                for j in range(2, len(data), 2):
                    try:
                        res = data[-j:].replace(b'\x00', b'').decode()
                    except UnicodeDecodeError:
                        break
                    else:
                        if res:
                            rv[field] = res
                break       # no more data available

        return rv, remaining_data

    def guess_info(self, read_data):
        """
        Try to guess delimiter from available data.

        @param read_data: read data
        """
        count, candidate = max(
            (read_data.count(binascii.unhexlify(d)), binascii.unhexlify(d))
            for d in self.JOB_DELIMITERS.values()
        )

        # select as candidate the known delimiter with the most occurrences
        current_delimiter = candidate if count else None

        if current_delimiter is not None:
            # print current_delimiter
            return current_delimiter
        else:
            print 'Job delimiter is undefined'
            return None


if __name__ == '__main__':
    if len(argv[1:]) != 1:
        print "Please specify directory path containing qmgrX.dat input file(s):\npython bit_jobs_parser.py C:\\ProgramData\\Microsoft\\Network\\Downloader\\"
        exit(1)
    else:
        print 'The Begining'
        logging.basicConfig(format='(%(threadName)s) %(message)s', level=logging.DEBUG)
        logg = logging.getLogger(__name__)

        input_files = []

        if path.exists(argv[1]) and path.isdir(argv[1]):
            for root, dirs, files in walk(argv[1]):
                for f in files:
                    if f.endswith(".dat") and f.startswith("qmgr"):
                        input_files.append(path.join(root, f))
        else:
            print("Invalid directory path: {0}".format(argv[1]))

        if len(input_files) > 0:
            p = BITSParser(input_files, 'output.txt', logg)
            p.write_output()
        else:
            print "No qmgrX.dat files were found in the directory {0}".format(argv[1])
        print "The End"
