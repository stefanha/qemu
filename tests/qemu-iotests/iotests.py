# Common utilities and Python wrappers for qemu-iotests
#
# Copyright (C) 2012 IBM Corp.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import re
import subprocess
import string
import unittest
import sys; sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'scripts'))
import qemu
import struct

__all__ = ['imgfmt', 'imgproto', 'test_dir', 'IotestsTestCase', 'notrun', 'main']

imgfmt = os.environ.get('IMGFMT', 'raw')
imgproto = os.environ.get('IMGPROTO', 'file')
test_dir = os.environ.get('TEST_DIR', '/var/tmp')
output_dir = os.environ.get('OUTPUT_DIR', '.')
cachemode = os.environ.get('CACHEMODE')


def compare_images(img1, img2):
    '''Return True if two image files are identical'''
    return qemu_img('compare', '-f', imgfmt,
                    '-F', imgfmt, img1, img2) == 0
    # TODO

def create_image(name, size):
    '''Create a fully-allocated raw image with sector markers'''
    file = open(name, 'w')
    i = 0
    while i < size:
        sector = struct.pack('>l504xl', i / 512, i / 512)
        file.write(sector)
        i = i + 512
    file.close()

class VM(qemu.VM):
    '''A QEMU VM'''

    def __init__(self):
        self.add_qtest()
        self.add_display_none()
        self._num_drives = 0

    def add_drive(self, path, opts=''):
        '''Add a virtio-blk drive to the VM'''
        options = ['if=virtio',
                   'format=%s' % imgfmt,
                   'cache=%s' % cachemode,
                   'file=%s' % path,
                   'id=drive%d' % self._num_drives]
        if opts:
            options.append(opts)

        self._args.append('-drive')
        self._args.append(','.join(options))
        self._num_drives += 1
        return self


class IotestsTestCase(qemu.QMPTestCase):
    '''Abstract base class for iotests cases'''

    def assert_no_active_block_jobs(self):
        result = self.vm.qmp('query-block-jobs')
        self.assert_qmp(result, 'return', [])

    def cancel_and_wait(self, drive='drive0', force=False, resume=False):
        '''Cancel a block job and wait for it to finish, returning the event'''
        result = self.vm.qmp('block-job-cancel', device=drive, force=force)
        self.assert_qmp(result, 'return', {})

        if resume:
            self.vm.resume_drive(drive)

        cancelled = False
        result = None
        while not cancelled:
            for event in self.vm.get_qmp_events(wait=True):
                if event['event'] == 'BLOCK_JOB_COMPLETED' or \
                   event['event'] == 'BLOCK_JOB_CANCELLED':
                    self.assert_qmp(event, 'data/device', drive)
                    result = event
                    cancelled = True

        self.assert_no_active_block_jobs()
        return result

    def wait_until_completed(self, drive='drive0', check_offset=True):
        '''Wait for a block job to finish, returning the event'''
        completed = False
        while not completed:
            for event in self.vm.get_qmp_events(wait=True):
                if event['event'] == 'BLOCK_JOB_COMPLETED':
                    self.assert_qmp(event, 'data/device', drive)
                    self.assert_qmp_absent(event, 'data/error')
                    if check_offset:
                        self.assert_qmp(event, 'data/offset', self.image_len)
                    self.assert_qmp(event, 'data/len', self.image_len)
                    completed = True

        self.assert_no_active_block_jobs()
        return event

def notrun(reason):
    '''Skip this test suite'''
    # Each test in qemu-iotests has a number ("seq")
    seq = os.path.basename(sys.argv[0])

    open('%s/%s.notrun' % (output_dir, seq), 'wb').write(reason + '\n')
    print '%s not run: %s' % (seq, reason)
    sys.exit(0)

def main(supported_fmts=[]):
    '''Run tests'''

    if supported_fmts and (imgfmt not in supported_fmts):
        notrun('not suitable for this image format: %s' % imgfmt)

    # We need to filter out the time taken from the output so that qemu-iotest
    # can reliably diff the results against master output.
    import StringIO
    output = StringIO.StringIO()

    class MyTestRunner(unittest.TextTestRunner):
        def __init__(self, stream=output, descriptions=True, verbosity=1):
            unittest.TextTestRunner.__init__(self, stream, descriptions, verbosity)

    # unittest.main() will use sys.exit() so expect a SystemExit exception
    try:
        unittest.main(testRunner=MyTestRunner)
    finally:
        sys.stderr.write(re.sub(r'Ran (\d+) tests? in [\d.]+s', r'Ran \1 tests', output.getvalue()))
