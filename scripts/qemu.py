# Module for launching and interacting with QEMU
#
# Copyright (C) 2012 IBM Corp.
# Copyright (C) 2014 Red Hat Inc
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
import string
import subprocess
import sys
import tempfile
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), 'qmp'))
import qmp

__all__ = ['logfile', 'qemu_img', 'qemu_io', 'VM', 'dictpath', 'QMPTestCase']

# Note that the path and (optional) arguments cannot contain spaces
qemu_img_args = os.environ.get('QEMU_IMG', 'qemu-img').strip().split(' ')
qemu_io_args = os.environ.get('QEMU_IO', 'qemu-io').strip().split(' ')
qemu_args = os.environ.get('QEMU', 'qemu').strip().split(' ')
socket_scm_helper = os.environ.get('SOCKET_SCM_HELPER',
                                   'socket_scm_helper').strip().split(' ')

# By default all activity goes straight to standard output.  This module
# variable can be set by the user to silence or divert output.
logfile = sys.stdout


def _run_and_capture_stdout(args):
    '''Run command and return its output as a string'''
    logfile.write('Executing: %s\n' % ' '.join(args))
    output = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()[0]
    logfile.write(output)
    return output


def qemu_img(*args):
    '''Run qemu-img and return its output'''
    return _run_and_capture_stdout(qemu_img_args + list(args))


def qemu_io(*args):
    '''Run qemu-io and return its output'''
    return _run_and_capture_stdout(qemu_io_args + list(args))


class VM(object):
    '''A QEMU VM'''

    def __init__(self):
        self._popen = None
        self._args = list(qemu_args)

    def add_args(self, *args):
        '''Add arguments to the QEMU command-line'''
        self._args.extend(args)

    def log(self, msg):
        '''Print a message to the logger'''
        logfile.write('VM %#x: %s\n' % (id(self), msg))

    def launch(self):
        '''Launch the VM and establish a QMP connection'''
        assert self._popen is None

        mon_path = tempfile.mktemp()    # mkstemp() only does regular files
        self._qmp = qmp.QEMUMonitorProtocol(mon_path, server=True)
        self.add_args('-chardev', 'socket,id=mon,path=%s' % mon_path,
                      '-mon', 'chardev=mon,mode=control')

        self.log('Launching: ' + ' '.join(self._args))

        try:
            self._popen = subprocess.Popen(self._args,
                                           stdout=logfile,
                                           stderr=subprocess.STDOUT)
            self._qmp.accept()
        finally:
            os.remove(mon_path)

    def shutdown(self):
        '''Terminate the VM and clean up'''
        if self._popen is not None:
            self._qmp.cmd('quit')
            self._popen.wait()
            self._popen = None
            self.log('Shut down')

    def __enter__(self):
        self.launch()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
        return False    # propagate exception

    def add_display_none(self):
        '''Disable graphics'''
        self.add_args('-display', 'none', '-vga', 'none')

    def add_qtest(self):
        '''Add the qtest accelerator'''
        self.add_args('-qtest', 'null', '-machine', 'accel=qtest')

    def add_monitor_telnet(self, ip, port):
        '''Add a telnet HMP monitor'''
        self.add_args('-monitor', 'tcp:%s:%d,server,nowait,telnet' % (ip, port))

    def hmp_qemu_io(self, drive, cmd):
        '''Perform a qemu-io command on a given drive'''
        return self.qmp('human-monitor-command',
                        command_line='qemu-io %s "%s"' % (drive, cmd))

    def pause_drive(self, drive, event=None):
        '''Pause drive r/w operations'''
        if not event:
            self.pause_drive(drive, "read_aio")
            self.pause_drive(drive, "write_aio")
            return
        self.hmp_qemu_io(drive, 'break %s bp_%s' % (event, drive))

    def resume_drive(self, drive):
        '''Resume drive r/w operations'''
        self.hmp_qemu_io(drive, 'remove_break bp_%s' % drive)

    def add_fd(self, fd, fdset, opaque, opts=''):
        '''Pass a file descriptor to the VM'''
        options = ['fd=%d' % fd,
                   'set=%d' % fdset,
                   'opaque=%s' % opaque]
        if opts:
            options.append(opts)

        self.add_args('-add-fd', ','.join(options))

    def send_fd_scm(self, fd_file_path):
        '''Open file and send its file descriptor over QMP socket'''
        # In iotest.py, the qmp should always use unix socket.
        assert self._qmp.is_scm_available()
        return subprocess.Popen([
            socket_scm_helper,
            "%d" % self._qmp.get_sock_fd(),
            fd_file_path
        ], stdout=sys.stdout, stderr=sys.stderr).wait()

    _underscore_to_dash = string.maketrans('_', '-')

    def qmp(self, cmd, **args):
        '''Invoke a QMP command and return the result dict'''
        qmp_args = dict()
        for k in args.keys():
            qmp_args[k.translate(self._underscore_to_dash)] = args[k]

        self.log('-> QMP %s %s' % (cmd, qmp_args))
        retval = self._qmp.cmd(cmd, args=qmp_args)
        self.log('<- QMP %s' % retval)
        return retval

    def get_qmp_event(self, wait=False):
        '''Poll for one queued QMP event and return it'''
        return self._qmp.pull_event(wait=wait)

    def get_qmp_events(self, wait=False):
        '''Poll for queued QMP events and return a list of dicts'''
        events = self._qmp.get_events(wait=wait)
        self._qmp.clear_events()
        return events


_index_re = re.compile(r'([^\[]+)\[([^\]]+)\]')

def dictpath(self, d, path):
    '''Traverse a path in a nested dict such as a QMP response object'''
    for component in path.split('/'):
        m = _index_re.match(component)
        if m:
            component, idx = m.groups()
            idx = int(idx)

        if not isinstance(d, dict) or component not in d:
            raise ValueError('failed path traversal for "%s" in "%s"' % (path, str(d)))
        d = d[component]

        if m:
            if not isinstance(d, list):
                raise ValueError('path component "%s" in "%s" is not a list in "%s"' % (component, path, str(d)))
            try:
                d = d[idx]
            except IndexError:
                raise ValueError('invalid index "%s" in path "%s" in "%s"' % (idx, path, str(d)))
    return d


class QMPTestCase(unittest.TestCase):
    '''Abstract base class for QMP test cases'''

    def assert_qmp_absent(self, d, path):
        try:
            result = dictpath(d, path)
        except ValueError:
            return
        self.fail('path "%s" has value "%s"' % (path, str(result)))

    def assert_qmp(self, d, path, value):
        '''Assert that the value for a specific path in a QMP dict matches'''
        result = dictpath(d, path)
        self.assertEqual(result, value, 'values not equal "%s" and "%s"' % (str(result), str(value)))
