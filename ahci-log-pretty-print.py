#!/usr/bin/env python2
import sys
import re

bar_write_re = re.compile(r'^vfio: vfio_bar_write\(0000:00:1f\.2:BAR5\+(?P<addr>[xa-z0-9]+), (?P<value>[xa-z0-9]+), (?P<size>\d+)\)$')
bar_read_re = re.compile(r'^vfio: vfio_bar_read\(0000:00:1f\.2:BAR5\+(?P<addr>[xa-z0-9]+), (?P<size>\d+)\) = (?P<value>.*)$')

def get_port_reg_name(addr):
	if addr == 0: return 'Command List Base Address'
	elif addr == 4: return 'Command List Base Address Upper 32-Bits'
	elif addr == 8: return 'FIS Base Address'
	elif addr == 0xc: return 'FIS Base Address Upper 32-Bits'
	elif addr == 0x10: return 'Interrupt Status'
	elif addr == 0x14: return 'Interrupt Enable'
	elif addr == 0x18: return 'Command and Status'
	elif addr == 0x20: return 'Task File Data'
	elif addr == 0x24: return 'Signature'
	elif addr == 0x28: return 'Serial ATA Status (SCR0: SStatus)'
	elif addr == 0x2c: return 'Serial ATA Control (SCR2: SControl)'
	elif addr == 0x30: return 'Serial ATA Error (SCR1: SError)'
	elif addr == 0x34: return 'Serial ATA Active (SCR3: SActive)'
	elif addr == 0x38: return 'Command Issue'
	elif addr == 0x3c: return 'Serial ATA Notification (SCR4: SNotification)'
	elif addr == 0x40: return 'FIS-based Switching Control'
	return 'unknown (%#x)' % addr

def get_bar5_reg_name(addr):
	x = int(addr, 16)
	if x == 0: return 'Host Capabilities'
	elif x == 4: return 'Global Host Control'
	elif x == 8: return 'Interrupt Status'
	elif x == 0xc: return 'Ports Implemented'
	elif x == 0x10: return 'Version'
	elif x == 0x14: return 'Command Completion Coalescing Control'
	elif x == 0x18: return 'Command Completion Coalescing Ports'
	elif x == 0x1c: return 'Enclosure Management Location'
	elif x == 0x20: return 'Enclosure Management Control'
	elif x == 0x24: return 'Host Capabilities Extended'
	elif x == 0x28: return 'BIOS/OS Handoff Control and Status'
	elif 0x100 <= x <= 0x10ff: # Port control registers
		port_num = (x - 0x100) // 0x80
		return 'Port %d %s' % (port_num, get_port_reg_name(x - 0x100 - port_num * 0x80))
	return addr

def bar_write(addr, value, size):
	print 'bar_write %s value %s size %s' % (get_bar5_reg_name(addr), value, size)

def bar_read(addr, size, value):
	print 'bar_read %s size %s value %s' % (get_bar5_reg_name(addr), size, value)

for line in sys.stdin:
	m = bar_write_re.match(line)
	if m:
		bar_write(*m.groups())
		continue
	m = bar_read_re.match(line)
	if m:
		bar_read(*m.groups())
		continue
	print line,
