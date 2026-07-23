#!/bin/sh
# Convert the APE binary in place to a native ELF so it also works when
# invoked via execve directly (systemd, xargs, exec*) instead of through a
# shell. Harmless if it fails; the binary still runs from any shell.
/usr/bin/finpass --assimilate 2>/dev/null \
	|| sh /usr/bin/finpass --assimilate 2>/dev/null \
	|| true
