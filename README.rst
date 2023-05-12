========================
Linux FireWire utilities
========================

2023/05/12 Takashi Sakamoto

What's this?
============

The linux-firewire-utils package contains Linux FireWire utilities for
listing devices (lsfirewire, lsfirewirephy) and for querying and
configuring devices (firewire-request, firewire-phy-command).


Installation
============

This package uses GNU Autoconf; you can use the standard installation
sequence.

::

    $ meson (--prefix=directory-to-install) build
    $ meson compile -C build
    $ meson install -C build


Authors
=======

* Clemens Ladisch
* Stefan Richter
* Takashi Sakamoto

License
=======

GNU GPL v2; see the file COPYING.


Links
=====

Report bugs to linux1394-devel@lists.sourceforge.net.

home page: `<http://ieee1394.docs.kernel.org/>`_
