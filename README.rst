========================
Linux FireWire utilities
========================

2023/11/26 Takashi Sakamoto

What's this?
============

The linux-firewire-utils package contains Linux FireWire utilities for printing content of
configuration ROM (``config-rom-pretty-printer``), for listing devices (``lsfirewire``,
``lsfirewirephy``), and for querying and configuring devices (``firewire-request``,
``firewire-phy-command``).

The latest release is
`version 0.5.0 <https://git.kernel.org/pub/scm/utils/ieee1394/linux-firewire-utils.git/tag/?h=v0.5.0>`_

Installation
============

This package uses GNU Autoconf; you can use the standard installation
sequence.

::

    $ meson setup (--prefix=directory-to-install) build
    $ meson compile -C build
    $ meson install -C build


Authors
=======

* Clemens Ladisch
* Stefan Richter
* Takashi Sakamoto

The utilities were originally maintained by Clemens Ladisch in
`github.com <https://github.com/cladisch/linux-firewire-utils>`_, currently forked and maintained
by Takashi Sakamoto for further integration in
`git.kernel.org <https://git.kernel.org/pub/scm/utils/ieee1394/linux-firewire-utils.git/>`_.

License
=======

GNU GPL v2; see the file COPYING.


Links
=====

Report bugs to linux1394-devel@lists.sourceforge.net.

home page: `<http://ieee1394.docs.kernel.org/>`_

How to make DEB package
=======================

- Please refer to `<https://salsa.debian.org/takaswie/linux-firewire-utils>`_.
