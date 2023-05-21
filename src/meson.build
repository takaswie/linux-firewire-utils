#
# Metadata.
#

conf = configuration_data()

conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('PACKAGE_STRING', meson.project_name())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_URL', 'https://git.kernel.org/pub/scm/utils/ieee1394/linux-firewire-utils.git/')
conf.set_quoted('PACKAGE_BUGREPORT', 'linux1394-devel@sourceforge.net')

#
# Commands
#

lsfirewire = configure_file(
  input: 'lsfirewire.in',
  output: 'lsfirewire',
  configuration: conf,
  install: true,
  install_dir: join_paths(get_option('prefix'), get_option('bindir')),
  install_mode: 'rwxr-xr-x',
)

config_header = configure_file(
  input: 'config.h.template',
  output: 'config.h',
  configuration: conf,
)

lsfirewirephy = executable('lsfirewirephy',
  sources: ['lsfirewirephy.c', config_header],
  install: true,
)

firewire_request = executable('firewire-request',
  sources: ['firewire-request.c', config_header],
  install: true,
)

firewire_phy_command = executable('firewire-phy-command',
  sources: ['firewire-phy-command.c', config_header],
  install: true,
)

config_rom_pretty_printer_command = executable('config-rom-pretty-printer',
  sources: 'config-rom-pretty-printer.c',
  install: true,
)

#
# Man pages.
#

manuals = [
  'lsfirewire.8',
  'lsfirewirephy.8',
  'firewire-request.8',
  'firewire-phy-command.8',
  'config-rom-pretty-printer.8',
]

man_pages = []

foreach output : manuals
  input = output + '.in'
  man_pages += configure_file(
    input: input,
    output: output,
    configuration: conf,
  )
endforeach

install_man(man_pages)
