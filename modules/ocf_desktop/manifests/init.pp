class ocf_desktop {
  include ocf::acct
  include ocf::packages::chrome
  include ocf::packages::cups
  include ocf::packages::firefox
  include ocf::packages::pulse

  include ocf_mesos::slave

  include ocf_desktop::crondeny
  include ocf_desktop::defaults
  include ocf_desktop::drivers
  include ocf_desktop::firewall_output
  include ocf_desktop::grub
  include ocf_desktop::modprobe
  include ocf_desktop::packages
  include ocf_desktop::sshfs
  include ocf_desktop::stats
  include ocf_desktop::steam
  include ocf_desktop::suspend
  include ocf_desktop::tmpfs
  include ocf_desktop::udev
  include ocf_desktop::wireshark
  include ocf_desktop::xsession

  # Firewall Rules #
  include ocf::firewall::allow_http

  # allow steam login and steam content
  ocf::firewall::firewall46 {
    '101 allow steam (tcp)':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'tcp',
        dport  => ['27015-27030', 27036, 27037],
        action => 'accept',
      };
  }
  ocf::firewall::firewall46 {
    '101 allow steam (udp)':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'udp',
        dport  => [4380, '27000-27031', 27036],
        action => 'accept',
      };
  }
}
