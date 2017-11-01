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
}
