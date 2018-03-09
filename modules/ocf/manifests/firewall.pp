class ocf::firewall(
  # Temporary variable for enabling mandatory input packet filtering on a
  # host-by-host basis.
  $drop_other_input = false,
  ) {
  # Install prerequisite packages (that is, netfilter-persistent)
  include firewall

  include ocf::firewall::chains

  class {
    ['ocf::firewall::pre', 'ocf::firewall::post']:
      require => Class['ocf::firewall::chains'],
  }

  # One unpleasant thing about the puppetlabs-firewall module is that it
  # calls iptables-save, which saves all iptables rules when it runs,
  # including any transient rules added by Docker that happen to be
  # present. These transient rules then get saved and loaded at every boot.
  # Docker is designed to clear away or work with most existing iptables
  # rules. However, it doesn't clear POSTROUTING rules as we'd like it to,
  # so we have to manually ensure those don't get persisted.
  exec { 'Delete Docker POSTROUTING rules in iptables persistent config':
    require => Class['ocf::firewall::post'],
    command => "sed -i '/^-A POSTROUTING / d' /etc/iptables/rules.v4",
    onlyif  => "grep '^-A POSTROUTING ' /etc/iptables/rules.v4",
  }
}
