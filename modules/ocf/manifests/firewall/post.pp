class ocf::firewall::post {
  require ocf::networking

  # Only allow root and postfix to connect to anthrax port 25; everyone else
  # must use the sendmail interface.
  # firewall-multi doesn't multiplex this so we have to do it manually :(
  ['root', 'postfix'].each |$username| {
    ocf::firewall::firewall46 {
      "996 allow ${username} to send on SMTP port":
        opts   => {
          chain  => 'PUPPET-OUTPUT',
          proto  => 'tcp',
          dport  => 25,
          uid    => $username,
          action => 'accept',
        },
        before => undef,
    }
  }

  ocf::firewall::firewall46 {
    '997 forbid other users from sending on SMTP port':
      opts   => {
        chain       => 'PUPPET-OUTPUT',
        proto       => 'tcp',
        destination => ['anthrax', 'dev-anthrax'],
        dport       => 25,
        action      => 'drop',
      },
      before => undef,
  }

  # Special devices we want to protect from most hosts
  $devices_ipv4_only = ['corruption-mgmt','hal-mgmt', 'jaws-mgmt', 'pagefault',
                        'pandemic-mgmt', 'papercut', 'riptide-mgmt']
  $devices = ['radiation']

  firewall { '998 allow all outgoing ICMP':
    chain  => 'PUPPET-OUTPUT',
    proto  => 'icmp',
    action => 'accept',
    before => undef,
  }

  firewall { '998 allow all outgoing ICMPv6':
    provider => 'ip6tables',
    chain    => 'PUPPET-OUTPUT',
    proto    => 'ipv6-icmp',
    action   => 'accept',
    before   => undef,
  }

  firewall_multi { '999 drop output (special devices)':
    chain       => 'PUPPET-OUTPUT',
    proto       => 'all',
    action      => 'drop',
    destination => $devices_ipv4_only,
    before      => undef,
  }

  ocf::firewall::firewall46 { '999 drop output (special devices)':
    opts   => {
      chain       => 'PUPPET-OUTPUT',
      proto       => 'all',
      action      => 'drop',
      destination => $devices,
    },
    before => undef,
  }

  # drop from internal zone exceptions: tsunami, werewolves, death, and dev- versions
  # hard code the addresses in case of DNS malfunction

  $drop_all = ['tsunami', 'werewolves', 'death', 'dev-tsunami', 'dev-werewolves', 'dev-death']

  $drop_all.each |String $s| {
    ocf::firewall::firewall46 { "997 drop internal zone exception, (${s})":
      opts  => {
        chain  => 'PUPPET-INPUT',
        proto  => ['tcp', 'udp'],
        action => 'drop',
        source => $s
      }
    }
  }

  firewall {
    '998 allow from internal zone (IPv4)':
      chain     => 'PUPPET-INPUT',
      src_range => '169.229.226.5-169.229.226.90',
      proto     => ['tcp', 'udp'],
      action    => 'accept';

    '998 allow ssh from desktops (IPv6)':
      provider  => 'ip6tables',
      chain     => 'PUPPET-INPUT',
      src_range => '2607:f140:8801::1:100-2607:f140:8801::1:139',
      proto     => ['tcp', 'udp'],
      action    => 'accept';
  }

  # Drop packets on the primary network inteface that are not whitelisted
  # TODO: eliminate this if statement once testing is complete
  if !$ocf::firewall::allow_other_traffic {
    ocf::firewall::firewall46 {
      '999 drop unrecognized input packets on primary interface':
        opts   => {
          chain  => 'PUPPET-INPUT',
          proto  => 'all',
          src    => ['tcp', 'udp'],
          action => 'drop',
        },
        before => undef,
    }
  }
}
