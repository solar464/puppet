class ocf::firewall::pre {
  Firewall {
    require => undef,
  }
  #Default rules
  firewall  { '000 accept all icmp (IPv4)':
    chain  => 'INPUT',
    proto  => 'icmp',
    action => 'accept',
  }


  firewall { '000 accept all icmp (IPv6)':
    chain    => 'INPUT',
    proto    => 'ipv6-icmp',
    action   => 'accept',
    provider => 'ip6tables',
  }

  ocf::firewall::firewall46 { '001 accept all to lo interface':
    opts => {
      'chain'   => 'INPUT',
      'proto'   => 'all',
      'iniface' => 'lo',
      'action'  => 'accept',
    },
  }

  ocf::firewall::firewall46 { '002 allow RELATED and ESTABLISHED traffic':
    opts => {
      'chain'  => 'INPUT',
      'proto'  => 'all',
      'state'  => ['RELATED', 'ESTABLISHED'],
      'action' => 'accept',
    },
  }

  firewall { '003 allow all SNS':
    source => '128.32.30.64/27',
    action => 'accept',
  }

  # allow from supernova and hypervisors, hard code the addresses in case of DNS malfunction
  # ordering: [supernova, crisis, hal, jaws, pandemic, riptide]

  $allow_all = ['169.229.226.36', '169.229.226.7', '169.229.226.10', '169.229.226.12',
                '169.229.226.14', '169.229.226.16']

  $allow_all_v6 = ['2607:f140:8801::1:36', '2607:f140:8801::1:7', '2607:f140:8801::1:10',
                    '2607:f140:8801::1:12', '2607:f140:8801::1:14', '2607:f140:8801::1:16']

  $allow_all.each |String $s| {
    firewall { "004 allow all from supernova and hypervisors (${s})":
      chain  => 'INPUT',
      action => 'accept',
      source => $s,
    }
  }

  $allow_all_v6.each |String $s| {
    firewall { "004 allow all from supernova and hypervisors (${s})":
      chain    => 'INPUT',
      action   => 'accept',
      source   => $s,
      provider => 'ip6tables',
    }
  }

  firewall { '005 allow ssh from desktops (IPv4)':
    chain     => 'INPUT',
    src_range => '169.229.226.100-169.229.226.139',
    proto     => 'tcp',
    dport     => 22,
    action    => 'accept',
  }

  firewall { '005 allow ssh from desktops (IPv6)':
    provider  => 'ip6tables',
    chain     => 'INPUT',
    src_range => '2607:f140:8801::1:100-2607:f140:8801::1:139',
    proto     => 'tcp',
    dport     => 22,
    action    => 'accept',
  }

  ocf::firewall::firewall46 { '006 allow munin connections':
    opts => {
      'action' => 'accept',
      'dport'  => 'munin',
      'source' => 'munin',
      'proto'  => 'tcp',
    },
  }
}
