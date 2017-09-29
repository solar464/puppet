class ocf::firewall::pre {
  Firewall{
    require => undef,
  }
  #Default rules
  firewall  { '000 accept all icmp (IPv4)':
    chain  => 'INPUT',
    proto  => 'icmp',
    action => 'accept',
  }


  firewall  { '000 accept all icmp (IPv6)':
    chain    => 'INPUT',
    proto    => 'icmpv6',
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

  ocf::firewall::firewall46{ '002 allow RELATED and ESTABLISHED traffic':
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
  ocf::firewall::firewall46{ '004 allow ssh from staff login server':
    opts => {
      'source' => 'admin',
      'action' => 'accept',
      'proto'  => 'tcp',
    },
  }
  ocf::firewall::firewall46 { '005 allow munin connections':
    opts => {
      'action' => 'accept',
      'dport'  => 'munin',
      'source' => 'munin',
      'proto'  => 'tcp',
    },
  }
}
