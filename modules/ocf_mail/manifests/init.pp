class ocf_mail {
  include ocf_ssl::default_bundle
  include ocf_mail::firewall_input
  include ocf_mail::spam
  include ocf_mail::site_ocf
  include ocf_mail::site_vhost

  package { ['postfix']:; }

  service { 'postfix':
    require => Package['postfix'],
  }
  user { 'ocfmail':
    ensure  => present,
    name    => ocfmail,
    gid     => ocfmail,
    groups  => [sys],
    home    => '/var/mail',
    shell   => '/bin/false',
    system  => true,
    require => Group['ocfmail'],
  }

  group { 'ocfmail':
    ensure => present,
    name   => ocfmail,
    system => true,
  }

  file { '/etc/postfix/main.cf':
    mode    => '0644',
    content => template('ocf_mail/postfix/main.cf.erb'),
    notify  => Service['postfix'],
    require => Package['postfix'],
  }

  ocf::firewall::firewall46 {
    '101 allow submission':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'tcp',
        dport  => 587,
        action => 'accept',
      };

    '102 allow smtp':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => 'tcp',
        dport  => 25,
        action => 'accept',
      };
  }
}
