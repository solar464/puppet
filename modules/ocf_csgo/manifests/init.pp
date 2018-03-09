class ocf_csgo {
  include ocf::firewall::allow_http
  include ocf::apt::i386

  user { 'ocfcsgo':
    comment => 'Counter-Strike Server',
    home    => '/opt/csgo',
    groups  => ['sys'],
    shell   => '/bin/false';
  }

  file {
    default:
      owner  => ocfcsgo,
      group  => ocfcsgo;

    ['/opt/csgo', '/opt/csgo/bin', '/opt/csgo/etc']:
      ensure => directory,
      mode   => '0755';

    '/opt/csgo/bin/update-csgo':
      source => 'puppet:///modules/ocf_csgo/bin/update-csgo',
      mode   => '0755';

    '/opt/csgo/etc/csgo-update.cmd':
      source => 'puppet:///modules/ocf_csgo/etc/csgo-update.cmd';
  }

  package {
    'lib32gcc1':;
  }

  exec {
    'download-steamcmd':
      command => 'curl http://media.steampowered.com/installer/steamcmd_linux.tar.gz | tar xzf - -C /opt/csgo/bin',
      user    => ocfcsgo,
      creates => '/opt/csgo/bin/steamcmd.sh',
      notify  => Exec['update-csgo'],
      require => File['/opt/csgo/bin'];

    'update-csgo':
      command     => '/opt/csgo/bin/update-csgo',
      user        => ocfcsgo,
      refreshonly => true,
      require     => [File['/opt/csgo/bin/update-csgo'], Package['lib32gcc1']];
  }

  ocf::munin::plugin { 'csgo':
    source => 'puppet:///modules/ocf_csgo/munin';
  }

  # Firewall rules for dedicated server hosting
  ocf::firewall::firewall46 {
    '101 allow srcds_linux':
      opts => {
        chain  => 'PUPPET-INPUT',
        proto  => ['tcp', 'udp'],
        dport  => [26901, 27005, 27015, 27020],
        action => 'accept',
      };
  }
}
