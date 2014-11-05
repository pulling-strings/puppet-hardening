# fail2ban setup
class hardening::fail2ban($ignoreip=[]) {
  
  package{'fail2ban':
    ensure  => present
  } ->

  file { '/etc/fail2ban/jail.local':
    ensure=> file,
    mode  => '0644',
    content => template('hardening/jail.conf.erb'),
    owner => root,
    group => root,
  } ~>

  service{'fail2ban':
    ensure    => running,
    enable    => true,
    hasstatus => true,
  }


}
