# iptables based ssh connections rate limit
class baseline::hardening::ssh_ratelimit($allowed_host=''){
  include ufw
  $before = "\# don't delete the 'COMMIT' line or these rules won't be processed"

  if($allowed_host != ''){
    File_Line['Prevent SSH bruth force'] ->

    file_line { 'Allow host':
      path  => '/etc/ufw/before.rules',
      line  => "-A INPUT -p tcp -s ${allowed_host} --dport ssh -j ACCEPT",
      after => $before
    }
  }

  file_line { 'Pass SSH':
    path  => '/etc/ufw/before.rules',
    line  => '-A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT',
    after => $before
  } ->

  file_line { 'Prevent SSH bruth force':
    path  => '/etc/ufw/before.rules',
    line  => '-A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 120 --hitcount 8 --rttl --name SSH -j DROP',

    after => $before
  } ->

  file_line { 'Mark ssh packets':
    path   => '/etc/ufw/before.rules',
    line   => '-A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH',
    after  => $before,
    notify => Service['ufw']
  } -> Exec['ufw-enable']

}
