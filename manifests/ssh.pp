# SSH hardening see:
#  http://bodhizazen.net/Tutorials/SSH_security 
class hardening::ssh($user,$strict=false){
  file_line { 'disable ssh protocol 1':
    path => '/etc/ssh/ssh_config',
    line => 'Protocol 2'
  }

  file_line {'Disable password auth' :
    path => '/etc/ssh/ssh_config',
    line => 'PasswordAuthentication no'
  }

  file_line {'Allow only single ssh user' :
    path => '/etc/ssh/ssh_config',
    line => "AllowUsers ${user}"
  }

  file_line {'Dont allow root ssh' :
    path => '/etc/ssh/ssh_config',
    line =>  'PermitRootLogin no'
  } ~> Service['ssh']

  ensure_resource('service', 'ssh', {})

  if($strict){
    file_line {'No tcp forwarding' :
      path => '/etc/ssh/ssh_config',
      line => 'AllowTcpForwarding no'
    }

    file_line {'No X11 forwarding' :
      path => '/etc/ssh/ssh_config',
      line => 'X11Forwarding no'
    }

    file_line {'Strict file mode checks' :
      path => '/etc/ssh/ssh_config',
      line => 'StrictModes yes'
    }
  }
}
