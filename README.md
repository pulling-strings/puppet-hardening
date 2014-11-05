# Intro

A Pupppet module for hardening Ubuntu (and maybe FreeBSD in the future)

# Usage

```puppet
include hardening::ssh
include hardening::fail2ban
```

Add the following params to hiera:

```yaml
hardening::ssh::user: 'ronen'
hardening::ssh::strict: true
hardening::fail2ban::ignoreip: 
  - '192.168.1.1'
```

# Copyright and license

Copyright [2014] [First Last Name]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at:

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
