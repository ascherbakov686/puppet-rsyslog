

Manage rsyslog client and server via Puppet

This is a reiteration of Saz Rsyslog module with some improvements.

## REQUIREMENTS

* Puppet >= 3.0
* Starting with release 4.0.0 Puppet < 3.0 is not tested anymore

## Supported platforms
* Debian-based distributions
* RedHat-based distributions


## USAGE

### Client

#### Using default values
```
  class { 'rsyslog::client': }
```

#### Variables and default values
```
  class { 'rsyslog::client':
    log_remote                => true,
    spool_size                => '1g',
    spool_timeoutenqueue      => false,
    remote_type               => 'tcp',
    remote_forward_format     => 'RSYSLOG_ForwardFormat',
    log_local                 => false,
    log_local_custom          => undef,
    log_auth_local            => false,
    listen_localhost          => false,
    split_config              => false,
    custom_config             => undef,
    custom_params             => undef,
    server                    => 'log',
    port                      => '514',
    remote_servers            => false,
    ssl_ca                    => undef,
    ssl_permitted_peer        => undef,
    ssl_auth_mode             => 'anon',
    log_templates             => false,
    log_filters               => false,
    actionfiletemplate        => false,
    high_precision_timestamps => false,
    rate_limit_burst          => undef,
    rate_limit_interval       => undef,
    imfiles                   => undef
  }
```
for read from file in puppet module files
```
  rsyslog::imfile { 'my-imfile':
    file_name     => '/some/file',
    file_tag      => 'mytag',
    file_facility => 'myfacility',
  }

```
To define `imfile` messages in Hiera, first add this class in your machine `.yaml` or `.json` file definition.
```
  - rsyslog::imfile_hiera
```

Then add muliple log files to read from. Specify imfile custom name with `rsyslog::imfile_hiera::imconfig_file:` parameter, as shown in the below example. This will place a new imfile in `/etc/rsyslog.d/` directory with the name defined by you. The Rsyslog server must have read permissions to the logs defined in imfile.
```
# rsyslog  imfile  
rsyslog::imfile_hiera::imconfig_file: 'to_storage-vm001_server.conf'
rsyslog::imfile_hiera::imfiles:
  '$InputFileName /var/log/nginx/access.log':
    - '$InputFileTag nginx'
    - '$InputFileStateFile state-nginx_access'
    - '$InputFileSeverity notice'
    - '$InputFileFacility local0'
    - '$InputFilePollInterval 10'
    - '$InputFilePersistStateInterval 0'
    - '$InputRunFileMonitor'

  '$InputFileName /var/log/collectd.log':
    - '$InputFileTag collectd'
    - '$InputFileStateFile state-collectd'
    - '$InputFileSeverity notice'
    - '$InputFileFacility local0'
    - '$InputFilePollInterval 10'
    - '$InputFilePersistStateInterval 0'
    - '$InputRunFileMonitor'
```

On the server side machine you need to create your own template to write these `imfile` logs. The `tag` and `facility` parameters must match with the ones defined in imfiles.
```
rsyslog::server::mytemplateh:
    - tname: 'nginx'
      logfile: 'nginx.log'
      facility: 'local0'
      tag: 'nginx'
      
    - tname: 'collectd'
      logfile: 'collectd.log'
      facility: 'local0'
      tag: 'collectd'
```

Log messages redirected to rsyslog server via puppet apache file with 'logger' command only with a 'tag'
Ex in Puppet Apache to redirect directly to rsyslog server:
```
access_log_pipe: "||/usr/bin/logger -t www -n 192.168.1.167 -d -P 514"
```

Create template on the Rsyslog server to receive and process Apache log messages via logger utility:
```
rsyslog::server::mytemplateh:
    - tname: 'www.domain.com'
      logfile: 'www_domain_com.log'
      tag: 'www' 
```
This will create the following template with the below rule:
```
#Template
$Template www.domain.com,"/opt/log/%HOSTNAME%/%$YEAR%/%$MONTH%/www_domain_com.log"
#Rule to redirect to template log file
if $syslogtag == "www" then -?www.domain.com
```

The `log_templates` parameter can be used to set up custom logging templates, which can be used for local and/or remote logging. More detail on template formats can be found in the [rsyslog documentation](http://www.rsyslog.com/doc/rsyslog_conf_templates.html).

The following examples sets up a custom logging template as per [RFC3164fmt](https://www.ietf.org/rfc/rfc3164.txt) on client side:

```puppet
class{'rsyslog::client':
  log_templates => [
    {
      name      => 'RFC3164fmt',
      template  => '<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%',
    },
  ]
}
```

#### Logging to multiple remote servers

The `remote_servers` parameter can be used to set up logging to multiple remote servers which are supplied as a list of key value pairs for each remote. There is an example configuration provided in `./test/multiple_hosts.pp`

Using the `remote_servers` parameter over-rides the other remote sever parameters, and they will not be used in the client configuration file:
* `log_remote`
* `remote_type`
* `server`
* `port`

The following example sets up three remote logging hosts for the client:

```puppet
class{'rsyslog::client':
  remote_servers => [
    {
      host => 'logs.example.org',
    },
    {
      port => '55514',
    },
    {
      host      => 'logs.somewhere.com',
      port      => '555',
      pattern   => '*.log',
      protocol  => 'tcp',
      format    => 'RFC3164fmt',
    },
  ]
}
```

To send logs to remote server via Hiera:
```
rsyslog::client::remote_servers: true
rsyslog::client::remote_servers:
  - host: '10.25.3.41'
    port: '514'
    pattern: 'mail,user,local0,auth,authpriv.*;*.err;'
    protocol: 'udp'
#    format: 'RFC3164fmt'
  - host: '10.25.3.42'
    port: '514'
    pattern: '*.*'
    protocol: 'tcp'
#    format: 'RFC3164fmt'
```

Each host has the following parameters:
* *host*: Sets the address or hostname of the remote logging server. Defaults to `localhost`
* *port*: Sets the port the host is listening on. Defaults to `514`
* *pattern*: Sets the pattern to match logs. Defaults to `*.*`
* *protocol*: Sets the protocol. Only recognises TCP and UDP. Defaults to UDP
* *format*: Sets the log format. Defaults to not specifying log format, which defaults to the format set by `ActionFileDefaultTemplate` in the client configuration.

#### Logging to a MySQL or PostgreSQL database

Events can also be logged to a MySQL or PostgreSQL database. The database needs to be deployed separately, either locally or remotely. Schema are available from the `rsyslog` source:

  * [MySQL schema](http://git.adiscon.com/?p=rsyslog.git;a=blob_plain;f=plugins/ommysql/createDB.sql)
  * [PostgreSQL schema](http://git.adiscon.com/?p=rsyslog.git;a=blob_plain;f=plugins/ompgsql/createDB.sql)

Declare the following to configure the connection:
````
  class { 'rsyslog::database':
    backend  => 'mysql',
    server   => 'localhost',
    database => 'Syslog',
    username => 'rsyslog',
    password => 'secret',
  }
````


To create a Rsyslog MySQL database server on a machine and send machine logs from local client to local database storage.
First add module to your machine hiera `.yaml` definition classes:
```
  - rsyslog::database
```
Then supply your database credentials and rsyslog pattern. The database template is represented by the file `mysql_createDB.sql.erb` stored in module template directory which automatically creates the required database schema. This file is copied to the server and placed in `/etc/rsyslog.d` path.

```
rsyslog::database::backend: 'mysql'
rsyslog::database::server: '127.0.0.1'
rsyslog::database::database: 'syslog'
rsyslog::database::username: 'youruser'
rsyslog::database::password: 'yourpass'
rsyslog::database::pattern1: 'local0,mail,user,auth,authpriv.*;cron.none;*.warn;'
```

You also need to define MySQL database server on the machine via `puppetlabs-mysql` module:
```
mysql::server::databases:
  syslog:
    ensure: present

mysql::server::users:
    youruser@%:
        ensure: present
        password_hash: '*E62D3F829F44A91CC231C76347712772B3B9DABC'
       
mysql::server::grants:
  youruser@%/syslog.*:
    ensure: present
    privileges: ALL
    table: syslog.*
    user: youruser@%
```

#### Logging from a Rsyslog Client machine to a MySQL remote database
To send log messages to a remote database from a client, first insert module name in client classes hiera .yaml definition:
```
  - "rsyslog::database_clientonly"
```
Keep in mind that `rsyslog::database_clientonly` module is in conflict with `rsyslog::database`. Make sure you remove `rsyslog::database` if defined in Rsyslog client hostname .yaml or .json definition.


Rsyslog db remote hiera definition example:
```
"rsyslog::database_clientonly::backend": mysql
"rsyslog::database_clientonly::server": "192.168.1.167"
"rsyslog::database_clientonly::database": syslog
"rsyslog::database_clientonly::username": youruser
"rsyslog::database_clientonly::password": yourpassword
"rsyslog::database_clientonly::pattern1": "local0,mail,user,auth,authpriv.*;*.warn;"
#discard some program logs ,such as CRON, or messages match in order to not flood the database with unwanted messages.
"rsyslog::database_clientonly::discard_prog": 'CRON' 
"rsyslog::database_clientonly::discard_msg": 'session opened for user nobody' 
```

### Server

#### Using default values
```
  class { 'rsyslog::server': }
```

#### Variables and default values
```
  class { 'rsyslog::server':
    enable_tcp                => true,
    enable_udp                => true,
    enable_relp               => true,
    enable_onefile            => false,
    relay_server              => false,
    server_dir                => '/srv/log/',
    custom_config             => undef,
    content                   => undef,
    port                      => '514',
    relp_port                 => '20514',
    address                   => '*',
    high_precision_timestamps => false,
    ssl_ca                    => undef,
    ssl_cert                  => undef,
    ssl_key                   => undef,
    log_templates             => false,
    log_filters               => false,
    actionfiletemplate        => false,
    rotate                    => undef
  }
```

Specify your own Rsyslog server log path store and rotate. The logs will be stored in a path as this: `/opt/log/machine_hostname/2018/04/`

```
rsyslog::server::server_dir: '/opt/log/'
rsyslog::server::rotate: 'month'
```

Add your own custom template on the server:
```
rsyslog::server::mytemplate: 'php-fpm'
rsyslog::server::mytemplate_facility: 'local0'
rsyslog::server::mytemplate_tag: 'php-fpm'
```
Specify other custom templates:
```
syslog::server::log_templates: true
rsyslog::server::log_templates:
    - name: 'ByProg'
      template: "/var/log/client_logs/%HOSTNAME%/%PROGRAMNAME%.log"
```

Server and client can be installed at the same time.

## PARAMETERS

The following lists all the class parameters this module accepts.

    RSYSLOG CLASS PARAMETERS            VALUES              DESCRIPTION
    -------------------------------------------------------------------
    msg_reduction                       true,false          Reduce repeated messages. Defaults to false.
    non_kernel_facility                 true,false          Permit non-kernel facility messages in the kernel log. Defaults to false.
    omit_local_logging                  true,false          Turn off message reception via local log socket. Defaults to true only for RedHat 7+ and false elsewhere.
    preserve_fqdn                       true,false          Use full name of host even if sender and receiver are in the same domain. Defaults to false.
    local_host_name                     STRING              Use a custom local host name, instead of clients actual host name. Defaults to undef.
    package_status                      STRING              Manages rsyslog package installation. Defaults to 'present'.

    RSYSLOG::SERVER CLASS PARAMETERS    VALUES              DESCRIPTION
    -------------------------------------------------------------------
    enable_tcp                          true,false          Enable TCP listener. Defaults to true.
    enable_udp                          true,false          Enable UDP listener. Defaults to true.
    enable_relp                         true,false          Enable RELP listener. Defaults to true.
    enable_onefile                      true,false          Only one logfile per remote host. Defaults to false.
    relay_server                        true,false          If the server should be able to relay the received logs to another server. The rsyslog::client must also be set up. Defaults to false.
    server_dir                          STRING              Folder where logs will be stored on the server. Defaults to '/srv/log/'
    custom_config                       STRING              Specify your own template to use for server config. Defaults to undef. Example usage: custom_config => 'rsyslog/my_config.erb'
    content                             STRING              Specify the content of the server config, instead of using a template. Defaults to undef.
    port                                STRING/INTEGER      Port to listen on for messages via UDP and TCP. Defaults to 514
    relp_port                           STRING/INTEGER      Port to listen on for messages via RELP. Defaults to 20514
    address                             STRING              The IP address to bind to. Applies to UDP listener only. Defaults to '*'.
    high_precision_timestamps           true,false          Whether or not to use high precision timestamps. Defaults to false.
    ssl_ca                              STRING              Path to SSL CA certificate. Defaults to undef.
    ssl_cert                            STRING              Path to SSL certificate. Defaults to undef.
    ssl_key                             STRING              Path to SSL private key. Defaults to undef.
    log_templates                       HASH                Provides a hash defining custom logging templates using the `$template` configuration parameter. Defaults to false.
    log_filters                         HASH                Provides a hash defining custom logging filters using the `if/then` configurations parameter. Defaults to false.
    actionfiletemplate                  STRING              If set this defines the `ActionFileDefaultTemplate` which sets the default logging format for remote and local logging. Defaults to false.
    rotate                              STRING              Enables rotation of logfiles. Valid values: year, month, day. Defaults to undef.

    RSYSLOG::CLIENT CLASS PARAMETERS    VALUES              DESCRIPTION
    -------------------------------------------------------------------
    log_remote                          true,false          Log Remotely. Defaults to true.
    spool_size                          STRING              Max size for disk queue if remote server failed. Defaults to '1g'.
    remote_type                         'tcp','udp','relp'  Which protocol to use when logging remotely. Defaults to 'tcp'.
    remote_forward_format               STRING              Which forward format for remote servers should be used. Only used if remote_servers is false.
    log_local                           true,false          Log locally. Defaults to false.
    log_auth_local                      true,false          Just log auth facility locally. Defaults to false.
    split_config                        true,false          Splits the client config into 00_client_config.conf, 50_client_remote.conf and 99_client_local.conf. Defaults to false.
    custom_config                       STRING              Specify your own template to use for client config. Defaults to undef. Example usage: custom_config => 'rsyslog/my_config.erb'
    custom_params                       TODO                TODO
    server                              STRING              Rsyslog server to log to. Will be used in the client configuration file. Only used, if remote_servers is false.
    port                                '514'               Remote server port. Only used if remote_servers is false.
    remote_servers                      Array of hashes     Array of hashes with remote servers. See documentation above. Defaults to false.
    ssl_ca                              STRING              SSL CA file location. Defaults to undef.
    ssl_permitted_peer                  STRING              List of permitted peers. Defaults to undef.
    ssl_auth_mode                       STRING              SSL auth mode. Defaults to anon.
    log_templates                       HASH                Provides a has defining custom logging templates using the `$template` configuration parameter.
    log_filters                         HASH                Provides a has defining custom logging filters using the `if/then` configurations parameter.
    actionfiletemplate                  STRING              If set this defines the `ActionFileDefaultTemplate` which sets the default logging format for remote and local logging.
    high_precision_timestamps           true,false          Whether or not to use high precision timestamps.
    rate_limit_burst                    INTEGER             Specifies the number of messages in $rate_limit_interval before limiting begins. Defaults to undef.
    rate_limit_interval                 INTEGER             Specifies the number of seconds per rate limit interval. Defaults to undef.

    RSYSLOG::DATABASE CLASS PARAMETERS  VALUES              DESCRIPTION
    -------------------------------------------------------------------
    backend                             'mysql','pgsql'     Database backend (MySQL or PostgreSQL).
    server                              STRING              Database server.
    database                            STRING              Database name.
    username                            STRING              Database username.
    password                            STRING              Database password.

### Other notes

In old configuration, by default, `rsyslog::server` will strip numbers from hostnames. This means the logs of
multiple servers with the same non-numerical name will be aggregrated in a single
directory. i.e. www01 www02 and www02 would all log to the www directory.

This default behaviour has been modified. Some logs are not aggregated anymore in a single directory but are stored in a directory by the name of each machine hostname (lines 11-22 in `server-default.conf.erb` from template module directory).
The old rule has  the below definition:
```
$Template dynKernLog,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%source:R,ERE,1,DFLT:([A-Za-z-]*)--end%<%= scope.lookupvar('rsyslog::server::logpath') -%>kern.log"
```

The new rules has this definition:
```
$Template dynDaemonLog,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>daemon.log"
```

Some rules had been added to discard some cron and samba messages which heavily spam `auth.log`. The rules can be found in the file `server-default.conf.erb` from template module directory, in between lines 52-60. Feel free to directly edit the file and add or remove this templates.
```
## OLD Rules to discard cron auth 
# :programname, isequal, "CRON" ~
if $programname == 'CRON' then stop

# Discard samba auth for nobody user messages 
if $programname == 'smbd' and $msg contains "session opened for user nobody" then stop
```

Also, some new default templates rules had been added in between lines 86-99 and line 109:
```
if $syslogfacility-text == 'local0' and $syslogtag == 'apachea' then -?dynApache
& stop

if $syslogfacility-text == 'local0' and $syslogtag == 'apachee' then -?dynApache_error
& stop

if $syslogfacility-text == 'local0' and $syslogtag == 'proftpd' then -?dynFtp
& stop

if $syslogfacility-text == 'local0' and $syslogtag == 'wtmp' then -?dynWtmp
& stop

if $syslogfacility-text == 'local0' and $syslogtag == 'nginx' or $syslogtag == 'nginx_error' then -?dynNginx
& stop
```
Their template definition is defined in between lines 25-30:
```
$Template dynApache,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>apache.log"
$Template dynApache_error,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>apache_eror.log"
$Template dynFtp,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>ftp.log"
#$Template dynDnsmasq,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>dnsmasq.log"
$Template dynWtmp,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>wtmp.log"
$Template dynNginx,"<%= scope.lookupvar('rsyslog::server::server_dir') -%>%HOSTNAME%<%= scope.lookupvar('rsyslog::server::logpath') -%>nginx.log"
```

To log each host to a seperate directory, set the custom_config parameter to
'rsyslog/server-hostname.conf.erb'

If any of the following parameters are set to `false`, then the module will not
manage the respective package:

    gnutls_package_name
    relp_package_name
    rsyslog_package_name

This can be used when using the adiscon PPA repository, that has merged rsyslog-gnutls
with the main rsyslog package.

Default package_status parameter for rsyslog class used to be 'latest'. However, it was
against puppet best practices so it defaults to 'present' now.


