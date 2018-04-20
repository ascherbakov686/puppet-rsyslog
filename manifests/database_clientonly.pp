# == Class: rsyslog::database
#
# Full description of class role here.
#
# === Parameters
#
# [*backend*]  - Which backend server to use (mysql|pgsql)
# [*server*]   - Server hostname
# [*database*] - Database name
# [*username*] - Database username
# [*password*] - Database password
#
# === Variables
#
# === Examples
#
#  class { 'rsyslog::database':
#    backend  => 'mysql',
#    server   => 'localhost',
#    database => 'mydb',
#    username => 'myuser',
#    password => 'mypass',
#  }
#
class rsyslog::database_clientonly (
  $backend,
  $server,
  $database,
  $username,
  $password,
  $pattern1 = '*.*',
  $backendfile = '/etc/rsyslog.d/z-mysql_client.conf',
  $discard_prog = undef,
  $discard_msg = undef,

  
) {
  include ::rsyslog

  case $backend {
    'mysql': { $db_package = $rsyslog::mysql_package_name }
    'pgsql': { $db_package = $rsyslog::pgsql_package_name }
    default: { fail("Unsupported backend: ${backend}. Only MySQL (mysql) and PostgreSQL (pgsql) are supported.") }
  }

  package { $rsyslog::mysql_package_name:
  ensure => installed,
}


  file { $backendfile:
    ensure    => present,
    mode => '0600',
    content   => template( 'rsyslog/database.conf.erb' ),
    require   => Package[$db_package],
      notify => Class['rsyslog::service'],
	}

  
}
