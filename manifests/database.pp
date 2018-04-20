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
class rsyslog::database (
  $backend,
  $server,
  $database,
  $username,
  $password,
  $pattern1 = '*.*',
) {
  include ::rsyslog

  case $backend {
    'mysql': { $db_package = $rsyslog::mysql_package_name }
    'pgsql': { $db_package = $rsyslog::pgsql_package_name }
    default: { fail("Unsupported backend: ${backend}. Only MySQL (mysql) and PostgreSQL (pgsql) are supported.") }
  }

  package { $db_package:
    ensure => $rsyslog::package_status,
  }

  rsyslog::snippet { "z-${backend}":
    ensure    => present,
    file_mode => '0600',
    content   => template("${module_name}/database.conf.erb"),
    require   => Package[$db_package],
    notify => Class['rsyslog::service'],
	}

    file { '/etc/rsyslog.d/mysql_createDB.sql':
    ensure => present,
    content => template("${module_name}/mysql_createDB.sql.erb"),
	recurse => true,
    purge   => true,
    require   => Package[$db_package],
  }
	 exec { 'import_rsyslog_mysql_db':
        unless  => '/usr/bin/test -f /var/rsyslogdb_populated',
		path    => ['/usr/bin', '/bin',],
        command => "cat /etc/rsyslog.d/mysql_createDB.sql | mysql -u root -plinux && touch /var/rsyslogdb_populated",
		require   => [ Package[$db_package], Service["mysqld"] ],
        
      }
}
