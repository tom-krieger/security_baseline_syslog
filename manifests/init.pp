# @summary 
#    Configure logging
#
# Logging services should be configured to prevent information leaks and to aggregate logs on a remote server so that they can be 
# reviewed in the event of a system compromise and ease log analysis.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @param logfile 
#    Logfile to log into
#
# @param syslog
#    Syslog gaemon to use
#
# @param is_loghost
#    Flag is a server is a syslog host
#
# @param remote_syslog_host
#    Remote server to send syslog messages to
#
# @example
#   include ::security_baseline_syslog
class security_baseline_syslog (
  Boolean $enforce                    = true,
  String $message                     = '',
  String $log_level                   = 'info',
  Integer $level                      = 1,
  Boolean $scored                     = true,
  String $logfile                     = '',
  Enum['rsyslog','syslog-ng'] $syslog = 'rsyslog',
  Boolean $is_loghost                 = false,
  String $remote_syslog_host          = '',
) {

  if($enforce) {
    if($syslog == 'syslog-ng') {
      class { 'syslogng': }
    } elsif ($syslog == 'rsyslog') {
      class { 'rsyslog::server': }
    }
  }

  class { '::security_baseline_syslog::rules':
    enforce   => $enforce,
    message   => $message,
    log_level => $log_level,
    level     => $level,
    scored    => $scored,
  }

  exec { 'reload-rsyslog':
    command     => 'pkill -HUP rsyslog',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'reload-syslog-ng':
    command     => 'pkill -HUP syslog-ng',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}
