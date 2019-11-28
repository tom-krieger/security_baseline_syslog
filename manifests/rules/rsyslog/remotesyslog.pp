# @summary 
#    Ensure rsyslog is configured to send logs to a remote log host (Scored)
#
# The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to 
# receive messages from remote hosts, reducing administrative overhead.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on 
# the local system, they could tamper with or remove log data that is stored on the local system
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
# @example
#   class { 'security_baseline_syslog::rules::rsyslog::remotesyslog':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::rsyslog::remotesyslog (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  $logentry_default = {
    rulenr    => '4.2.1.4',
    rule      => 'rsyslog-remotesyslog',
    desc      => 'Ensure rsyslog is configured to send logs to a remote log host (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($::security_baseline_syslog::syslog == 'rsyslog') {

    if($facts['security_baseline_syslog']['rsyslog']['remotesyslog'] == 'none') {
      echo { 'rsyslog-remotesyslog':
        message  => 'Rsyslog is not configured to send logs to a remote log host.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Rsyslog is not configured to send logs to a remote log host.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Rsyslog is configured to send logs to a remote log host.',
        rulestate => 'compliant',
      }
    }

    if($enforce) {
      if($::security_baseline_syslog::remote_syslog_host != '') {
        file_line { 'rsyslog-remotesyslog':
          ensure => present,
          path   => '/etc/rsyslog.conf',
          line   => "*.* @@@@${::security_baseline_syslog::remote_syslog_host}",
          match  => '\*\.\* @@',
          notify => Exec['reload-rsyslog'],
        }
      }
    }

    $logentry = $logentry_default + $logentry_data
    ::security_baseline::logging { 'rsyslog-remotesyslog':
      * => $logentry,
    }
  }
}
