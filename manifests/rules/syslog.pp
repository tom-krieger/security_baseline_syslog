# @summary 
#    Ensure rsyslog or syslog-ng is installed (Scored)
#
# The rsyslog and syslog-ng software are recommended replacements to the original syslogd daemon which provide improvements 
# over syslogd , such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and 
# the encryption of log data en route to a central logging server.
#
# Rationale:
#ä The security enhancements of rsyslog and syslog-ng such as connection-oriented (i.e. TCP) transmission of logs, the 
# option to log to database formats, and the encryption of log data en route to a central logging server) justify 
# installing and configuring the package.
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
#   class { 'security_baseline_syslog::rules::rsyslog::filepermissions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::syslog (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  $logentry_default = {
    rulenr    => '4.2.3',
    rule      => 'syslog-installed',
    desc      => 'Ensure rsyslog or syslog-ng is installed (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($facts['security_baseline_syslog']['syslog_installed']) {
    $logentry_data = {
        level     => 'ok',
        msg       => 'Syslog-ng or syslog is installed.',
        rulestate => 'compliant',
      }
  } else {
    echo { 'syslog-installed':
      message  => 'Syslog-ng and rsyslog are not installed.',
      loglevel => $log_level,
      withpath => false,
    }
    $logentry_data = {
      level     => $log_level,
      msg       => 'Syslog-ng and rsyslog are not installed.',
      rulestate => 'not compliant',
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'syslog-installed':
    * => $logentry,
  }
}
