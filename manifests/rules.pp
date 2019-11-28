# @summary 
#    Wrapper class around all syslog checks
#
# Call all classes dealing with syslog rules
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
# @example
#   include security_baseline_syslog::rules
#
# @api private
class security_baseline_syslog::rules (
  Boolean $enforce   = true,
  String $message    = '',
  String $log_level  = 'info',
  Integer $level     = 1,
  Boolean $scored    = true,
) {
  $classes = [
    'security_baseline_syslog::rules::rsyslog::service',
    'security_baseline_syslog::rules::rsyslog::filepermissions',
    'security_baseline_syslog::rules::rsyslog::remotesyslog',
    'security_baseline_syslog::rules::rsyslog::remoteloghost',
    'security_baseline_syslog::rules::syslogng::service',
    'security_baseline_syslog::rules::syslogng::filepermissions',
    'security_baseline_syslog::rules::syslogng::remotesyslog',
    'security_baseline_syslog::rules::syslogng::remoteloghost',
    'security_baseline_syslog::rules::syslog',
    'security_baseline_syslog::rules::logfiles',
  ]

  $classes.each |$class| {
    class { $class:
      enforce   => $enforce,
      message   => $message,
      log_level => $log_level,
      level     => $level,
      scored    => $scored,
    }
  }
}
