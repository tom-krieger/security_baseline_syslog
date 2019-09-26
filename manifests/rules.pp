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
) {
  $classes = [
    'security_baseline_syslog::rules::rsyslog_service',
  ]

  $classes.each |$class| {
    class { $class:
      enforce   => $enforce,
      message   => $message,
      log_level => $log_level,
    }
  }
}
