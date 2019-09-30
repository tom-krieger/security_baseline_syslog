# @summary 
#    Ensure permissions on all logfiles are configured (Scored)
#
# Log files stored in /var/log/ contain logged information from many services on the 
# system, or on log hosts others as well.
#
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure that sensitive 
# data is archived and protected.
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
#   class { 'security_baseline_syslog::rules::rsyslog::filepermissions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::logfiles (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
) {
  $logentry_default = {
    rulenr    => '4.2.4',
    rule      => 'syslog-logfiles',
    desc      => 'Ensure permissions on all logfiles are configured (Scored)',
  }

  if($facts['security_baseline_syslog']['syslog_installed']) {

      if($enforce) {
        file { '/var/log':
          ensure  => directory,
          recurse => true,
          mode    => 'g-wx,o-rwx',  #lint:ignore:no_symbolic_file_modes
          ignore  => 'puppetlabs',
        }
      }
  }
}
