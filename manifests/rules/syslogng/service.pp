# @summary 
#    Ensure syslog-ng Service is enabled (Scored)
#
# Once the syslog-ng package is installed it needs to be activated.
#
# Rationale:
# If the syslog-ng service is not activated the system may default to the syslogd service or lack logging instead.
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
#   class { 'security_baseline_syslog::rules::syslogng::service':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::syslogng::service (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  $logentry_default = {
    rulenr    => '4.2.2.1',
    rule      => 'syslog-ng-service',
    desc      => 'Ensure syslog-ng Service is enabled (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($::security_baseline_syslog::syslog == 'syslog-ng') {

    if($facts['security_baseline_syslog']['syslog-ng']['services'] == false) {
      echo { 'syslog-ng-service':
        message  => 'Syslog-ng service is not enabled.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Syslog-ng service is not enabled.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Syslog-ng service is enabled.',
        rulestate => 'compliant',
      }
    }

    if($enforce) {
      if(!defined(Service['syslog-ng'])) {
        service { 'syslog-ng':
          ensure => running,
          enable => true,
        }
      }
    }

    $logentry = $logentry_default + $logentry_data
    ::security_baseline::logging { 'syslog-ng-service':
      * => $logentry,
    }
  }
}
