# @summary 
#    Ensure syslog-ng default file permissions configured (Scored)
#
# syslog-ng will create logfiles that do not already exist on the system. This setting controls what permissions will be 
# applied to these newly created files.
#
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived 
# and protected.
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
#   class { 'security_baseline_syslog::rules::syslog-ng::filepermissions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::syslogng::filepermissions (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  $logentry_default = {
    rulenr    => '4.2.2.3',
    rule      => 'syslog-ng-filepermissions',
    desc      => 'Ensure syslog-ng default file permissions configured (Scored)',
  }

  if($::security_baseline_syslog::syslog == 'syslog-ng') {

    if($facts['security_baseline_syslog']['syslog-ng']['filepermissions'] != '0640') {
      echo { 'syslog-ng-filepermissions':
        message  => 'Syslog-ng creates files with wrong permissions.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Syslog-ng creates files with wrong permissions.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Syslog-ng creates files with correct permissions.',
        rulestate => 'compliant',
      }
    }

    if($enforce) {
      file_line { 'syslog-ng.conf permissions':
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => 'options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };',
        notify => Exec['reload-syslog-ng'],
      }
    }

    $logentry = $logentry_default + $logentry_data
    ::security_baseline::logging { 'syslog-ng-filepermissions':
      * => $logentry,
    }
  }
}
