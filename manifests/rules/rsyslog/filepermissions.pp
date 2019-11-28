# @summary 
#    Ensure rsyslog default file permissions configured (Scored)
#
# rsyslog will create logfiles that do not already exist on the system. This setting controls what permissions will be 
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
#   class { 'security_baseline_syslog::rules::rsyslog::filepermissions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::rsyslog::filepermissions (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  $logentry_default = {
    rulenr    => '4.2.1.3',
    rule      => 'rsyslog-filepermissions',
    desc      => 'Ensure rsyslog default file permissions configured (Scored)',
  }

  if($::security_baseline_syslog::syslog == 'rsyslog') {

    if($facts['security_baseline_syslog']['rsyslog']['filepermissions'] != '0640') {
      echo { 'rsyslog-filepermissions':
        message  => 'Rsyslog creates files with wrong permissions.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Rsyslog creates files with wrong permissions.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Rsyslog creates files with correct permissions.',
        rulestate => 'compliant',
      }
    }

    if($enforce) {
      file_line { 'rsyslog-filepermissions':
        ensure => present,
        path   => '/etc/rsyslog.conf',
        line   => '$FileCreateMode 0640',
        match  => '^\$FileCreateMode.*',
        notify => Exec['reload-rsyslog'],
      }

      if(!defined(File['/etc/rsyslog.d/'])) {
        file { '/etc/rsyslog.d/':
          ensure  => directory,
          recurse => true,
          mode    => '0640',
        }
      }
    }

    $logentry = $logentry_default + $logentry_data
    ::security_baseline::logging { 'rsyslog-filepermissions':
      * => $logentry,
    }
  }
}
