# @summary 
#    Ensure syslog-ng is configured to send logs to a remote log host (Scored)
#
# The syslog-ng utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to 
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
# @example
#   class { 'security_baseline_syslog::rules::syslogng::remotesyslog':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::syslogng::remotesyslog (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  $logentry_default = {
    rulenr    => '4.2.2.4',
    rule      => 'syslog-ng-remotesyslog',
    desc      => 'Ensure syslog-ng is configured to send logs to a remote log host (Scored)',
  }

  if($::security_baseline_syslog::syslog == 'syslog-ng') {

    if($facts['security_baseline_syslog']['syslog-ng']['remotesyslog'] == 'none') {
      echo { 'syslog-ng-remotesyslog':
        message  => 'syslog-ng is not configured to send logs to a remote log host.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'syslog-ng is not configured to send logs to a remote log host.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'syslog-ng is configured to send logs to a remote log host.',
        rulestate => 'compliant',
      }
    }

    if($enforce) {
      if($::security_baseline_syslog::remote_syslog_host != '') {
        file_line { 'syslog-ng.conf logging_host':
      ensure => present,
      path   => '/etc/syslog-ng/syslog-ng.conf',
      line   => "destination logserver { tcp(\"${::security_baseline_syslog::remote_syslog_host}\" port(514)); }; log { source(src); destination(logserver); };",
      match  => '^destination logserver',
      notify => Exec['reload-syslog-ng'],
    }
      }
    }

    $logentry = $logentry_default + $logentry_data
    ::security_baseline::logging { 'syslog-ng-remotesyslog':
      * => $logentry,
    }
  }
}
