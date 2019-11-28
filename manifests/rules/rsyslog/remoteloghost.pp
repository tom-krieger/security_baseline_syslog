# @summary 
#    Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)
#
# By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load 
# the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen 
# on the specified TCP port.
# 
# Rationale:
# The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts within 
# the specified domain and that those systems that are not designed to be log hosts do not accept any remote rsyslog messages. 
# This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete 
# syslog data in a central location.
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
#   class { 'security_baseline_syslog::rules::rsyslog::remoteloghost':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_syslog::rules::rsyslog::remoteloghost (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  $logentry_default = {
    rulenr    => '4.2.1.5',
    rule      => 'rsyslog-remoteloghost',
    desc      => 'Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)',
    level     => $level,
    scored    => $scored,
  }

  if(
    ($::security_baseline_syslog::syslog == 'rsyslog') and
    $::security_baseline_syslog::is_loghost
  ) {

    if($facts['security_baseline_syslog']['rsyslog']['loghost']) {
      echo { 'rsyslog-remoteloghost':
        message  => 'Host is configured to accept remote log messages.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => 'ok',
        msg       => 'Host is configured to accept remote log messages.',
        rulestate => 'not scored',
      }
    } else {
      echo { 'rsyslog-remoteloghost':
        message  => 'Host is configured to not accept remote log messages.',
        loglevel => $log_level,
        withpath => false,
      }
      $logentry_data = {
        level     => 'ok',
        msg       => 'Host is configured to not accept remote log messages.',
        rulestate => 'not scored',
      }
    }

    $logentry = $logentry_default + $logentry_data
    ::security_baseline::logging { 'rsyslog-remoteloghost':
      * => $logentry,
    }
  }
}
