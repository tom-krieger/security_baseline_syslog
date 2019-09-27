require 'facter/helpers/check_service_enabled'
require 'facter/helpers/check_package_installed'
require 'facter/helpers/check_value_string'

# frozen_string_literal: true

# security_baseline.rb
# collect facts about the security baseline for syslog

Facter.add(:security_baseline_syslog) do
  confine osfamily: ['RedHat', 'Suse']
  setcode do
    # distid = Facter.value(:lsbdistid)
    security_baseline_syslog = {}

    rsyslog = {}
    rsyslog['service'] = check_service_is_enabled('rsyslog')
    rsyslog['package'] = check_package_installed('rsyslog')
    val = Facter::Core::Execution.exec('grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null').split(%r{\s+})[1].strip
    rsyslog['filepermissions'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec('grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null')
    rsyslog['remotesyslog'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec("grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null")
    mod = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec("grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null")
    port = check_value_string(val, 'none')
    rsyslog['loghost'] = if (mod != 'none') && (port != 'none')
                           true
                         else
                           false
                         end
    security_baseline_syslog['rsyslog'] = rsyslog

    syslog_ng = {}
    syslog_ng['service'] = check_service_is_enabled('syslog-ng')
    syslog_ng['package'] = check_package_installed('syslog-ng')
    val = Facter::Core::Execution.exec('grep ^options /etc/syslog-ng/syslog-ng.conf 2>/dev/null').match(%r{perm\((\d+)\)}).strip
    syslog_ng['filepermissions'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec('grep destination logserver /etc/syslog-ng/syslog-ng.conf 2>/sdev/null').match(%r{tcp\((.*)\)}).strip
    logserv = check_value_string(val, 'none')
    val = Facter::Code::Execution.exec('grep "log.*{.*source(src);.*destination(logserver);.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
    logsend = check_value_string(val, 'none')
    syslog_ng['remotesyslog'] = if (logserv == 'none') || (logsend == 'none')
                                  'none'
                                else
                                  logserv
                                end
    val = Facter::Core::Execution.exec('grep "source net{.*tcp();.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
    logsrc = check_value_string(val, 'none')
    val = Facter::Code::Execution.exec('grep "destination remote.*{.*file(\"/var/log/remote/\${FULLHOST}-log\");.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
    logdest = check_value_string(val, 'none')
    val = Facter::Code::Execution.exec('grep "log {.*source(net);.*destination(remote);.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
    log = check_value_string(val, 'none')
    syslog_ng['loghost'] = if (logsrc != 'none') && (logdest != 'none') && (log != 'none')
                             true
                           else
                             false
                           end
    security_baseline_syslog['syslog-ng'] = syslog_ng

    security_baseline_syslog['syslog_installed'] = security_baseline_syslog['rsyslog']['package'] || security_baseline_syslog['syslog-ng']['package']

    security_baseline_syslog
  end
end
