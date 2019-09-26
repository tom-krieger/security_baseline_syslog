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
    val = Facter::Core::Execution.exec('grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf').split(%r{\s+})[1].strip
    rsyslog['filepermissions'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec('grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    rsyslog['remotesyslog'] = check_value_string(val, 'none')
    security_baseline_syslog['rsyslog'] = rsyslog

    syslog_ng = {}
    syslog_ng['service'] = check_service_is_enabled('syslog-ng')
    syslog_ng['package'] = check_package_installed('syslog-ng')
    security_baseline_syslog['syslog-ng'] = syslog_ng

    security_baseline_syslog['syslog_installed'] = security_baseline_syslog['rsyslog']['package'] || security_baseline_syslog['syslog-ng']['package']

    security_baseline_syslog
  end
end
