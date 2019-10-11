require 'spec_helper'

describe 'security_baseline_syslog' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      os_facts.merge(
        'security_baseline_syslog' => {
          'rsyslog' => {
            'filepermissions' => '0640',
            'loghost' => true,
            'package' => true,
            'remotesyslog' => 'none',
            'service' => 'enabled',
          },
          'syslog-ng' => {
            'filepermissions' => 'none',
            'loghost' => false,
            'package' => false,
            'remotesyslog' => 'none',
            'service' => 'disabled',
          },
          'syslog_installed' => true,
        },
      )

      it { is_expected.to compile }
    end
  end
end
