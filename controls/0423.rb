title 'Access Control: Identification, Authentication and Authorisation'

if os[:family] == 'redhat'
  control 'asd-ism-2016-0423-1' do
    title 'Passphrase management practices'
    desc  'ensure that passphrases are changed at least every 90 days: /etc/login.defs'
    impact 1.0

    tag control: 0423
    tag revision: 2
    tag applicability: ['UD', 'P', 'C', 'S', 'TS']
    tag complianc: 'must'
    tag authority: 'AA'

    describe login_defs do
      its('PASS_MAX_DAYS') { should cmp <= 90 }
    end
  end

  control 'asd-ism-2016-0423-2' do
    title 'Passphrase management practices'
    desc  'prevent passphrases from being changed by the user more than once a day: /etc/login.defs'
    impact 1.0

    tag control: 0423
    tag revision: 2
    tag applicability: ['UD', 'P', 'C', 'S', 'TS']
    tag complianc: 'must'
    tag authority: 'AA'

    describe login_defs do
      its('PASS_MIN_DAYS') { should cmp >= 1 }
    end
  end

  control 'asd-ism-2016-0423-3' do
    title 'Passphrase management practices'
    desc  'prevent passphrases from being reused within eight passphrase changes: /etc/pam.d/system-auth'
    impact 1.0

    tag control: 0423
    tag revision: 2
    tag applicability: ['UD', 'P', 'C', 'S', 'TS']
    tag complianc: 'must'
    tag authority: 'AA'

    describe file('/etc/pam.d/system-auth') do
      its('content') { should match /^(?=.*?\bpassword\b)(?=.*?\bsufficient\b)(?=.*?\bremember=13\b).*$/ }
    end
  end
end