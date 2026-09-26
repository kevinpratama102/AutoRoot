title 'CVE-2016-5195'

# Run the Red Hat check script to see if we are vulnerable
control 'CVE-2016-5195' do
  impact 1.0
  title 'CVE-2016-5195 aka Dirty COW'
  desc 'A race condition was found in the way the Linux kernel\'s memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and thus increase their privileges on the system.

This could be abused by an attacker to modify existing setuid files with instructions to elevate privileges. An exploit using this technique has been found in the wild. This flaw affects most modern Linux distributions.'

  describe dirtyc0w do
    it { should_not be_vulnerable }
  end
end
