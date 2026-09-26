class Dirtyc0w < Inspec.resource(1)
  name 'dirtyc0w'

  desc "
    Test for CVE-2016-5195 aka Dirty COW
  "

  example "
    describe dirtyc0w do
      it { should_not be_vulnerable }
    end
  "

  def initialize(cleanup = true)
    return skip_resource "This resource only supports Linux OSes" unless inspec.os.linux? # Only affects linux os
    @cleanup = cleanup
    @path = '/tmp/dirtyc0w'
    @test_file = "#{@path}/foo"
    @script_url = 'https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c'
    @source = "#{@path}/dirtyc0w.c"
    @execuable = "#{@path}/dirtyc0w"
    @test_str = 'This is a TEST'

    inspec.backend.run_command("mkdir -p #{@path}")

    res = inspec.backend.run_command("wget #{@script_url} -O #{@source}")
    return skip_resource "Can't download script from #{@script_url} to #{@source}: #{res.stdout} #{res.stderr}" unless res.exit_status.eql?(0)

    res = inspec.backend.run_command("gcc -pthread #{@source} -o #{@execuable}")
    return skip_resource "Script compile error: #{res.stdout} #{res.stderr}" unless res.exit_status.eql?(0)

    res = inspec.backend.run_command("sudo sh -c 'echo #{@test_str} > #{@test_file} && chmod 0404 #{@test_file}'")
    return skip_resource "File create failed: #{res.stdout} #{res.stderr}" unless res.exit_status.eql?(0)

    res = inspec.backend.run_command("#{@execuable} #{@test_file} m00000000000000000")
    return skip_resource "#{@execuable} command failed: #{res.stdout} #{res.stderr}" unless res.exit_status.eql?(0)
  end

  def vulnerable?
    retval = !inspec.file(@test_file).content.chomp.eql?(@test_str)
    inspec.backend.run_command("rm -f #{@test_file}") if @cleanup # Cleanup file
    return retval
  end
end
