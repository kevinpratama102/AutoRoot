if node['platform_family'] == 'rhel'
  if node['platform'] == 'centos'
    include_recipe 'yum'

    cookbook_file '/etc/yum.repos.d/CentOS-Base.repo' do
      source 'CentOS-Base.repo'
    end
  else
    #Centos repo breaks RHEL
    file '/etc/yum.repos.d/CentOS-Base.repo' do
      action :delete
    end
  end

  yum_repository 'rpmforge' do
    action :delete
  end
  
end

package 'bash' do
  action :upgrade
  only_if { node['languages']['bash']['shellshock_vulnerable'] }
end
