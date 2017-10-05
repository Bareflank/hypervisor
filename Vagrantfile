# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
    config.vm.provider "virtualbox" do |vb|
        vb.memory = "2048"
        vb.cpus = 2
    end

    config.vm.define "ubuntu17_04", primary: true do |ubuntu17_04|
        ubuntu17_04.vm.box = "ubuntu/zesty64"
        ubuntu17_04.vm.provision "shell",
            path: "scripts/vagrant/provision_ubuntu17_04.sh"
    end
end
