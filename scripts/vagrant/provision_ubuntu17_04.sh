#!/bin/bash

VAGRANT_BUILD_DIR="/vagrant/build_ubuntu17_04"
VAGRANT_HOME_DIR="/home/ubuntu"

sudo apt-get update
sudo apt-get install -y git build-essential linux-headers-$(uname -r) clang \
    binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu nasm cmake

# Setup Bareflank environment variables
echo "source /vagrant/env.sh $VAGRANT_BUILD_DIR" >> $VAGRANT_HOME_DIR/.profile

# Have 'vagrant ssh' bring you straight to the configured build directory
echo "cd $VAGRANT_BUILD_DIR" >> $VAGRANT_HOME_DIR/.profile
