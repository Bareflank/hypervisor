#!/bin/bash

set -e

sudo ./run.sh start vmm.modules
sudo ./run.sh stop
sudo ./run.sh dump
