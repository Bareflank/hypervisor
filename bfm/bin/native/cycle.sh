#!/bin/bash

set -e

sudo ./run.sh start vmm.modules
@echo "Bareflank has successfully started"

sudo ./run.sh stop
@echo "Bareflank has successfully stopped"
