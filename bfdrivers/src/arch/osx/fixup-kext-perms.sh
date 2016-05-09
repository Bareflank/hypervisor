#!/bin/bash

sudo chown -R root $HOME/Library/Developer/Xcode/DerivedData/bareflank-*/Build/Products/Debug/bareflank.kext
sudo chgrp -R wheel $HOME/Library/Developer/Xcode/DerivedData/bareflank-*/Build/Products/Debug/bareflank.kext

