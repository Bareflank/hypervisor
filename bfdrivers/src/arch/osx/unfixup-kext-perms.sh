#!/bin/bash

sudo chown -R $USER ~/Library/Developer/Xcode/DerivedData/bareflank-*/Build/Products/Debug/bareflank.kext
sudo chgrp -R staff ~/Library/Developer/Xcode/DerivedData/bareflank-*/Build/Products/Debug/bareflank.kext

