#!/bin/sh

/usr/share/privilege-control/db/updater.sh

/usr/bin/api_feature_loader --verbose --dir=/usr/share/privilege-control/
