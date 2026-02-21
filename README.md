# hass_ecovacs-bumper
Home Assistant add-on for Ecovacs local backend.
This is a personal project. The repository has been created for personal use and for future reference only.

This is a Home Assistant add-on that installs a local Bumper server, allowing you to manage Ecovacs vacuum cleaners locally.
For more information, please refer to the original project repository created by the author:
https://github.com/bmartin5692/bumper

To install it, simply download the ecovacs_bumper folder as-is and upload it to Home Assistant inside the /addons directory.
At this point, the add-on will be available for installation.

Bumper requires TLS certificates and a directory to store its database, therefore the user must create the following directories:

/addon_configs/ecovacs_bumper/certs
/addon_configs/ecovacs_bumper/data

The first directory must contain the generated certificates, while the second one is used to store the local database.
Here how create the certificates:

https://bumper.readthedocs.io/en/latest/Create_Certs/
