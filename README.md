# nba
A Netbox Agent for *nix hosts using the pynetbox library. Run independently on the cli or install as a service on your host and point it at a netbox deployment. A configurable set of host data will automatically be added to netbox and kept up to date periodically.

TODO:
* Set up home test environment
    * netbox docker container
* Support configuration via config file (and environment variables?)
* Better logging and debugging (syslog or custom)
* Systemd Service
* Use pynetbox instead of custom functions
* Redesign and break up into modules for getting different system info
    * unit and integration tests
    * get system info via more portable methods and cli commands where possible
* Make distro and system agnostic. (should work on FreeBSD too)
* CI/TD via travis-CI to test, build apt package, and build/deploy docker image running in digital ocean