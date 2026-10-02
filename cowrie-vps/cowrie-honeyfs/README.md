# Bait files go here (NOT committed to git)

Copy the contents of the `honeyfs/` folder from the fake-files bundle into
this directory, keeping the same paths (`root/`, `home/dave/`, `etc/`,
`opt/`, `var/`). Every file listed in `../cowrie/honeyfs-manifest.txt` must
be present or `docker compose build` stops with a list of what's missing.

Everything in here except this README is gitignored. The bait includes
realistic-looking SSH keys and API-key-shaped strings; keeping them out of
the repo avoids GitHub push-protection blocks and secret-scanner alerts.

Anything else you drop in here is added to the fake filesystem too
(owner and permissions are set automatically - see
`../cowrie/build_fs_pickle.py`). If you add a file you want the build to
insist on, add its path to the manifest.
