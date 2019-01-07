This is the actual AWS Federation App.

It runs in a docker container, or you could run it in a normal virtualenv.

The key thing to be aware of is that it is designed to NOT keep the AWS credentials
resident on disk anywhere - you upload them manually to the server post-launch, and
they are stored only in RAM. They never hit the disk or are logged, which means
an attacker trying to snapshot things in AWS won't get a copy of those credentials.
Note that other secrets, in particular user credentials, are not treated the same
way, and are stored in a SQLite database on the local disk.

The upshot is that if you reboot or kill/restart the server, you will need to re-upload
the AWS credentials and groups. Such is the price of security.