# awsfed
AWS Federated Access Login Gateway

awsfed is a portal server for Amazon Web Services that lets you map multiple users in multiple groups different AWS roles,
giving both console and API access via federated login. This keeps all user management in one place - the only thing you do
in AWS is add one access account per role a user will adopt.

This code is a sanitized version of the code I have run in production for my employer, and is tailored to their needs and
situation - some of the choices made were appropriate to them, but not the best for the world at large. It is not perfect;
were I to rewrite it from scratch, there are a number of changes I would make. 

As presented here, awsfed is a webserver written in python that expects to run on an AWS ec2 instance in a docker container
behind an ALB providing HTTPS termination. Modifying it for other environments should be straightforward. I'd recommend you
run it isolated, preferably in it's own account in your organization. By definition, it will have high-level access to your
aws accounts - it is best to protect that at your highest security level available. 

