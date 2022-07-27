## What's this?

This is an Ansible collection to sign / verify playbooks and roles in a SCM repository.
You can sign your own playbooks and roles, and also verify them by calling this module in a playbook.
This is useful for checking playbook file integrity before actual PlaybookRun.

## Installation
```
# make a collection package file
$ ansible-galaxy collection build .

# install it as a collection
$ ansible-galaxy collection install ./playbook-integrity-1.0.0.tar.gz
```

## Usage

```
# sign with GPG default private key
$ ansible-playbook playbooks/sign-playbook.yml -e repo=<PATH/TO/REPO>

$ verify with GPG default public key
$ ansible-playbook playbooks/verify-playbook.yml -e repo=<PATH/TO/REPO>
```

Also you can specify the keyring file such as `pubring.gpg` as below

```
# sign with the specific private key
$ ansible-playbook playbooks/sign-playbook.yml -e repo=<PATH/TO/REPO> -e key=<PATH/TO/PRIVATE_KEY>

$ verify with the specific public key
$ ansible-playbook playbooks/verify-playbook.yml -e repo=<PATH/TO/REPO> -e key=<PATH/TO/PUBLIC_KEY>
```