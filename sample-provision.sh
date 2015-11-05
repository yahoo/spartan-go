#!/bin/bash
SPARTAN_USERID=admin@example.com
SPARTAN_URL=https://spartan.example.com/v1/

# create usergroup 'test-usergroup1'
spartan -u $SPARTAN_USERID -s $SPARTAN_URL create-usergroup test-usergroup1

# create app 'test-app1' that is owned by 'test-usergroup1'
spartan -u $SPARTAN_USERID -s $SPARTAN_URL create-app test-app1 test-usergroup1

# create role 'SuperRole' owned by 'test-usergroup1', 
# with role handle(service endpoint) being https://testserver.example.com
# and role type being 'SERVICE'
spartan -u $SPARTAN_USERID -s $SPARTAN_URL create-role SuperRole test-usergroup1 https://testserver.example.com SERVICE

# associate role 'SuperRole' to app 'test-app1'
spartan -u $SPARTAN_USERID -s $SPARTAN_URL add-to-role SuperRole test-app1

# At this point, we can add identities to test-app1.
# These containers/hosts(identity represents a container/host) would be 
# able to authorize itself to https://testserver.example.com service
# via 'SuperRole' role
