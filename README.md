1. We will keep policy in its directory. for example for client OMNIFI if it has client code "OMN" then the policy file
   and data.json will also go into /policies/fin and /data/fin respectively


````shell
#to run opa as server
opa run --server

#load data
curl -X PUT http://localhost:8181/v1/data/fin --data-binary @data.json

#check the data
curl http://localhost:8181/v1/data/fin | jq

#load policy
curl -X PUT http://localhost:8181/v1/policies/auth/fin --data-binary @policy.rego
````