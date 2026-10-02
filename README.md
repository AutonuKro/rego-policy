
````shell
#to run opa as server
opa run --server

#load data
curl -X PUT http://localhost:8181/v1/data/fin --data-binary @data.json

#check the data
curl http://localhost:8181/v1/data/fin | jq

#load policy
curl -X PUT http://localhost:8181/v1/policies/auth/fin --data-binary @abc.rego
````
