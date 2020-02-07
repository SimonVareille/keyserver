#:/bin/bash

systemctl start mongod
systemctl status mongod

mongo
use keyserver-test
db.createUser({ user:"keyserver-user", pwd:"trfepCpjhVrqgpXFWsEF", roles:[{ role:"readWrite", db:"keyserver-test" }] })

export NODE_ENV=development

npm start
