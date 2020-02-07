#:/bin/bash

systemctl start mongod
systemctl status mongod

(echo 'use keyserver-test';echo 'db.createUser({ user:"keyserver-user", pwd:"trfepCpjhVrqgpXFWsEF", roles:[{ role:"readWrite",db:"keyserver-test" }] })') | mongo


export NODE_ENV=development

npm start
