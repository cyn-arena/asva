

### Database

By now (in 2026) nodegoat dependency libraries are way outdated. Ensure Mongo DB Server is v3.0.15 to v3.2.22, the latest compatible version with node mongo DB driver v2.1.18.

If, inexplicably (and we don't really want to spend time troubleshooting, that the DB is not auto- and pre-populated with default user accounts, create them manually by referring to the DAO schema and data insert function in db-reset.js.

Don't be shocked to see cleartext passwords, remember this is a damn vulnerable app.
```
# /artifacts/db-reset.js

...
{
    "_id": 1,
    "userName": "admin",
    "firstName": "Node Goat",
    "lastName": "Admin",
    "password": "Admin_123",
    "isAdmin": true
}
...

```

And do the same for "Allocations", that is create the data manually if it's not auto- and pre- populated.  Nodegoat mimicks a financial planning app where registered users can decide portfolio allocations.  Refer to the schema as follows in allocations-dao.js.
```
# /app/data/allocations-dao.js

...
const allocations = {
    userId: userId,
    stocks: stocks,
    funds: funds,
    bonds: bonds
};
...
```

### App Configuration

Update App Port and DB server connection URL
```
# config/env/all.js

const port = process.env.PORT || 4043;
let db = process.env.MONGODB_URI || "mongodb://mongo30:27017/nodegoat";
```

### Dockerfile

Denote the 2 build stages - Dependency and Runtime.

In the Runtime stage, add the following environment variables to override defaults.
```
# Dockerfile

ENV PORT=4043
ENV MONGODB_URI=mongodb://mongo30:27017/nodegoat
```

Un-comment the line after "# In production environment .." so that the Container will run as a non-root user.
The K8s pods will provide addtional hardening.

### Test Automation

Nodegoat uses ZAProxy and Cypress for automating App Security Testing and E2E Functional Testing respectively.  We will explore other browser automation alternatives on a narrower use case to suit this project's scope, becuase arguably both ZAP and Cypress are dated tools.  

#### Limitations to Server Side Injection Vulnerability Testing

The server is run on a K8s cluster and will restart or failover to other nodes.  The injection exploit(s) which is meant to be a DOS attack will only cause an immediate but temporary shutdown of the service instance. 