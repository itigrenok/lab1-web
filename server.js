const express = require('express')
const app = express()
const fs = require('fs');
const crypto = require('crypto')
const jwt = require("jsonwebtoken");

const secret = "SECRET"
const user = {
    login: "admin",
    password: "d033e22ae348aeb5660fc2140aec35850c4da997",
    credential: { id: 1, role: "admin" }
}

const authorization = (req, res, next) => {
    var access_token = req.headers.authorization

    if (!access_token) {
        return res.status(403).sendFile(__dirname + '/views/403.html');
    }

    try {
        const data = jwt.verify(access_token, secret);
        req.userId = data.id;
        req.userRole = data.role;
        return next();
    } catch {
        return res.sendStatus(403);
    }
};

app.use(express.json());
app.listen(8990)

app.post("/v1/authorization", function (req, res) {
        let hex = crypto.createHash('sha1').update(req.body.password).digest('hex')

        if (!(req.body.login === user.login && hex === user.password)) {
            return res.status(401).sendFile(__dirname + '/views/401.html')
        }

        return res.send({"access_token": jwt.sign(user.credential, secret)})
});

app.get("/v1/cars", authorization, (req, res) => {
    res.send(JSON.stringify(fs.readFileSync(__dirname + "/table.json", 'utf8')))
});