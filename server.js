/*Node Modules*/
var express = require('express');
//var moment = require('moment');

var http = require('http'),
    fs = require('fs');

var MongoClient = require('mongodb').MongoClient;
var ObjectId = require('mongodb').ObjectId;
var assert = require('assert');
var async = require('async');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var passwordHash = require('password-hash');
var session = require('express-session');
querystring = require('querystring');
var mongourl = 'mongodb://admin:syscraft@ds153123.mlab.com:53123/appointmentscheduler';

//if change here also change it to device history and devicedata controller
var loginexpiredmessage = 'Login Expired. Please reload and login again.';

//var mongourl = 'mongodb://localhost:27017/lotusbeacon';
MongoClient.connect(mongourl, function(err, db) {
    assert.equal(null, err);
    console.log("Connected correctly to server.");
    db.close();
});

// Send index.html to all requests
var server = http.createServer(function(req, res) {
    res.writeHead(200, {
        'Content-Type': 'text/html'
    });
    res.end(index);
});

var app = express();

//app.use('/', express.static(__dirname + '/angular/'));
app.use(session({
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    },
    secret: '2C44-4D44-WppQ38S',
    resave: true,
    saveUninitialized: true
}));

app.use(bodyParser.json()); // parse application/json
app.use(bodyParser.json({
    type: 'application/vnd.api+json'
})); // parse application/vnd.api+json as json
app.use(bodyParser.urlencoded({
    extended: true
})); // parse application/x-www-form-urlencoded
app.use(methodOverride('X-HTTP-Method-Override')); // override with the X-HTTP-Method-Override header in the request. simulate DELETE/PUT
app.use(express.static(__dirname + '/public')); // set the static files location /public/img will be /img for users
app.all("/*", function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With");
    res.header("Access-Control-Allow-Methods", "GET, PUT, POST");

    return next();
});

var server = app.listen(process.env.PORT || 3000, function() {
    console.log("App started with Mongodb");
});

function parse_JSON(responsecontent) {
    try {
        return JSON.parse(responsecontent);
    } catch (ex) {
        return null;
    }
}


app.post('/users/signin', function(req, res) {
    mobileNo = req.body.mobileNo;
    password = req.body.password;

    var resObj = {};
    if (!(password && mobileNo)) {
        resObj.IsSuccess = false;
        resObj.message = "Please enter appropriate informations";
        res.send(resObj);
        return;
    }


    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }
        assert.equal(null, err);

        var collection = db.collection('users');

        collection.find({
            "mobileNo": mobileNo,
        }).toArray(function(err, users) {
            if (users.length <= 0) {
                resObj.IsSuccess = false;
                resObj.message = "Mobile Number not registered with us.";
                res.send(resObj);
                return 0;
            }

            var isPasswordMatch = passwordHash.verify(req.body.password, users[0].password);
            if (!isPasswordMatch) {
                resObj.IsSuccess = false;
                resObj.message = "Invalid Password.";
                res.send(resObj);
                return 0;
            }

            users[0].Password = "";
            req.session.loggedInUser = users[0];

            resObj.IsSuccess = true;
            resObj.message = "Logged In Successfully.";
            resObj.user = users[0];
            res.send(resObj);
            return 0;
        });
    });
});

app.post('/users/signout', function(req, res) {
    var resObj = {};
    console.log("Logging out user.");
    req.session.destroy(function() {
        //res.redirect('/');
        resObj.message = "Logged out successfully";
        resObj.IsSuccess = true;
        res.send(resObj);
    });
});

app.post('/users/checkSession', function(req, res) {
    var resObj = {};
    if (req.session.loggedInUser) {
        resObj.user = req.session.loggedInUser;
        resObj.IsSuccess = true;
        res.send(resObj);
    } else {
        resObj.IsSuccess = false;
        resObj.message = "Not logged in.";
        res.send(resObj);
    }
});

app.post('/users/register', function(req, res) {
    email = req.body.email;
    firstName = req.body.firstName;
    lastName = req.body.lastName;
    mobileNo = req.body.mobileNo;
    password = req.body.password;
    email = email.toLowerCase();

    var resObj = {};

    if (!(password && firstName && email && mobileNo)) {
        resObj.IsSuccess = false;
        resObj.message = "Please enter appropriate informations";
        res.send(resObj);
        return;
    }

    var hashedPassword = passwordHash.generate(password);

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }

        assert.equal(null, err);

        var collection = db.collection('users');

        async.waterfall([
            function(callback) {
                collection.find({
                    "mobileNo": mobileNo,
                }).toArray(function(err, users) {
                    if (users.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Mobile already registered with application.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(approved, callback) {
                collection.insert({
                    'email': email,
                    'firstName': firstName,
                    'lastName': lastName,
                    'password': hashedPassword,
                    'mobileNo': mobileNo,
                    'UserType': 1
                });

                callback(null, 'registered');
            },
            function(response, callback) {
                db.close();
                resObj.IsSuccess = true;
                resObj.message = "Registered Successfully";
                res.send(resObj);
                return 0;
            }
        ]);
    });
});

app.post('users/updateprofile', function(req, res) {
    /*    ResetPassword = req.body.ResetPassword;
        Password = req.body.Password;
        Email = req.body.Email;
        Name = req.body.Name;
        Designation = req.body.Designation;
        MobileNo = req.body.MobileNo;
        AssignedStore = req.body.AssignedStore;
        UserObjectID = req.body.UserObjectID;

        UserID = UserID.toLowerCase();
        Email = Email.toLowerCase();
        Name = Name.toLowerCase();
        Designation = Designation.toLowerCase();
        MobileNo = MobileNo.toLowerCase();

        var resObj = {};
        if (!req.session.loggedInUser) {
            resObj.IsSuccess = false;
            resObj.message = loginexpiredmessage;
            resObj.data = '';
            res.send(resObj);
            return;
        }

        if (!(UserID && Name && Email && UserObjectID)) {
            resObj.IsSuccess = false;
            resObj.message = "Please enter appropriate informations";
            res.send(resObj);
            return;
        }


        MongoClient.connect(mongourl, function(err, db) {
            if (err) {
                return console.dir(err);
            }

            assert.equal(null, err);

            var collection = db.collection('users');

            async.waterfall([
                function(callback) {
                    collection.find({
                        '_id': { $ne: ObjectId(UserObjectID) }
                    }).toArray(function(err, users) {
                        var cnt = users.length;
                        for (var u in users) {
                            if (users[u].UserID == UserID) {
                                resObj.IsSuccess = false;
                                resObj.message = "This ID Already Exists in the Portal";
                                res.send(resObj);
                                return 0;
                            } else if (users[u].Email == Email) {
                                resObj.IsSuccess = false;
                                resObj.message = "Email ID already exists";
                                res.send(resObj);
                                return 0;
                            } else if (users[u].MobileNo == MobileNo) {
                                resObj.IsSuccess = false;
                                resObj.message = "Mobile No already exists";
                                res.send(resObj);
                                return 0;
                            }
                        }
                        callback(null, users);
                    });
                },
                function(userdata, callback) {
                    var hashedPassword = passwordHash.generate(Password);
                    callback(null, hashedPassword);
                },
                function(hashedpassword, callback) {
                    if (ResetPassword) {
                        collection.update({
                            '_id': ObjectId(UserObjectID)
                        }, {
                            '$set': {
                                'UserID': UserID,
                                'Email': Email,
                                'Name': Name,
                                'Designation': Designation,
                                'Password': hashedpassword,
                                'MobileNo': MobileNo,
                                'AssignedStore': ObjectId(AssignedStore),
                            }
                        });

                    } else {
                        collection.update({
                            '_id': ObjectId(UserObjectID)
                        }, {
                            '$set': {
                                'UserID': UserID,
                                'Email': Email,
                                'Name': Name,
                                'Designation': Designation,
                                'MobileNo': MobileNo,
                                'AssignedStore': ObjectId(AssignedStore),
                            }
                        });
                    }

                    callback(null, 'updated');
                },
                function(response, callback) {
                    db.close();
                    resObj.IsSuccess = true;
                    resObj.message = "Manager has been Updated Successfully";
                    res.send(resObj);
                    callback(null, response);
                }
            ]);
        });*/
});

app.post('users/updatepassword', function(req, res) {
    oldPassword = req.body.oldPassword;
    password = req.body.password;
    mobileNo = req.body.mobileNo;

    var hashedPassword = passwordHash.generate(password);

    var resObj = {};
    if (!mobileNo) {
        resObj.IsSuccess = false;
        resObj.message = 'No user selected';
        resObj.data = '';
        res.send(resObj);
        return;
    }

    if (!(mobileNo && password && oldPassword)) {
        resObj.IsSuccess = false;
        resObj.message = "Please enter appropriate informations";
        res.send(resObj);
        return;
    }

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }
        assert.equal(null, err);

        var collection = db.collection('users');

        collection.find({
            "mobileNo": mobileNo,
        }).toArray(function(err, users) {
            if (users.length <= 0) {
                resObj.IsSuccess = false;
                resObj.message = "Mobile Number not registered with us.";
                res.send(resObj);
                return 0;
            }

            var isPasswordMatch = passwordHash.verify(oldPassword, users[0].password);
            if (!isPasswordMatch) {
                resObj.IsSuccess = false;
                resObj.message = "Old Password doesnot matched with existing password.";
                res.send(resObj);
                return 0;
            }

            collection.update({
                'mobileNo': 'mobileNo'
            }, {
                '$set': {
                    'password': hashedPassword,
                }
            });

            resObj.IsSuccess = true;
            resObj.message = "Password Updated Successfully.";
            res.send(resObj);
            return 0;
        });
    });
});