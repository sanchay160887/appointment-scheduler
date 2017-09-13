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

var server = app.listen(process.env.PORT || 5300, function() {
    console.log("App started with Mongodb");
});

function parse_JSON(responsecontent) {
    try {
        return JSON.parse(responsecontent);
    } catch (ex) {
        return null;
    }
}

function array_unique(a) {
    a.sort();
    for (var i = 1; i < a.length;) {
        if (a[i - 1] == a[i]) {
            a.splice(i, 1);
        } else {
            i++;
        }
    }
    return a;
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
                }, function() {
                    callback(null, 'registered');
                })
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

app.post('/users/fetchByMobile', function(req, res) {
    mobileNo = req.body.mobileNo;

    var resObj = {};

    if (!(mobileNo)) {
        resObj.IsSuccess = false;
        resObj.message = "Please provide Mobile Number";
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
            if (users.length) {
                resObj.IsSuccess = true;
                users[0].password = '';
                resObj.user = users[0];
                res.send(resObj);
                return 0;
            }
            callback(null, true);
        });

    });
});

app.post('/appointments/request', function(req, res) {
    var requestedBy = req.body.requestedBy;
    var requestedFrom = req.body.requestedFrom;
    var requestDate = req.body.requestDate;
    var reqStartTime = req.body.startTime;
    var reqEndTime = req.body.endTime;
    var privacy = req.body.privacy;

    var resObj = {};

    if (!(requestedBy && requestedFrom && requestDate && reqStartTime && reqEndTime)) {
        resObj.IsSuccess = false;
        resObj.message = "Please provide appropriate informations";
        res.send(resObj);
        return;
    }

    if (!privacy) {
        privacy = 'public';
    } else if (privacy != 'public' && privacy != 'private') {
        resObj.IsSuccess = false;
        resObj.message = "Invalid privacy request";
        res.send(resObj);
        return;
    }

    startTime = new Date(requestDate + ' ' + reqStartTime);
    if (startTime) {
        startTime = startTime.getTime();
    } else {
        resObj.IsSuccess = false;
        resObj.message = "Invalid time request";
        res.send(resObj);
        return;
    }


    endTime = new Date(requestDate + ' ' + reqEndTime);
    if (endTime) {
        endTime = endTime.getTime();
    } else {
        resObj.IsSuccess = false;
        resObj.message = "Invalid time request";
        res.send(resObj);
        return;
    }

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }

        assert.equal(null, err);

        var collection = db.collection('users');
        var appcollection = db.collection('appointments');
        async.waterfall([
            function(callback) {
                collection.find(ObjectId(requestedBy)).
                toArray(function(err, users) {
                    if (!users.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Logged In with Invalid User.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(approved, callback) {
                collection.find(ObjectId(requestedFrom)).
                toArray(function(err, users) {
                    if (!users.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Invalid User for request.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(approved, callback) {
                appcollection.find({
                    'startTime': { $lte: endTime },
                    'endTime': { $gte: startTime },
                    'status': 'approved',
                    $or: [{
                            'requestedFrom': ObjectId(requestedBy)
                        },
                        {
                            'requestedBy': ObjectId(requestedBy)
                        }
                    ]
                }).
                toArray(function(err, appointments) {
                    if (appointments.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "You are having other appointments on selected time.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(approved, callback) {
                appcollection.find({
                    'startTime': { $lte: endTime },
                    'endTime': { $gte: startTime },
                    'status': 'approved',
                    $or: [{
                            'requestedFrom': ObjectId(requestedFrom)
                        },
                        {
                            'requestedBy': ObjectId(requestedFrom)
                        }
                    ]
                }).
                toArray(function(err, appointments) {
                    if (appointments.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Requested User not available on selected Schedule.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(approved, callback) {
                appcollection.insert({
                    'requestedBy': ObjectId(requestedBy),
                    'requestedFrom': ObjectId(requestedFrom),
                    'privacy': privacy,
                    'startTime': startTime,
                    'endTime': endTime,
                    'status': 'pending'
                }, function() {
                    callback(null, 'registered');
                })
            },
            function(response, callback) {
                db.close();
                resObj.IsSuccess = true;
                resObj.message = "Request sent successfully";
                res.send(resObj);
                return 0;
            }
        ]);
    });
});

app.post('/appointments/all', function(req, res) {
    var requestedFrom = req.body.requestedFrom;
    var startFromTime = req.body.startFromTime;
    var endToTime = req.body.endToTime;

    var resObj = {};

    if (!(requestedFrom && endToTime && startFromTime)) {
        resObj.IsSuccess = false;
        resObj.message = "Please provide appropriate informations";
        res.send(resObj);
        return;
    }

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }

        assert.equal(null, err);

        var collection = db.collection('users');
        var appcollection = db.collection('appointments');
        async.waterfall([
            function(callback) {
                collection.find(ObjectId(requestedFrom)).
                toArray(function(err, users) {
                    if (!users.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Invalid User for request.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(next, callback) {
                appcollection.aggregate([{
                        $match: {
                            'startTime': { $gte: startFromTime },
                            'endTime': { $lte: endToTime },
                            $or: [{
                                    'requestedFrom': ObjectId(requestedFrom)
                                },
                                {
                                    'requestedBy': ObjectId(requestedFrom)
                                }
                            ]
                        }
                    }, {
                        $lookup: {
                            from: 'users',
                            localField: 'requestedBy',
                            foreignField: '_id',
                            as: 'requested_by'
                        }
                    }, {
                        $unwind: {
                            'path': "$requested_by",
                        }
                    }, {
                        $lookup: {
                            from: 'users',
                            localField: 'requestedFrom',
                            foreignField: '_id',
                            as: 'requested_from'
                        }
                    }, {
                        $unwind: {
                            'path': "$requested_from",
                        }
                    }])
                    .toArray(function(err, appointments) {
                        if (!appointments) {
                            resObj.IsSuccess = false;
                            resObj.message = "No appointments scheduled.";
                            res.send(resObj);
                            return 0;
                        } else {
                            resObj.IsSuccess = true;
                            resObj.message = "Appointment fetched successfully.";
                            resObj.appointments = appointments;
                            res.send(resObj);
                        }
                    });
            }
        ]);
    });
});

app.post('/users/verifycontacts', function(req, res) {
    var contacts = req.body.contacts;

    var mobileNos = [];

    resObj = {};

    for (var c in contacts) {
        contacts[c].phone = contacts[c].phone.split(' ').join();
        mobileNos.push(contacts[c].phone);
    }

    var dbUsers = [];

    mobileNos = array_unique(mobileNos);

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }
        assert.equal(null, err);

        var collection = db.collection('users');

        collection.find({
            "mobileNo": { $in: mobileNos },
        }).toArray(function(err, users) {
            for (var u in users) {
                dbUsers[users[u].mobileNo] = { firstName: users[u].firstName, lastName: users[u].lastName, id: users[u]._id }
            }

            for (var c in contacts) {
                if (dbUsers[contacts[c].phone]) {
                    contacts[c].dbFirstName = dbUsers[contacts[c].phone].firstName;
                    contacts[c].dbLastName = dbUsers[contacts[c].phone].lastName;
                    contacts[c].dbId = dbUsers[contacts[c].phone].id;
                } else {
                    contacts[c].dbFirstName = contacts[c].name;
                    contacts[c].dbLastName = '';
                    contacts[c].dbId = '';
                }
                contacts[c].allFieldsValue = contacts[c].dbFirstName.toLowerCase() + ' ' + contacts[c].dbLastName.toLowerCase() + ' ' + contacts[c].phone;
            }

            resObj.IsSuccess = true;
            resObj.message = "Fetched Successfully.";
            resObj.contacts = contacts;
            res.send(resObj);
            return 0;
        });

    });
});

app.post('/appointments/pendings', function(req, res) {
    var requestedFrom = req.body.requestedFrom;
    var startFromTime = req.body.startFromTime;
    var listFilter = req.body.listFilter;

    var resObj = {};

    if (!startFromTime) {
        resObj.IsSuccess = false;
        resObj.message = "Please provide appropriate informations";
        res.send(resObj);
        return;
    }

    if (!listFilter) {
        listFilter = 'pending';
    }

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }

        assert.equal(null, err);

        var collection = db.collection('users');
        var appcollection = db.collection('appointments');
        async.waterfall([
            function(callback) {
                collection.find(ObjectId(requestedFrom)).
                toArray(function(err, users) {
                    if (!users.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Invalid User for request.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(next, callback) {
                var filters = {
                    'startTime': { $gte: startFromTime },
                    'requestedFrom': ObjectId(requestedFrom),

                };
                if (listFilter != 'all') {
                    filters.status = listFilter;
                }
                appcollection.aggregate([{
                        $match: filters
                    }, {
                        $lookup: {
                            from: 'users',
                            localField: 'requestedBy',
                            foreignField: '_id',
                            as: 'requested_by'
                        }
                    }, {
                        $unwind: {
                            'path': "$requested_by",
                        }
                    }])
                    .sort({ 'startTime': 1 })
                    .toArray(function(err, appointments) {
                        if (!appointments) {
                            resObj.IsSuccess = false;
                            resObj.message = "No appointments scheduled.";
                            res.send(resObj);
                            return 0;
                        } else {
                            resObj.IsSuccess = true;
                            resObj.message = "Appointment fetched successfully.";
                            resObj.appointments = appointments;
                            res.send(resObj);
                        }
                    });
            }
        ]);
    });
});

app.post('/appointments/approve', function(req, res) {
    var appointmetnId = req.body.appointmetnId;
    var actionTaken = req.body.actionTaken;
    var requestUser = req.body.requestUser;

    var resObj = {};

    if (!(requestUser && appointmetnId && actionTaken)) {
        resObj.IsSuccess = false;
        resObj.message = "Please provide appropriate informations";
        res.send(resObj);
        return;
    }

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }
        assert.equal(null, err);

        var collection = db.collection('appointments');

        async.waterfall([
            function(callback) {
                appcollection.find({
                    'startTime': { $lte: endTime },
                    'endTime': { $gte: startTime },
                    'status': 'approved',
                    $or: [{
                            'requestedFrom': ObjectId(requestUser)
                        },
                        {
                            'requestedBy': ObjectId(requestUser)
                        }
                    ]
                }).
                toArray(function(err, appointments) {
                    if (appointments.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Unable to approve. You are having another appointments on this time.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(next, callback) {
                collection.find(ObjectId(appointmetnId)).toArray(function(err, users) {

                    collection.update({
                        _id: ObjectId(appointmetnId)
                    }, {
                        '$set': {
                            'status': actionTaken,
                        }
                    }).then(function() {
                        resObj.IsSuccess = true;
                        resObj.message = "Status updated successfully.";
                        res.send(resObj);
                        return 0;
                    })

                });

            }
        ]);
    });
});

app.post('/appointments/sent', function(req, res) {
    var requestedBy = req.body.requestedBy;
    var startFromTime = req.body.startFromTime;
    var listFilter = req.body.listFilter;

    var resObj = {};

    if (!startFromTime) {
        resObj.IsSuccess = false;
        resObj.message = "Please provide appropriate informations";
        res.send(resObj);
        return;
    }

    if (!listFilter) {
        listFilter = 'all';
    }

    MongoClient.connect(mongourl, function(err, db) {
        if (err) {
            return console.dir(err);
        }

        assert.equal(null, err);

        var collection = db.collection('users');
        var appcollection = db.collection('appointments');
        async.waterfall([
            function(callback) {
                collection.find(ObjectId(requestedBy)).
                toArray(function(err, users) {
                    if (!users.length) {
                        resObj.IsSuccess = false;
                        resObj.message = "Invalid User for request.";
                        res.send(resObj);
                        return 0;
                    }
                    callback(null, true);
                });
            },
            function(next, callback) {
                var filters = {
                    'startTime': { $gte: startFromTime },
                    'requestedBy': ObjectId(requestedBy),

                };
                if (listFilter != 'all') {
                    filters.status = listFilter;
                }
                appcollection.aggregate([{
                        $match: filters
                    }, {
                        $lookup: {
                            from: 'users',
                            localField: 'requestedFrom',
                            foreignField: '_id',
                            as: 'requested_from'
                        }
                    }, {
                        $unwind: {
                            'path': "$requested_from",
                        }
                    }])
                    .sort({ 'startTime': 1 })
                    .toArray(function(err, appointments) {
                        if (!appointments) {
                            resObj.IsSuccess = false;
                            resObj.message = "No appointments requested.";
                            res.send(resObj);
                            return 0;
                        } else {
                            resObj.IsSuccess = true;
                            resObj.message = "Appointment fetched successfully.";
                            resObj.appointments = appointments;
                            res.send(resObj);
                        }
                    });
            }
        ]);
    });
});