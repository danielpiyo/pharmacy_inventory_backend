const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt-nodejs');
const jwt = require('jsonwebtoken');
const config = require(__dirname + '/config.js');

// Use body parser to parse JSON body
router.use(bodyParser.json());
const connAttrs = mysql.createConnection(config.connection);

router.get('/', function (req, res) {
    res.sendfile('/')
});

// login
router.post('/signin', function (req, res) {

    let user1 = {
        email: req.body.email,
        password: req.body.password
    }
    if (!user1) {
        return res.status(400).send({
            error: true,
            message: 'Please provide login details'
        });
    }
    connAttrs.query('SELECT * FROM p_users where email=?', user1.email, function (error, result) {
        if (error || result < 1) {
            res.set('Content-Type', 'application/json');
            var status = error ? 500 : 404;
            res.status(status).send(JSON.stringify({
                status: status,
                message: error ? "Error getting the that email" : "Email you have entered is Incorrect. Kindly Try Again. or Contact systemadmin",
                detailed_message: error ? error.message : ""
            }));
            console.log('========= You have Got an error ================ for this User: ' + user1.email);
            return (error);
        } else {
            user = result[0];


            bcrypt.compare(req.body.password, user.password, function (error, pwMatch) {
                var payload;
                if (error) {
                    return (error);
                }
                if (!pwMatch) {
                    res.status(401).send({
                        message: 'Wrong Password. please Try Again .'
                    });
                    return;
                }
                payload = {
                    sub: user.email,
                    entity_id: user.id,
                    username: user.username,
                    role: user.role
                };

                res.status(200).json({
                    user: {
                        username: user.username,
                        role: user.role
                    },
                    token: jwt.sign(payload, config.jwtSecretKey, {
                        expiresIn: 60 * 60 * 24
                    }) //EXPIRES IN ONE DAY,
                });
            });
        }

    });

});


// register
router.post('/register', function post(req, res, next) { // 
    
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }

    var user = {
        created_by: decoded.username,
        username: req.body.username,
        email: req.body.email,
        role: req.body.role
    };
    var unhashedPassword = req.body.password;
    bcrypt.genSalt(10, function (err, salt) {
        if (err) {
            return next(err);
        }
        // console.log(password);
        bcrypt.hash(unhashedPassword, salt, null, function (err, hash) {
            if (err) {
                return next(err);
            }
            // console.log(hash);
            user.hashedPassword = hash;

            connAttrs.query(

                'SELECT * FROM p_users where email=?', user.email, function (error, result) {
                    if (error || result.length > 0) {
                        res.set('Content-Type', 'application/json');
                        var status = error ? 500 : 404;
                        res.status(status).send(JSON.stringify({
                            status: status,
                            message: error ? "Error getting the server" : "Email you have entered is already taken.",
                            detailed_message: error ? error.message : `If user with this ${user.email} is nolonger with you please remove his details from the system`
                        }));
                        console.log("error occored");
                        return (error);
                    }
                    connAttrs.query("INSERT INTO p_users SET ? ", {
                        role: user.role,
                        email: user.email,
                        username: user.username,
                        password: user.hashedPassword,
                        created_by: user.created_by
                    }, function (error, results) {
                        if (error) {
                            res.set('Content-Type', 'application/json');
                            res.status(500).send(JSON.stringify({
                                status: 500,
                                message: "Error Posting your details",
                                detailed_message: error.message
                            }));
                        } else {
                            console.log(`${user.role}: ${user.username}, succesfully added by: ${user.created_by} on ${new Date()}`);
                            return res.contentType('application/json').status(201).send(JSON.stringify(results));
                        }
                    })
                })
        })
    })
})
});

// adding product categories
router.post('/newCategory', function (req, res) {
    var category = {
        name: req.body.category_name,
        description: req.body.description
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query(

            'SELECT * FROM p_category where category_name=?', category.name, function (error, result) {
                if (error || result.length > 0) {
                    res.set('Content-Type', 'application/json');
                    var status = error ? 500 : 404;
                    res.status(status).send(JSON.stringify({
                        status: status,
                        message: error ? "Error getting the server" : `Category you have entered was already captured on ${result[0].created_date}`,
                        detailed_message: error ? error.message : `If category ${category.name} is nolonger in use please remove it from the system`
                    }));
                    console.log("error occured");
                    return (error);
                }
                connAttrs.query("INSERT INTO p_category SET ? ", {
                    category_name: category.name,
                    description: category.description,
                    created_by: decoded.entity_id
                }, function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Posting new Category",
                            detailed_message: error.message
                        }));
                    } else {
                        console.log(`${decoded.role}: ${decoded.username}, succesfully added category: ${category.name} on ${new Date()}`);
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })
            })

    });
});

// adding products of Items


// adding product categories
router.post('/newItem', function (req, res) {
    var items = {
        name: req.body.name,
        category_id: req.body.category_id,
        quantity: req.body.quantity,
        buying_price:req.body.buying_price,
        price: req.body.price,
        description: req.body.description,
        discount_yn: req.body.discount_yn
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO p_items SET ? ", {
            name: items.name,
            description: items.description,
            created_by: decoded.entity_id,
            category_id: items.category_id,
            quantity: items.quantity,
            discount_yn:items.discount_yn,
            buying_price: items.buying_price,
            price: items.price
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting new Category",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.role}: ${decoded.username}, succesfully added Item: ${items.name} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        })


    });
});


// pulling existing categories
router.post('/categories', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT id, category_name, description FROM p_category";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Categories found",
                    detailed_message: error ? error.message : "Sorry there are no categories set. Please set categories first"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`categories selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling all the items with quantity greater than 0 or products
router.post('/items', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT A.id, A.category_id, B.category_name category, A.name, A.quantity, A.buying_price, A.price, A.description, A.created_date, C.username createdBy  FROM p_items A inner join p_category B on A.category_id=B.id inner join p_users C on A.created_by=C.id where A.quantity > 0";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Items or products found",
                    detailed_message: error ? error.message : "Sorry there are no Products set. Please consider setting up new products"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Items selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


// pulling all the items with quantity greater than 0 or products
router.post('/allitems', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT A.id, A.category_id, B.category_name category, A.name, A.quantity, A.buying_price, A.price, A.discount_yn, A.description, A.created_date, C.username createdBy  FROM p_items A inner join p_category B on A.category_id=B.id inner join p_users C on A.created_by=C.id";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Items or products found",
                    detailed_message: error ? error.message : "Sorry there are no Products set. Please consider setting up new products"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Items selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// all items discounted
router.post('/allitemsDiscount', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT A.id, A.category_id, B.category_name category, A.name, A.quantity, A.buying_price, A.price, A.discount_yn, A.description, A.created_date, C.username createdBy  FROM p_items A inner join p_category B on A.category_id=B.id inner join p_users C on A.created_by=C.id WHERE A.discount_yn='Y'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Items or products found",
                    detailed_message: error ? error.message : "Sorry there are no Products set. Please consider setting up new products"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Items selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});



// pulling items for particular category
router.post('/itemsCategory', function (req, res) {

    var category_id = req.body.category_id;
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM p_items where category_id=?";
        connAttrs.query(sql, category_id, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Items or products found",
                    detailed_message: error ? error.message : "Sorry there are no Products set. Please consider setting up new products"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Items for category ${category_id},  Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


// pulling item per id

// pulling items for particular category
router.post('/item', function (req, res) {

    var item_id = req.body.item_id;
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM p_items where id=?";
        connAttrs.query(sql, item_id, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Items or products found",
                    detailed_message: error ? error.message : "Sorry there are no Products set. Please consider setting up new products"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Item of id: ${item_id},  Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


// posting checkout logs
router.post('/checkOut', function (req, res) {
    var check_out = {
        category_id: req.body.category_id,
        item_id: req.body.item_id,
        quantity_from: req.body.quantity_from,
        quantity_to: req.body.quantity_to,
        item_price: req.body.item_price
    }
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "INSERT INTO p_logs SET?";
        connAttrs.query(sql, {
            category_id: check_out.category_id,
            item_id: check_out.item_id,
            created_by: decoded.entity_id,
            log_name: 'Check Out',
            quantity_from: check_out.quantity_from,
            quantity_to: check_out.quantity_to,
            sold_amount: (check_out.quantity_from - check_out.quantity_to) * check_out.item_price
        }, function (error, result) {
            if (error) {
                res.set('Content-Type', 'application/json');
                var status = 500;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: "Error getting the server",
                    detailed_message: error
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(result));
            console.log(`Item of id: ${check_out.item_id},  checkout succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// posting checkin logs
router.post('/checkIn', function (req, res) {
    var check_in = {
        category_id: req.body.category_id,
        item_id: req.body.item_id,
        quantity_from: req.body.quantity_from,
        quantity_to: req.body.quantity_to,
        item_price: req.body.item_price
    }
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "INSERT INTO p_logs SET?";
        connAttrs.query(sql, {
            category_id: check_in.category_id,
            item_id: check_in.item_id,
            created_by: decoded.entity_id,
            log_name: 'Check In',
            quantity_from: check_in.quantity_from,
            quantity_to: check_in.quantity_to,
            value_added_items: (check_in.quantity_to - check_in.quantity_from) * check_in.item_price
        }, function (error, result) {
            if (error) {
                res.set('Content-Type', 'application/json');
                var status = 500;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: "Error getting the server",
                    detailed_message: error
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(result));
            console.log(`${(check_in.quantity_to - check_in.quantity_from)} Items of id: ${check_in.item_id},  checkIn succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// price change logs 

// posting checkin logs
router.post('/priceChange', function (req, res) {
    var price_change = {
        category_id: req.body.category_id,
        item_id: req.body.item_id,
        price_from: req.body.price_from,
        price_to: req.body.price_to
    }
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "INSERT INTO p_logs SET?";
        connAttrs.query(sql, {
            category_id: price_change.category_id,
            item_id: price_change.item_id,
            created_by: decoded.entity_id,
            log_name: 'Price Changed',
            price_from: price_change.price_from,
            price_to: price_change.price_to
        }, function (error, result) {
            if (error) {
                res.set('Content-Type', 'application/json');
                var status = 500;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: "Error getting the server",
                    detailed_message: error
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(result));
            console.log(`Item of id: ${price_change.item_id},  Price has been changed from ${price_change.price_from} to ${price_change.price_to} succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling all registerd users
router.post('/users', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM p_users WHERE role='user'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Users found",
                    detailed_message: error ? error.message : "Sorry there are no User set. Please Add Users"
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`User selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling all Checkout reports for A day
router.post('/checkOutDay', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM pharmacy.all_check_out_reports WHERE days =0 and DATE_FORMAT(created_date, '%Y-%m-%d')=CURDATE()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling all Checkout reports for A week
router.post('/checkOutWeek', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM all_check_out_reports WHERE days BETWEEN 0 AND 7";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling all Checkout reports for A day
router.post('/checkOutMonth', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM all_check_out_reports WHERE days BETWEEN 0 AND 31";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// for graphs
// pulling all Checkout reports for A day
router.post('/checkOutDayChart', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT item name, amountSold value FROM pharmacy.all_check_out_reports WHERE days =0 and DATE_FORMAT(created_date, '%Y-%m-%d')=CURDATE()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// for graphs
// pulling all Checkout reports for A week
router.post('/checkOutWeekChart', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT item name, amountSold value FROM pharmacy.all_check_out_reports WHERE days BETWEEN 0 AND 7";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// for graphs
// pulling all Checkout reports for A month
router.post('/checkOutMonthChart', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT item name, amountSold value FROM pharmacy.all_check_out_reports WHERE days BETWEEN 0 AND 31";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// // Item update
router.post('/updateCategory', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            console.log('sub', decoded.sub)
            let itemToUpdate = {
                category_name: req.body.category_name,
                id: req.body.id,
                description: req.body.description,
                updated_by: decoded.username,
                updated_at: new Date()

            }

            if (!itemToUpdate) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE p_category SET description=?, category_name=?, updated_date = ?, updated_by=? WHERE id=?"
            connAttrs.query(sql, [itemToUpdate.description, itemToUpdate.category_name,
            itemToUpdate.updated_at, itemToUpdate.updated_by, itemToUpdate.id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Updating your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/update Released=========================")

        }
    })
})


// posting checkin logs
router.post('/updateItem', function (req, res) {
    var itemToUpdate = {
        item_name_from: req.body.item_name_from,
        item_name_to: req.body.item_name_to,
        buying_price_from: req.body.buying_price_from,
        buying_price_to: req.body.buying_price_to,
        category_id: req.body.category_id,
        category_id_from: req.body.category_id_from,
        quantity_from: req.body.quantity_from,
        quantity_to: req.body.quantity_to,
        discount_yn_before: req.body.discount_yn_before,
        discount_yn_after: req.body.discount_yn_after,
        description_from: req.body.description_from,
        description_to: req.body.description_to,
        item_id: req.body.item_id
    }
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "INSERT INTO p_logs SET?";
        connAttrs.query(sql, {
            category_id: itemToUpdate.category_id,
            category_id_from: itemToUpdate.category_id_from,
            item_id: itemToUpdate.item_id,
            item_name_from: itemToUpdate.item_name_from,
            item_name_to: itemToUpdate.item_name_to,
            buying_price_from:itemToUpdate.buying_price_from,
            buying_price_to: itemToUpdate.buying_price_to,
            quantity_from: itemToUpdate.quantity_from,            
            quantity_to: itemToUpdate.quantity_to,
            discount_yn_before: itemToUpdate.discount_yn_before,
            discount_yn_after: itemToUpdate.discount_yn_after,
            description_from: itemToUpdate.description_from,
            description_to: itemToUpdate.description_to,
            created_by: decoded.entity_id,
            log_name: 'Item Edit'
        }, function (error, result) {
            if (error) {
                res.set('Content-Type', 'application/json');
                var status = 500;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: "Error getting the server",
                    detailed_message: error
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(result));
            console.log(`Item of id: ${itemToUpdate.item_id}, has been Edited succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// checkout product report
router.post('/productReportCheckOut', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT  item, category, SUM(DISTINCT amountSOld) total FROM all_check_out_reports GROUP BY item, category";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// weekly report on each item with dates
// checkout product report
router.post('/productReportCheckOutWeekly', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT item AS name, SUM(DISTINCT amountSOld) AS value FROM pharmacy.all_check_out_reports WHERE created_date <= adddate(curdate(), INTERVAL 7-DAYOFWEEK(curdate()) DAY) AND created_date >= adddate(curdate(), INTERVAL 1-DAYOFWEEK(curdate()) DAY) group by DATE_FORMAT(created_date, '%Y-%m-%d'), item ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') ASC";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// dates for weekly charts
router.post('/productCheckOutMonthly', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT DATE_FORMAT(created_date, '%Y-%m-%d') AS DATE, item AS name, SUM(DISTINCT amountSOld) AS value FROM pharmacy.all_check_out_reports WHERE created_date <= LAST_DAY(curdate()) AND created_date >= date_add(date_add(LAST_DAY(curdate()),interval 1 DAY),interval -1 MONTH) group by DATE_FORMAT(created_date, '%Y-%m-%d'), item ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') ASC";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Record selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// user performance week
router.post('/userPerfomanceWeek', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT DISTINCT createdBy AS name, SUM(DISTINCT amountSOld) value FROM pharmacy.all_check_out_reports WHERE created_date <= adddate(curdate(), INTERVAL 7-DAYOFWEEK(curdate()) DAY) AND created_date >= adddate(curdate(), INTERVAL 1-DAYOFWEEK(curdate()) DAY) GROUP BY createdBy;";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Report selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// user performance month
router.post('/userPerfomanceMonth', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT DISTINCT createdBy AS name, SUM(DISTINCT amountSOld) value FROM pharmacy.all_check_out_reports WHERE created_date <= LAST_DAY(curdate()) AND created_date >= date_add(date_add(LAST_DAY(curdate()),interval 1 DAY),interval -1 MONTH) GROUP BY createdBy";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Checkout Report selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// reset Password

router.post('/resetPassoword', function post(req, res, next) { // 
    
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
    var unhashedPassword = req.body.password;
    bcrypt.genSalt(10, function (err, salt) {
        if (err) {
            return next(err);
        }
        // console.log(password);
        bcrypt.hash(unhashedPassword, salt, null, function (err, hash) {
            if (err) {
                return next(err);
            }
            // console.log(hash);
            // user.hashedPassword = hash;
            
                    connAttrs.query("UPDATE p_users SET password=? WHERE id=? ", [hash, req.body.id], function (error, results) {
                        if (error) {
                            res.set('Content-Type', 'application/json');
                            res.status(500).send(JSON.stringify({
                                status: 500,
                                message: "Error Posting your details",
                                detailed_message: error.message
                            }));
                        } else {
                            // console.log(`${user.role}: ${user.username}, succesfully added by: ${user.created_by} on ${new Date()}`);
                            return res.contentType('application/json').status(201).send(JSON.stringify(results));
                        }
                    })
                })
        })
    })
});

// NUMBER OF ITEMS REMAINING
router.post('/itemsTopup', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM pharmacy.p_items WHERE quantity <=10 order by id DESC;";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS , DAILY, WEEKLY, MONTHLY
router.post('/userDaily', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM pharmacy.all_check_out_reports WHERE createdBy =? AND DATE_FORMAT(created_date, '%Y-%m-%d') = curdate() ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS  WEEKLY
router.post('/userWeekly', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM pharmacy.all_check_out_reports WHERE createdBy = ? AND created_date <= adddate(curdate(), INTERVAL 7-DAYOFWEEK(curdate()) DAY) AND created_date >= adddate(curdate(), INTERVAL 1-DAYOFWEEK(curdate()) DAY) ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS  MONTHLY
router.post('/userMonthly', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM pharmacy.all_check_out_reports WHERE createdBy =? AND created_date <= LAST_DAY(curdate()) AND created_date >= date_add(date_add(LAST_DAY(curdate()),interval 1 DAY),interval -1 MONTH) ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS  WEEKLY ADMIN-VIEW
router.post('/userWeeklyAdminView', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT  * FROM pharmacy.all_check_out_reports WHERE created_date <= adddate(curdate(), INTERVAL 7-DAYOFWEEK(curdate()) DAY) AND created_date >= adddate(curdate(), INTERVAL 1-DAYOFWEEK(curdate()) DAY) ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS  MONTHLY ADMIN-VIEW
router.post('/userMonthlyAdminView', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT  * FROM pharmacy.all_check_out_reports WHERE created_date <= LAST_DAY(curdate()) AND created_date >= date_add(date_add(LAST_DAY(curdate()),interval 1 DAY),interval -1 MONTH) ORDER BY DATE_FORMAT(created_date, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});
module.exports = router;
