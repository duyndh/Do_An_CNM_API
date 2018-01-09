var express = require('express');
var router = express.Router();
var User = require('../model/user');
var Transaction = require('../model/transaction');
var request = require('request');
var ursa = require('ursa');
var crypto = require('crypto');
var randomstring = require('randomstring');

router.get('/',function(req, res, next) {
    res.json({
        status: 1,
        message: 'Welcome to KCoin Management API',
    });
});

function Hash(data) {
    var hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest();
}
function createAddress(res, user)
{
//isLimit = false;
  var headers, options;
  headers = {
    'User-Agent':       'Super Agent/0.0.1',
    'Content-Type':     'application/x-www-form-urlencoded'
  }
 
  // Configure the request
  options = {
    url: 'https://api.kcoin.club/generate-address',
    method: 'GET',
    headers: headers
  }
 
  // Start the request
  request(options, function (error, response, body) {
    if (!error && response.statusCode == 200) {
    var user_instance = new User();
    user_instance._id = user._id;
    //user_instance.address = JSON.parse(body).address;
    user_instance.address = JSON.parse(body).address;
    user_instance.publicKey = JSON.parse(body).publicKey;
    user_instance.privateKey = JSON.parse(body).privateKey;
    User.findByIdAndUpdate(user._id,user_instance,{}).exec(function (err, newUser) {
        if (err){
            res.json({
                status: 0,
                message: 'Failed to update address'});
        }
    });
    } else {
        res.json({
            status: 0,
            message: 'Failed to generate address'
        });
        return;
    }
  });
}
router.post('/register', function(req,res,next){
    var email = req.body.email;
    var name = req.body.name;
    var password = req.body.password;
    
    User.findOne({email: email},function(error,data){
        if (data){
            res.json({
                status: 0,
                message: 'Email is already in use!'
            });
            return;
        }
        if (!data){
            var newUser = new User();
            var private_key = ursa.generatePrivateKey(1024, 65537);
            var public_key = private_key.toPublicPem();
            
            newUser.name = name;
            newUser.email = email;
            newUser.password = newUser.encryptPassword(password);
            newUser.is_active=0;
            createAddress(res,newUser);
            newUser.save(function(error, result){
                console.log(result);
                if(error){
                    res.json({
                        status: 0,
                        message: 'Register failed!'
                    });
                    return;
                }
                var user_id = newUser.id;
                // set activation email
                var mailOptions = {
                from: 'KCoin Management <duyychiha9@gmail.com>',
                to: email, // list of receivers
                subject: 'Activation', // Subject line
                text: 'Hello world ?', // plain text body
                html: 'Click <b><a href="'+ req.protocol + "://" + req.get('host') +'/kcoin-api/active/'+ user_id +'">here</a></b> to active your account.' // html body
            };
            email_transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    res.json({
                        status: 0,
                        message: 'Send email failed!'
                    });
                    return;
                }
                res.json({
                    status: 1,
                    message: 'Register success!'
                });
            });
        });

        }
    });
    
});
router.post('/user-dashboard',function(req,res,next){
    var balance_address = req.body.address;
    var user_usable_balance = 0;
    var user_current_balance = 0;

    User.findOne({address: balance_address},function(error,data){
        if (error){
            res.json({
                status: 0,
                message: 'Get data fail'
            });
            
        }
      user_usable_balance = GetBalance(balance_address,'available');
      user_current_balance = GetBalance(balance_address,'actual');
        res.json({
            status: 1,
            message: 'Get data success',
            data: {
                name: data.name,
                address: data.address,
                usable_balance : user_usable_balance,
                current_balance : user_current_balance
            }
      });
     
    });
});


router.get('/active/:id', function(req,res,next){
    User.findOne({_id:req.params.id},function (err,user) {
        if (err) {
            res.json({
                status: 0,
                message: 'Active failed'
            });
            
        }
        var new_user = user;
        new_user.is_active = true;
        user.update(new_user, function(error){
            if (error) {
                res.json({
                    status: 0,
                    message: 'Active failed'
                });
                
            }
            // res.json({
            //     status: 1,
            //     message: 'Active success'
            // });
            res.redirect('http://localhost:3000/user/signin');
           
         });
 
     });
});
router.post('/signin', function(req,res,next){
    var email    = req.body.email;
    var password = req.body.password;
    User.findOne({email: email}, function (error, user) {
        if (!user) {
            res.json({
                status: 0,
                message: 'User not found!'
            });
            return;
        }
        if (user.is_active == 0) {
            res.json({
                status: 0,
                message: 'This user account has not been activated yet!'
            });
            return;
        }
        if (user.validPassword(password)){
            user_usable_balance = GetBalance(balance_address,'available');
            user_current_balance = GetBalance(balance_address,'actual');
                res.json({
                    status: 1,
                    message: 'Login success',      
                    data: {
                        id : user._id,
                        name: user.name,
                        address: user.address,
                        usable_balance : user_usable_balance,
                        current_balance : user_current_balance,
                        is_admin:user.is_admin
                    }
                });
                return;
        }else{
            res.json({
                status: 0,
                message: 'Your password is incorrect!'
            });
            return;
        }
    });

});


router.post('/forgotpwd', function(req,res,next){
    var M = req.body.email;
   // console.log(M);
    User.findOne({'email': M}, function (err, user) {
        if (err) {
            res.json({
                status: 0,
                message: 'Error'
            });
            return;
        }
        if (!user) {
            res.json({
                status: 0,
                message: 'User not found'
            });
            return;
        }
        
        var p = randomstring.generate(6);
        var new_user = user;
        new_user.password = new_user.encryptPassword(p);
        user.update(new_user, function (error) {
            if (error) {
                res.json({
                    status: 0,
                    message: 'Error'
                });
                return;
            }
            var mailOptions = {
                from: 'KCoin Management <duyychiha9@gmail.com>',
                to: M, // list of receivers
                subject: 'Forgotpassword', // Subject line
                text: 'Your new-password: ' + p// plain text body

            };
            email_transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    res.json({
                        status: 0,
                        message: 'Send email fail'
                    });
                    return;
                }
            });
            res.json({
                status: 1,
                message: 'Password reset'
            });
            return;
        });
    });
});


function getserverbalance(){
    var balance = 0;
    Transaction.find({status: 'available'}, function (error, available_balances) {
        if (!transactions){
            return;
        }
        for (var i in available_balances){
            var available_balance = available_balances[i];
            balance += available_balance.amount;
        }
        return balance;
    })
    

}
router.post('/create-transaction', function(req,res,next){
    var send_address = req.body.send_address;
    var receive_address = req.body.receive_address;
    var amount     = req.body.amount;
    var user_id = req.body.user_id;
    if (!send_address || !receive_address) {
        res.json({
            status: 0,
            message: 'Missing data'
        });
        
    }
    User.findById(user_id,function(error,user){
        if (error){
            res.json({
                status: 0,
                message: 'User not found'
            });
           
        }
        Balance.findById(req.user.balance_id,function(error,data){
            if (error){
                res.json({
                    status: 0,
                    message: 'Get user balance fail'
                });
                return;
            }
            if (data.usable_balance < amount){
                res.json({
                    status: 0,
                    message: 'Not enough money'
                });
                return;
            }
            var check = Balance.find({address:receive_address},function(error,local_address){
                if (error){
                    res.json({
                        status: 0,
                        message: 'An error occurs'
                    });
                    return;
                }
                var newTransaction = new Transaction();
                if (!newTransaction) {
                    res.json({
                        status: 0,
                        message: 'Transaction created fail'
                    });
                    return;
                }
                var current_time =  new Date();
                newTransaction.is_local = true;
                newTransaction.send_address = send_address;
                newTransaction.receive_address = receive_address;
                newTransaction.amount = amount;
                newTransaction.remaining_amount = amount;
                newTransaction.status = 'unconfirmed';
                newTransaction.created_at = current_time.toString();
                
                res.json({
                    status: 1,
                    message: 'New transaction created',
                    data: {
                        transaction_id: newTransaction._id
                    }

                });
                return;
            });
        });
    });   
});
function get_user_by_id(user_id){
    User.findById(user_id,function(error,user){
        if(error){
            return ;
        }
       return user;
    });
}
function sign_trans(transaction, keys) {
    var message = ToBinary(transaction, true);
    transaction.inputs.forEach((input, index) => {
        var key = keys[index];
        var signature = SignMessage(message, key.privateKey);
        // Genereate unlock script
        input.unlockScript = 'PUB ' + key.publicKey + ' SIG ' + signature;
    });
}


function sign_trans_request(inputs, outputs){
    // Generate transactions
    var bountyTransaction = {
        version: 1,
        inputs: [],
        outputs: []
    };

    var keys = [];

    inputs.forEach(input => {
        bountyTransaction.inputs.push({
            referencedOutputHash: input.source.referencedOutputHash,
            referencedOutputIndex: input.source.referencedOutputIndex,
            unlockScript: ''
        });
        keys.push(input.key);
    });

    // Output to all destination 10000 each
    outputs.forEach(output => {
        bountyTransaction.outputs.push({
            value: output.value,
            lockScript: 'ADD ' + output.address
        });
    });

    // Sign
    sign_trans(bountyTransaction, keys);

    return bountyTransaction;
}


function send_trans_request(user_id,send_address, receive_address, amount){
    var useResources = [];
    var remainingAmount = amount;
    Transaction.find({status: 'available'}, function (error, available_balances) {
        if (!transactions){
            return;
        }
        for (var i in available_balances) {
            var available_balance = available_balances[index];
            useResources.push(available_balance);
    
            available_balance.status = 'invalid';
            available_balance.save(function(error,transaction){
                if(error){
                    return;
                }
            });
    
            remainingAmount -= available_balance.amount;
            if (remainingAmount <= 0)
                break;
        }
    
        var outputs = [
            {
                address: send_address,
                value: amount
            }
        ];
    
        if (remainingAmount < 0) {
            outputs.push({
                address: send_address,
                value: -remainingAmount
            });
        }
    
        var inputs = [];
        for (var i in useResources) {
            var resource = useResources[index];
            var address = resource.send_address;
            var user = get_user_by_id(user_id);
            var key = {
                privateKey: user.private_key,
                publicKey: user.public_key,
            };
            var source = {
                referencedOutputHash: resource.src_hash,
                referencedOutputIndex: resource.index
            };
            inputs.push({source, key});
        }

        var requestData = {inputs, outputs};
        var signedRequest = SignTransactionRequest(requestData.inputs, requestData.outputs);
    
        console.log(signedRequest);
    
        var url = 'https://api.kcoin.club/transactions';
        var options = {
            uri: url,
            method: 'POST',
            json: signedRequest
        };
        request(options, function (error, response, body) 
        {
            console.log(body);
            if (body.code === 'InvalidContent') {
                return false;
            }
            return true;
        });
    })
}


router.post('/confirm-transaction', function(req,res,next){
    var transaction_id = req.body.transaction_id;
    var code          = req.body.code;
    var user_id = req.body.user_id;
    Transaction.findById(transaction_id,function(error,data){
        if (error){
            res.json({
                status: 0,
                message: 'Error getting transaction'
            });
            return;
        }
        if (!data){
            res.json({
                status: 0,
                message: 'Transaction not found!'
            });
            return;
        }
        var receive_address = data.receive_address;
        var send_address = data.send_address;
        var amount     = data.amount;
        var user = get_user_by_id(user_id);
            if (!user){
                data.remaining_amount = data.amount;
                data.status = 'pending';
    
                var sendRequestResult = send_trans_request(send_address, receive_address, amount);
                if (!sendRequestResult) {
                    res.json({
                        status: 0,
                        message: 'Failed to send create transaction request'
                    })
                }
            }
            else {
                data.remaining_amount = 0;
                data.status = 'unavailable'
            }
            Transaction.save(function(error,transaction){
                if (!transaction){
                    res.json({
                        status: 0,
                        message: 'Unknown error'
                    });
                    return;
                }
                res.json({
                    status: 1,
                    message: 'Your new transaction has been confirmed successfully.'
                });                
            })   
    });
});


function get_user_by_address(address){
    Balance.findOne({address:address},function(error,balance){
        if (error){
            return 0;
        }
        User.findOne({balance_id:balance._id},function(error,user){
            if (error){
                return 0;
            }
            return user;
        })
    });
}


function get_pending_strans(receive_address) {
        Transaction.findOne({receive_address: receive_address, status: 'pending'}, function (error, trans) {
            return(trans);
        });
}


function update_strans(transactions) {
    Transaction.save(function (err, trans) {
        return(trans);
    });
}


function get_remote_trans_by_hash(hash, index) {
        Transaction.findOne({src_hash: hash,index: index}, function (error, transaction) {
            return(transaction);
    })
}


function create_trans(trans) {
        trans.created_at = Date.now();
        var new_trans = new Transaction(trans);
        new_trans.save(function (err, tx) {
            return(tx);
        });
}

router.get('/sync-latest-blocks', function (req, res, next){
    var url = 'https://api.kcoin.club/blocks/?order=-1&limit=100';
    var options = {
        uri: url,
        method: 'GET',
        json: true
    };
    request(options, function (error, response, body) {
        var blocks = body;
        for (var i in blocks) {
            var block = blocks[i];
            var transactions = block.transactions;
            for (var index in transactions) {
                var transaction = transactions[index];
                var outputs = transaction.outputs;
                var hash = transaction.hash;
                for (var outputIndex in outputs) {
                    var output = outputs[outputIndex];
                    var value = output.value;
                    var lockScript = output.lockScript;
                    var receive_address = lockScript.split(" ")[1];
        
                    // confirm pending transaction
                    var pendingTransaction =  get_remote_trans_by_hash(receive_address);
                    if (pendingTransaction) {
                        pendingTransaction.remaining_amount = pendingTransaction.amount - value;
                        pendingTransaction.status           = 'pending';
        
                        var updatedTransaction =  update_strans(pendingTransaction);
                        continue;
                    }
        
                    // sync new transaction
                    var user = get_user_by_address(receive_address);
                    var existingRemoteTransaction =  get_remote_trans_by_hash(hash, outputIndex);
                    if (!existingRemoteTransaction && user) {
                        var remoteRemoteTransactionData = {
                            is_local: false,
                            send_address: hash,
                            index: outputIndex,
                            receive_address: receive_address,
                            amount: value,
                            status: 'available',
                        };
                        var newRemoteTransaction        =  create_trans(remoteRemoteTransactionData);
        
                        var localTransactionData = {
                            is_local: true,
                            send_address: '',
                            receive_address: receive_address,
                            amount: value,
                            remaining_amount: 0,
                            status: 'done',
                        };
                        var newLocalTransaction  =  create_trans(localTransactionData);
                    }
                }
            }
        }
        res.json({
            status: 1,
            message: 'Synced successfully',
            data: blocks
        });
    });
    
        
});

module.exports = router;