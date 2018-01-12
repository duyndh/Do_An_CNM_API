var express = require('express');
var router = express.Router();
var User = require('../model/user');
var Transaction = require('../model/transaction');
var request = require('request');
var ursa = require('ursa');
var crypto = require('crypto');
var randomstring = require('randomstring');
var util = require("util");

router.get('/',function(req, res, next) {
    res.json({
        status: 1,
        message: 'Welcome to KCoin Management API',
    });
});
function get_l_trans (address, sort = null, offset = 0, limit = 10) {
    return new Promise(resolve => {
        let query = Transaction.find({$or: [{send_address: address},{$and: [{receive_address: address},{status: {$ne: 'init'}}]}],status: {$ne: 'invalid' }}).find({'is_local':true}).skip(offset).limit(limit);
        // console.log('query 1:'+query);
        // console.log('query 2:'+util.inspect(query));
        if (sort) {
            query = query.sort({created_at: 'descending'});
        }

        query.exec(function (error, transactions) {
            if (!transactions) {
                resolve([]);
                return;
            }
            resolve(transactions);
        })
    });
}

function get_l_trans_2 (address, sort = null, offset = 0, limit = 10) {
    return new Promise(resolve => {
        let query = Transaction.find({$or: [{send_address: address},{$and: [{receive_address: address},{status: {$ne: 'init'}}]}],status: {$ne: 'invalid' }}).find({'is_local':true}).find({'status':'init'}).skip(offset).limit(limit);
        // console.log('query 1:'+query);
        // console.log('query 2:'+util.inspect(query));
        if (sort) {
            query = query.sort({created_at: 'descending'});
        }

        query.exec(function (error, transactions) {
            if (!transactions) {
                resolve([]);
                return;
            }
            resolve(transactions);
        })
    });
}

router.post('/gettrans',async function (req, res, next) {
    try {
        let address = req.body.address;
        let offset  = typeof req.query.offset !== 'undefined' ? req.query.offset : 0;
        let limit   = typeof req.query.limit !== 'undefined' ? req.query.limit : 10;
        // Transaction.find({address},)
        let result  = await get_l_trans_2(address, true, offset, limit);
        console.log(result);
        res.json({
            status: 1,
            message: 'Got data successfully',
            data: {
                transactions: result
            }
        });
    }
    catch (e) {
        res.json({
            status: 0,
            message: e.message
        });
    }
});


function post_request (url, data) {
 
    return new Promise(resolve => {
        let options = {
            uri: url,
            method: 'POST',
            json: data
        };
        request(options, function (error, response, body) {
            resolve(body);
        });
    });
};

SendGetRequest = function (url) {
    return new Promise(resolve => {
        let options = {
            uri: url,
            method: 'GET',
            json: true
        };
        request(options, function (error, response, body) {
            resolve(body);
        });
    });
};

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
        console.log(JSON.parse(body));
    var user_instance = new User();
    user_instance._id = user._id;
    //user_instance.address = JSON.parse(body).address;
    user_instance.address = JSON.parse(body).address;
    user_instance.public_key = JSON.parse(body).publicKey;
    user_instance.private_key = JSON.parse(body).privateKey;
    console.log(user_instance);
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

router.post('/get-user-trans', async function (req, res, next) {
        let address = req.body.address;
        console.log('get trans address '+address);
        let offset  = typeof req.query.offset !== 'undefined' ? req.query.offset : 0;
        let limit   = typeof req.query.limit !== 'undefined' ? req.query.limit : 10;
        let result  = await get_l_trans(address, true, offset, limit);
        res.json({
            status: 1,
            message: 'Got data successfully',
            data: {
                transactions: result
            }
        });
  });


GetBalance = async function(address, type = 'available') {
    let transactions  = await get_l_trans(address);
    let receivedAmount = 0;
    let sentAmount    = 0;
    //console.log('get local trans balance: '+transactions);
    for (let index in transactions) {
        let transaction = transactions[index];

        if (transaction.status === 'invalid' || transaction.status === 'init')
            continue;

        if (type === 'actual' && transaction.status !== 'done')
            continue;

        if (transaction.send_address === address) {
            sentAmount += transaction.amount;
        }
        else if (transaction.receive_address === address) {
            receivedAmount += transaction.amount;
        }
    }

    return receivedAmount - sentAmount;
};

router.post('/user-dashboard', async function(req,res,next){

        let address = req.body.balance_address;
       
        let available = await GetBalance(address, 'available');
        let actual = await GetBalance(address, 'actual');
        //let recent = await get_l_trans(address, true, 0, 100);
        console.log('available balance' + util.inspect(actual));
        var user = await get_user_by_address(address);
        console.log('user here : ' +user );
        res.json({
            status: 1,
            message: 'Got data successfully',
            data: {
                name: user.name,
                address: user.address,
                usable_balance: available,
                current_balance: actual,
                //transactions: recent
            }
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
            res.redirect('https://stormy-crag-55263.herokuapp.com/user/signin');
           
         });
 
     });
});


router.post('/signin', function(req,res,next){
    var email    = req.body.email;
    var password = req.body.password;
    console.log(email);
    console.log(password);
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
            var balance_address = user.address;
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
function get_free_remote_trans() {
    return new Promise(resolve => {
        Transaction.find({is_local:false,status: 'free'}, function (error, transactions) {
            if (!transactions){
                resolve([]);
                return;
            }
            resolve(transactions);
        })
    });
}
function GetAllPendingTransaction() {
        return new Promise(resolve => {
            Transaction.findOne({is_local:true,status: 'pending'}, function (error, tx) {
                resolve(tx);
            });
        });
    }
async function get_actual_server_balance () {
    var freeRemoteTransactions = await get_free_remote_trans();
    var balance = 0;
    console.log(freeRemoteTransactions);
    for (var index in freeRemoteTransactions){
        var freeRemoteTransaction = freeRemoteTransactions[index];
        balance += freeRemoteTransaction.amount;
    }

    return balance;
};

function get_remote_trans () {
    return new Promise(resolve => {
        Transaction.find({is_local:false}, function (error, transactions) {
            if (error){
                resolve([]);
                return;
            }
            resolve(transactions);
        })
    });
};


router.post('/create-transaction',async function(req,res,next){
    var send_address = req.body.send_address;
    var receive_address = req.body.receive_address;
    var amount     = req.body.amount;
    console.log(receive_address);
    if (!send_address || !receive_address) {
        res.json({
            status: 0,
            message: 'Missing data'
        });
        return;
    }
    var balance = GetBalance(send_address, 'available');
    if (balance < amount){
        res.json({
            status: 0,
            message: 'Not enough balance'
        });
        return;
    }
    var user = await get_user_by_address(send_address);
    //console.log(user);
    if (!user) { // is send money to external transaction
        var availableBalance = await get_actual_server_balance();
        console.log('Available balance of server : '+ availableBalance);
        if (availableBalance < amount){
            res.json({
                status: 0,
                message: 'Server busy... please try after 10 minutes!'
            });
            return;
        }
    }
    if (user){
            User.find({address:receive_address},function(error,local_address){
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
                let twoFACode = Generate2FACode();
                var current_time =  new Date();
                newTransaction.is_local = true;
                newTransaction.send_address = send_address;
                newTransaction.receive_address = receive_address;
                newTransaction.amount = amount;
                newTransaction.remaining_amount = amount;
                newTransaction.status = 'init';
                newTransaction.created_at = current_time.toString();
                newTransaction.two_fa_code = twoFACode;
                console.log(newTransaction);
                newTransaction.save(function (err, tx) {
                    //resolve(tx);
                    console.log('new trans : ' + tx);
                });
            
                console.log('2fa code : ' + twoFACode);
                console.log('send user ' + user );
                //process.exit();
                let srcAddress = newTransaction.send_address;
                let email = user.email;
                console.log('user email '+ email);
                let mailOptions = {
                    from: `KCoin Management <duyychiha9@gmail.com>`,
                    to: email,
                    subject: 'KCoin - Confirm new transaction',
                    text: 'Confirm new transaction: ',// plain text body
                    html: 'You just send to <b>'+newTransaction.receive_address+'</b> : <b>'+newTransaction.amount+'</b> Kcoin. <br>Your verification code is: <b>'+twoFACode+'</b><br>Click <a href="https://stormy-crag-55263.herokuapp.com/user/user-confirm/'+ newTransaction._id +'">here</a> to confirm your transaction.'
                };
                console.log('mail options '+ util.inspect(mailOptions));
                email_transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log('Email error : ' + util.inspect(error));
                        res.json({
                            status: 0,
                            message: 'Send confirmation email failed!'
                        });
                        return;
                    }
                    res.json({
                        status: 1,
                        message: 'New transaction created',
                        data: {
                            transaction_id: newTransaction._id
                        }
                        
                    });
                    return;
                });

                //
               
        });

        }
}); 

Generate2FACode = function () {
    let length = 6;
    let str = "";
    for ( ; str.length < length; str += Math.random().toString( 36 ).substr( 2 ) );
    return str.substr( 0, length ).toUpperCase();
};


function get_trans_by_id (id) {
    return new Promise(resolve => {
        Transaction.findById(id, function (error, tx) {
            resolve(tx);
        });
    });
};



function update_trans(localTx) {
    return new Promise(resolve => {
        localTx.save(function (err, tx) {
            resolve(tx);
        });
    });
}


function update_r_trans(remoteTx) {
    return new Promise(resolve => {
        remoteTx.save(function (err, tx) {
            resolve(tx);
        });
    });
}


async function build_trans_req(transactionId, srcAddress, dstAddress, amount) {
    let freeTransactions = await get_free_remote_trans();
    console.log('free transactions : '+ freeTransactions);
    let useResources = [];
    let remainingAmount = amount;
    for (let index in freeTransactions) {
        let freeTransaction = freeTransactions[index];
        useResources.push(freeTransaction);

        freeTransaction.status = 'used';
        freeTransaction.reason = transactionId;
        let updatedTransaction = await update_r_trans(freeTransaction);

        remainingAmount -= freeTransaction.amount;
        if (remainingAmount <= 0)
            break;
    }

    let outputs = [
        {
            address: dstAddress,
            value: amount
        }
    ];

    if (remainingAmount < 0) {
        outputs.push({
            address: srcAddress,
            value: -remainingAmount
        });
    }

    let inputs = [];
    for (let index in useResources) {
        let resource = useResources[index];
        console.log('resources here '+ resource);
        let address = resource.receive_address;
        console.log('build trans address : ' + address);
        let user = await get_user_by_address(address);
        //console.log('build trans user : ' + user);
        let key = {
            privateKey: user.private_key,
            publicKey: user.public_key,
        };

        let source = {
            referencedOutputHash: resource.src_hash,
            referencedOutputIndex: resource.index
        };

        inputs.push({source, key});
    }

    return {inputs, outputs}
}

async function send_trans_req (transactionId, srcAddress, dstAddress, amount) {
    //console.log('transactionId: '+ transactionId + ' srcAddress : '+ srcAddress+ ' dstAddress :  '+ dstAddress + ' amount '+ amount);
    let requestData = await build_trans_req(transactionId, srcAddress, dstAddress, amount);
    console.log('requested data ' + util.inspect(requestData));
    //process.exit();
    let signedRequest = await sign_trans_request(requestData.inputs, requestData.outputs);
    
    console.log('signed trans req' + util.inspect(signedRequest));

    let url = 'https://api.kcoin.club/transactions';
    let requestResult = await post_request(url, signedRequest);
    console.log('reqest result here : ' + util.inspect(requestResult));
    //process.exit();
    if (requestResult.code === 'InvalidContent') {
        return false;
    }
    return true;
};

get_user_by_id = function (id) {
    return new Promise(resolve => {
        User.findById(id, function (error, user) {
            resolve(user);
        });
    });
};
router.post('/delete-transaction',async function(req,res,next){
    let transaction_id = req.body.transaction_id;
    let deleteResult = await delete_l_trans(transaction_id);
    if (!deleteResult) {
        res.json({
            status: 0,
            message: 'Unknown error!'
        });
        return
    }
    res.json({
        status: 1,
        message: 'Transaction has been deleted.'
    });
});

function delete_l_trans (transaction_id) {
    return new Promise(resolve => {
        Transaction.find({_id: transaction_id,is_local:true}).remove(function (err) {
            resolve(!err);
        });
    });
};
function delete_trans  (user, req, res, next) {
    try {
        var transactionId = req.params.transactionId;
        var deleteResult = delete_l_trans(transactionId);
        if (!deleteResult) {
            res.json({
                status: 0,
                message: 'Unknown error!'
            });
            return
        }

        res.json({
            status: 1,
            message: 'Transaction has been deleted.'
        });
    }
    catch (e) {
        res.json({
            status: 0,
            message: e.message
        });
    }
};


function ToBinary(transaction, withoutUnlockScript){
    var version = Buffer.alloc(4);
    version.writeUInt32BE(transaction.version);
    var inputCount = Buffer.alloc(4);
    inputCount.writeUInt32BE(transaction.inputs.length);
    var inputs = Buffer.concat(transaction.inputs.map(input => {
      // Output transaction hash
      var outputHash = Buffer.from(input.referencedOutputHash, 'hex');
      // Output transaction index
      var outputIndex = Buffer.alloc(4);
      // Signed may be -1
      outputIndex.writeInt32BE(input.referencedOutputIndex);
      var unlockScriptLength = Buffer.alloc(4);
      // For signing
      if (!withoutUnlockScript) {
        // Script length
        unlockScriptLength.writeUInt32BE(input.unlockScript.length);
        // Script
        var unlockScript = Buffer.from(input.unlockScript, 'binary');
        return Buffer.concat([ outputHash, outputIndex, unlockScriptLength, unlockScript ]);
      }
      // 0 input
      unlockScriptLength.writeUInt32BE(0);
      return Buffer.concat([ outputHash, outputIndex, unlockScriptLength]);
    }));
    var outputCount = Buffer.alloc(4);
    outputCount.writeUInt32BE(transaction.outputs.length);
    var outputs = Buffer.concat(transaction.outputs.map(output => {
      // Output value
      var value = Buffer.alloc(4);
      value.writeUInt32BE(output.value);
      // Script length
      var lockScriptLength = Buffer.alloc(4);
      lockScriptLength.writeUInt32BE(output.lockScript.length);
      // Script
      var lockScript = Buffer.from(output.lockScript);
      return Buffer.concat([value, lockScriptLength, lockScript ]);
    }));
    return Buffer.concat([ version, inputCount, inputs, outputCount, outputs ]);
}

function Signmessage(message, privateKeyHex){
    // Create private key form hex
    var privateKey = ursa.createPrivateKey(Buffer.from(privateKeyHex, 'hex'));
    // Create signer
    var signer = ursa.createSigner('sha256');
    // Push message to verifier
    signer.update(message);
    // Sign
    return signer.sign(privateKey, 'hex');
}

function sign_trans(transaction, keys) {
    var message = ToBinary(transaction, true);
    transaction.inputs.forEach((input, index) => {
        var key = keys[index];
        var signature = Signmessage(message, key.privateKey);
        // Genereate unlock script
        input.unlockScript = 'PUB ' + key.publicKey + ' SIG ' + signature;
    });
}


async function sign_trans_request(inputs, outputs){
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


router.post('/confirm-transaction',async function(req,res,next){
    var transaction_id = req.body.transaction_id;
    var password = req.body.password;
    let code          = req.body.code;
    // console.log('confirm code ' + code);
    // console.log('confirm password ' +password);
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
        if (data.two_fa_code != code){
            res.json({
                status: 0,
                message: 'Invalid code!'
            });
            return;
        }

        
        var receive_address = data.receive_address;
        var send_address = data.send_address;
        var amount     = data.amount;
        //var user = get_user_by_address(send_address);
        User.findOne({'address':send_address},function(error,user){
            console.log('data 2 '+ data);
            console.log('user 2 '+ user);
            if (error){
                console.log('user error here : ' + error);
                res.json({
                    status: 0,
                    message: 'Error getting user address!'
                });
                return;
            }
            if (!user){
                data.remaining_amount = data.amount;
                data.status = 'pending';
    
                var sendRequestResult = send_trans_req(transaction_id,send_address, receive_address, amount);
                if (!sendRequestResult) {
                    res.json({
                        status: 0,
                        message: 'Failed to send create transaction request'
                    })
                }
            }else {
                if (user.validPassword(password)){
                    data.remaining_amount = 0;
                    data.status = 'done'
                    data.save(function(error,transaction){
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
                }else{
                    res.json({
                        status: 0,
                        message: 'Password is incorrect.'
                    });
                    return;
                }
                
        
            }
        });
        //console.log(user);
            

            
    });
});


function get_user_by_address(address){
    return new Promise(resolve => {
        User.findOne({address}, function (error, user) {
            resolve(user);
        });
    });
}


function get_remote_trans_by_hash(hash, index) {
    return new Promise(resolve => {
        Transaction.findOne({is_local:false,src_hash: hash,index}, function (error, transaction) {
            resolve(transaction);
    });
});
}

function CreateRemoteTransaction(newRemoteTx) {
    return new Promise(resolve => {
        newRemoteTx.created_at = Date.now();
        newRemoteTx.is_local = false;
       
        let newObj = new Transaction(newRemoteTx);
        
        newObj.save(function (err, tx) {
            if(err){
                console.log('err create remote trans  '+ err);
            }
           
            resolve(tx);

        });
    });
}

function CreateLocalTransaction(newLocalTx) {
    return new Promise(resolve => {
        newLocalTx.created_at = Date.now();
        newLocalTx.is_local = true;
        let newObj = new Transaction(newLocalTx);
        newObj.save(function (err, tx) {
            if(err){
                console.log('err create local trans  '+ err);
            }
            resolve(tx);
        });
    });
}

sync_trans = async function (transactions, isInitAction = false) {
    for (let index in transactions) {
        let transaction = transactions[index];
        let outputs = transaction.outputs;
        let hash = transaction.hash;
        let isReceiveRefund = false;
        for (let outputIndex in outputs) {
            let output = outputs[outputIndex];
            let value = output.value;
            let lockScript = output.lockScript;
            let dstAddress = lockScript.split(" ")[1];
            
            // confirm pending transaction
            let pendingTransaction = await GetPendingTransactionByDstAddress(dstAddress, value);
            // console.log('pending trans : '+ pendingTransaction);

            if (pendingTransaction) {
                pendingTransaction.remaining_amount = 0;
                pendingTransaction.status           = 'done';

                let updatedTransaction = await update_trans(pendingTransaction);
                isReceiveRefund = true;
                continue;
            }

            // sync new transaction
            let user = await get_user_by_address(dstAddress);
            //console.log('user:'+ user);
            console.log(util.inspect( dstAddress));
            // process.exit();
            let existingRemoteTransaction = await get_remote_trans_by_hash(hash, outputIndex);
            // console.log('remote trans:'+ existingRemoteTransaction);
            // console.log('output ' + output);
            // console.log('value ' + value);
            // console.log('lockScript ' + lockScript);
            // console.log('dstAddress ' + dstAddress);
           
            if (!existingRemoteTransaction && user) {
                //console.log('user ' + user);
                
                let remoteRemoteTransactionData = {
                    src_hash: hash,                   
                    index: outputIndex,
                    receive_address: dstAddress,
                    amount: value,
                    status: 'free',
                };

                let newRemoteTransaction        = await CreateRemoteTransaction(remoteRemoteTransactionData);
                console.log('create remote trans:'+ newRemoteTransaction);
                //process.exit();
                if (isReceiveRefund)
                    continue;

                let localTransactionData = {
                    send_address: '',
                    
                    receive_address: dstAddress,
                    amount: value,
                    remaining_amount: 0,
                    status: 'done',
                };
                let newLocalTransaction  = await CreateLocalTransaction(localTransactionData);
            }
        }
    }
};

GetLatestBlocks = async function (limit = 100) {
    let url = `https://api.kcoin.club/blocks/?order=-1&limit=${limit}`;
    let blocks = await SendGetRequest(url);
    return blocks;
};

router.get('/sync-latest-blocks',async function (req, res, next){
    try {
        blocks = await GetLatestBlocks();
        for (let index in blocks) {
            let block = blocks[index];
            let transactions = block.transactions;
            sync_trans(transactions);
            
        }
        res.json({
            status: 1,
            message: 'Synced successfully',
            data: blocks
        });
    }
    catch (e) {
        res.json({
            status: 0,
            message: e.message
        });
    }

});

router.get('/sync-block/:blockId', function(req, res, next) {
    try {
        var blockId = req.params.blockId;
        var isInitAction = req.query.init ? true : false;
        var url = 'https://api.kcoin.club/blocks/'+blockId;
        var options = {
            uri: url,
            method: 'GET',
            json: true
        };
        request(options, function(error, response, body) {
            //console.log(response);
            block = body;
            // process.exit();
            //console.log('sync trans '+transactions);
            var transactions = block.transactions;
            sync_trans(transactions, isInitAction);
            
            res.json({
                status: 1,
                message: 'Synced successfully',
                data: transactions
            });
        });
        
    }
    catch (e) {
        res.json({
            status: 0,
            message: e.message
        });
    }
});

function get_all_remote_trans(req, res, next) {
    try {
        var remoteTransactions = get_remote_trans();
        var userList = {};
        var data = [];
        for (var index in remoteTransactions) {
            var transaction = remoteTransactions[index];
            var dstAddr = transaction.dst_addr;

            if (!userList[dstAddr]){
                var user = get_user_by_address(dstAddr);
                userList[receive_address] = user;
            }

            data.push({
                hash: transaction.src_hash,
                index: transaction.index,
                dst_addr: transaction.dst_addr,
                dst_email: userList[dstAddr] ? userList[dstAddr].email : null,
                amount: transaction.amount,
                status: transaction.status
            });
        }

        res.json({
            status: 1,
            message: 'Got data successfully',
            data
        });
    }
    catch (e) {
        res.json({
            status: 0,
            message: e.message
        });
    }
};

function GetAllPendingTransaction() {
    return new Promise(resolve => {
        Transaction.findOne({is_local:true,status: 'pending'}, function (error, tx) {
            resolve(tx);
        });
    });
}

function GetRemoteTransactionByHashIndex(hash, index) {
    return new Promise(resolve => {
        Transaction.findOne({is_local:false,src_hash: hash, index}, function (error, transaction) {
            resolve(transaction);
        })
    });
}
function GetPendingTransactionByDstAddress(dstAddress, amount) {
    return new Promise(resolve => {
        Transaction.findOne({is_local:true,receive_address: dstAddress, status: 'pending', amount}, function (error, tx) {
            resolve(tx);
        });
    });
}


function get_pending_strans() {
    return new Promise(resolve => {
        Transaction.findOne({is_local:true,status: 'pending'}, function (error, tx) {
            resolve(tx);
        });
    });
}

function get_source_trans(transactionId) {
    return new Promise(resolve => {
        Transaction.find({is_local:false,reason: transactionId}, function (error, transactions) {
            if (error) {
                resolve([]);
                return;
            }
            resolve(transactions);
        })
    });
}


get_server_pending = async function () {
    let pendingAmount = 0;
    let pendingTransactions = await get_pending_strans();

    for (let index in pendingTransactions) {
        let local = pendingTransactions[index];

        let sources = await get_source_trans(local._id);
        let sourceAmount = 0;
        for (let sourceIndex in sources) {
            let source = sources[sourceIndex];
            sourceAmount += source.amount;
        }
        pendingAmount += sourceAmount - local.amount;
    }

    return pendingAmount;
};


router.post('/getadmindashboard',async function (req, res, next) {
    var admin_address = req.body.address;
    var user = await get_user_by_address(admin_address);
    if (user.is_admin){
        let actualBalance = await get_actual_server_balance();
        let pendingBalance = await get_server_pending();
        let availableBalance = actualBalance + pendingBalance;
        console.log(actualBalance);
        console.log(pendingBalance);
        User.count({},function(error,user_number){
            if (error){
                res.json({
                    status: 0,
                    message: 'Error counting users'
                });
            }
            res.json({
                status: 1,
                message: "Got info successfully",
                data: {
                    available: availableBalance,
                    actual: actualBalance,
                    number_of_user : user_number
                }
            });
        });
    }else{
        res.json({
            status: 0,
            message: "Access denined"
        });
    }
    
});

GetUsers = function () {
    return new Promise(resolve => {
        User.find({}, function (error, users) {
            if (error){
                resolve([]);
                return;
            }
            resolve(users);
        })
    });
};


router.post('/getuserinfo',async function (req, res, next) {
    try {
        let users = await GetUsers();
        let data = [];
        for (let index in users) {
            let user = users[index];
            let address = user.address;

            let available = await GetBalance(address, 'available');
            let unconfirmed = await GetBalance(address, 'actual');
            console.log('available money '+ available);
            console.log('unconfirmed money '+ unconfirmed);
            let actual = available - unconfirmed;
            data.push({
                id: user._id,
                email: user.email,
                address,
                actual,
                available
            });
        }

        res.json({
            status: 1,
            message: 'Got data successfully',
            data
        });
    }
    catch (e) {
        res.json({
            status: 0,
            message: e.message
        });
    }
});

router.post('/getusertransaction',async function (req, res, next) {
    var address = req.body.address;
    var user_out = await get_user_by_address(address);
   
    if (user_out.is_admin){
        let userId = req.body.id;
        let user = await get_user_by_id(userId);
        console.log('address here '+user.address);

        let transactions = await get_l_trans(user.address, null, 0, null);
        console.log(transactions);
        res.json({
            status: 1,
            message: 'Got data successfully',
            data: {
                user: {
                    id: user._id,
                    email: user.email,
                    address: user.address
                },
                transactions
            }
        });
    }else{
    res.json({
        status: 0,
        message: 'Invalid access',
        data
    });
}
});

router.post('/getalltransactions', async function (req, res, next) {
    var address = req.body.address;
    var user_out = await get_user_by_address(address);
    if (user_out.is_admin){
        let remoteTransactions = await get_remote_trans();
        console.log('remote-trans'+remoteTransactions);
        let userList = {};
        let data = [];
        for (let index in remoteTransactions) {
            let transaction = remoteTransactions[index];
            let receive_address = transaction.receive_address;

            if (!userList[receive_address]){
                let user = await get_user_by_address(receive_address);
                userList[receive_address] = user;
            }

            data.push({
                hash: transaction.src_hash,
                index: transaction.index,
                receive_address: transaction.receive_address,
                email: userList[receive_address] ? userList[receive_address].email : null,
                amount: transaction.amount,
                status: transaction.status
            });
        }

        res.json({
            status: 1,
            message: 'Got data successfully',
            data
        });
    }else{
        res.json({
            status: 0,
            message: 'Invalid access',
            data
        });
    }

});


module.exports = router;