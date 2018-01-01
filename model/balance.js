var mongoose= require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt-nodejs');



var balanceSchema = new mongoose.Schema(
    {
        address:{type: String},
        real_balance:{type: Number},
        usable_balance:{type:Number},
        private_key:{type: String},
        public_key:{type: String}
    }
);

var Balance = module.exports = mongoose.model('Balance', balanceSchema, 'balance');

module.exports = mongoose.model('Balance',balanceSchema);