var mongoose= require('mongoose');


var balanceSchema = new mongoose.Schema(
    {
        address:{type: String},
        real_balance:{type: Number},
        usable_balance:{type:Number},
        private_key:{type: String},
        public_key:{type: String}
    }
);

module.exports = mongoose.model('Balance',balanceSchema, 'balance');