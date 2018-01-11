var mongoose = require('mongoose');

var TransactionSchema = new mongoose.Schema(
    {
        is_local:{type:Boolean},
        src_hash: {type: String},
        send_address: {type: String},
        index: {type: Number},
        receive_address: {type: String},
        amount: {type: Number},
        remaining_amount: {type: Number},
        reason:{type:String},
        status: {type: String},
        two_fa_code: {type: String},
        created_at: {type: String}    
    }
);

module.exports = mongoose.model('Transaction', TransactionSchema, 'transaction');
