var mongoose = require('mongoose');

var TransactionSchema = new mongoose.Schema(
    {
        is_local:{type:Boolean},
        src_hash: {type: String},
        send_address: {type: String, required: true},
        index: {type: Number},
        receive_address: {type: String, required: true},
        amount: {type: Number, required: true},
        remaining_amount: {type: Number},
        reason:{type:String},
        status: {type: String},
        created_at: {type: String}    
    }
);

module.exports = mongoose.model('Transaction', TransactionSchema, 'transaction');
