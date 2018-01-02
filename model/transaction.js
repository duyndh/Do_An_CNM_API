let mongoose = require('mongoose');

let TransactionSchema = new mongoose.Schema(
    {
        send_address: {type: String, required: true},
        index: {type: Number},
        receive_address: {type: String, required: true},
        amount: {type: Number, required: true},
        remaining_amount: {type: Number},
        status: {type: String},
        created_at: {type: String}    
    }
);

module.exports = mongoose.model('Transaction', TransactionSchema, 'transaction');
