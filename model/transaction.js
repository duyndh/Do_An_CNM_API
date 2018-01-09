var mongoose = require('mongoose');

var TransactionSchema = new mongoose.Schema(
    {
        src_hash: {type: String},
        inputs:[{unlockScript:{type: String}, referencedOutputHash:{type: String},referencedOutputIndex:{type: Number}}],
          outputs:[{value:{type: Number},lockScript:{type: String}}],
        status: {type: String},
        created_at: {type: String}    
    }
);

module.exports = mongoose.model('Transaction', TransactionSchema, 'transaction');
