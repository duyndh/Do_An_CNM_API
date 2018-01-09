var mongoose= require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt-nodejs');



var userSchema = new mongoose.Schema(
    {
        name:{type: String},
        email:{type: String},
  		password:{type:String},
        is_active:{type:Boolean},
        is_admin:{type:Boolean,default:false},
        address:{type: String},
        private_key:{type: String},
        public_key:{type: String}
});

userSchema.methods.encryptPassword = function(password){
	return bcrypt.hashSync(password, bcrypt.genSaltSync(5),null);
};

userSchema.methods.validPassword = function(password){
    return bcrypt.compareSync(password, this.password);
};
//var User = module.exports = mongoose.model('User', userSchema, 'user');
var User = mongoose.model('User',userSchema);
module.exports.getUserById = function(id, callback){
    User.findById(id, callback);
};
/*mongoose.model('User', StudentSchema);*/
module.exports = mongoose.model('User',userSchema);