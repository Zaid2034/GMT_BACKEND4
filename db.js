const mongoose = require ('mongoose');
const dotenv = require ('dotenv');
dotenv.config ();

const uri=process.env.MONGO_URL;

mongoose
  .connect (
    process.env.MONGO_URL
    
  )
  .then (res => {
    console.log ('Db connect');
  })
  .catch (err => {
    console.log ('Error', err);
  });

const userSchema = mongoose.Schema ({
   email: {
    type: String,
    unique:true,
    required: true,
    trim: true,
    maxLength: 50,
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minLength: 3,
    maxLength: 30,
  },
  password: {
    type: String,
    required: true,
    minLength: 6,
  },
});
const trackingToken=mongoose.Schema({
    token:String
})
const User = mongoose.model ('User', userSchema);
const TrackingToken=mongoose.model('Tokens',trackingToken)
module.exports = {
  User,
  TrackingToken
};
