const Sequelize = require('sequelize');
const { STRING, Model } = Sequelize
const jwt = require('jsonwebtoken')

class User extends Model {

    get token(){
        return jwt.sign({ id: this.id }, 'swaggertothemax134245234')
    }

    toJSON(){
        let jsonObject= { ...this.dataValues, token: this.token }
        delete jsonObject.password_digest
        return jsonObject
    }

}

const sequelize = new Sequelize('ezzybrzy', null, null, {
    host: 'localhost',
    dialect: 'postgres'
  });


  User.init({
    first_name: {
        type: STRING,
    },
    last_name: {
        type: STRING
    },
    email: {
        type: STRING
    },
    subject: {
        type: STRING
    },
    message: {
        type: STRING
    },
    userID: {
        type: STRING
    }
}, { sequelize, modelName: 'User' } )

module.exports = User

sequelize.sync()


/*
const User = sequelize.define('User', {
    first_name: {
        type: STRING,
    },
    last_name: {
        type: STRING
    },
    email: {
        type: STRING
    },
    subject:{
        type: STRING
    },
    message: {
        type: STRING
    },
    userID: {
        type: INTEGER
    }
});

(async function(){
    await User.sync()
})()
*/

