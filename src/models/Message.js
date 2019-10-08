const Sequelize = require('sequelize');
const { STRING, INTEGER, BOOLEAN } = Sequelize;

const sequelize = new Sequelize('ezzybrzy', null, null, {
    host: 'localhost',
    dialect: 'postgres'
});

const Message = sequelize.define('Message', {
    userID: {
        type: INTEGER,
    },
    message: {
        type: STRING
    },
    isJack: {
        type: BOOLEAN
    }
});

(async function(){
    await Message.sync()
})()

sequelize.sync({force:true})
module.exports = Message