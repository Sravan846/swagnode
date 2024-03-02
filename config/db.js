const mongoose = require('mongoose');
mongoose.connect(process.env.DBConnection)
mongoose.connection.on("connected", (err) => {
    if (err) {
        console.log('err', err)
    } else {
        console.log("Db is connected successfully");
    }
})