require("dotenv").config()
const express = require('express');
require("./config/db")
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use("/api", require("./routers"))
require("./swagger/swagger")(app);


const port = process.env.PORT || 4000
app.listen(port, () => { console.log(`Server is start for this port:${port}`); })