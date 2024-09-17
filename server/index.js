const chalk = require("chalk")
require("dotenv").config()
const express = require("express")
const path = require("path")
const cors = require("cors")
const helmet = require("helmet")
const mongoose = require("mongoose")
////////////////////////////////////////////////
const keys = require("./config/keys")
const routes = require("./routes")
const socket = require("./socket")
///////////////////////////////////////////////////////////////////
//connect to mongoDB
mongoose
  .connect(keys.database.url, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() =>
    console.log(`${chalk.green("✓")} ${chalk.blue("MongoDB Connected!")}`)
  )
  .catch(err => console.log(`${chalk.red("✗")} MongoDB connection error:`, err))
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
const app = express()
// Serve static files from the React app
// app.use(express.static(path.join(__dirname, "..", "client", "dist")))
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: true
  })
)
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
)

require("./config/passport")(app)
const { apiURL } = keys.app
// testing routes
app.get("/", (req, res) => {
  res.status(200).json("Hello from server")
})
const api = `/${apiURL}`
// api routes
app.use(api, routes)
app.use(api, (req, res) => res.status(404).json("No API route found"))

// All other GET requests should return the React app
// app.get("*", (req, res) => {
//   res.sendFile(path.resolve(__dirname, "..", "client", "dist", "index.html"))
// })

const server = app.listen(keys.port, () => {
  console.log(
    `${chalk.green("✓")} ${chalk.blue(
      `Listening on port: ${keys.port}. Visit ${keys.app.serverURL} in your browser.`
    )}`
  )
})

socket(server)
