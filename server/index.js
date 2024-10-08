if (process.env.NODE_ENV !== "production") {
  require("dotenv").config()
}
const chalk = require("chalk")
const express = require("express")
const path = require("path")
const cors = require("cors")
const helmet = require("helmet")

////////////////////////////////////////////////
const keys = require("./config/keys")
const routes = require("./routes")
const socket = require("./socket")
const connectDB = require("./config/db")
///////////////////////////////////////////////////////////////////
//connect to mongoDB
connectDB()
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
const app = express()
// Serve static files from the React app
app.use(express.static(path.join(__dirname, "..", "client", "build")))
///////////////////////////////////////////////////////////////////////////////////
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
)
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: true
  })
)

require("./config/passport")(app)
// testing routes
// app.get("/", (req, res) => {
//   res.status(200).json("Hello from server")
// })
app.use(routes)

//All other GET requests should return the React app
app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "..", "client", "build", "index.html"))
})
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
const server = app.listen(keys.port, () => {
  console.log(
    `${chalk.green("✓")} ${chalk.blue(
      `Listening on port: ${keys.port}. Visit ${keys.app.serverURL} in your browser.`
    )}`
  )
})

socket(server)
