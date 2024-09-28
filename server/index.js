if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
const chalk = require("chalk");
const express = require("express");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const mongoose = require("mongoose");
////////////////////////////////////////////////
const keys = require("./config/keys");
const routes = require("./routes");
const socket = require("./socket");
///////////////////////////////////////////////////////////////////
//connect to mongoDB
mongoose
  .connect(keys.database.url)
  .then(() =>
    console.log(`${chalk.green("✓")} ${chalk.blue("MongoDB Connected!")}`)
  )
  .catch((err) =>
    console.log(`${chalk.red("✗")} MongoDB connection error:`, err)
  );
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
const app = express();
// Serve static files from the React app
app.use(express.static(path.join(__dirname, "..", "client", "build")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: true,
  })
);

require("./config/passport")(app);
const { apiURL } = keys.app;
// testing routes
// app.get("/", (req, res) => {
//   res.status(200).json("Hello from server")
// })

// api routes
app.use(apiURL, routes);
app.use(apiURL, (req, res) => res.status(404).json("No API route found"));

// All other GET requests should return the React app
app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "..", "client", "build", "index.html"));
});

const server = app.listen(keys.port, () => {
  console.log(
    `${chalk.green("✓")} ${chalk.blue(
      `Listening on port: ${keys.port}. Visit ${keys.app.serverURL} in your browser.`
    )}`
  );
});

socket(server);
