require('dotenv').config()
const express = require('express')
const path = require('path')

const chalk = require('chalk')
const cors = require('cors')
const helmet = require('helmet')

const keys = require('./config/keys')
const routes = require('./routes')
const socket = require('./socket')
const setupDB = require('./utils/db')

const { port } = keys
const app = express()
// Serve static files from the React app
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')))
////////////////////////////////////////////////////////////

app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: true
  })
)
app.use(cors())

setupDB()
require('./config/passport')(app)

const { apiURL } = keys.app

const api = `/${apiURL}`
// api routes
app.use(api, routes)
app.use(api, (req, res) => res.status(404).json('No API route found'))
// All other GET requests should return the React app

app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, '..', 'client', 'dist', 'index.html'))
})

const server = app.listen(port, () => {
  console.log(
    `${chalk.green('✓')} ${chalk.blue(
      `Listening on port ${port}. Visit http://localhost:${port}/ in your browser.`
    )}`
  )
})

socket(server)
