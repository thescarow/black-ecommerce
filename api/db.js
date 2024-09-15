require('dotenv').config()
const chalk = require('chalk')
const mongoose = require('mongoose')

const keys = require('./config/keys')
const { database } = keys

const connectDB = async () => {
  try {
    // Connect to MongoDB
    mongoose.set('useCreateIndex', true)
    mongoose
      .connect(database.url, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useFindAndModify: false
      })
      .then(() =>
        console.log(`${chalk.green('✓')} ${chalk.blue('MongoDB Connected!')}`)
      )
      .catch(err => console.log(err))
  } catch (error) {
    console.error('MongoDB connection error', error)
    process.exit(1)
  }
}

module.exports = connectDB
