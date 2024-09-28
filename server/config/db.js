const chalk = require("chalk")
const mongoose = require("mongoose")
const keys = require("./keys")

const connectDB = async () => {
  try {
    await mongoose.connect(keys.database.url)
    console.log(`${chalk.green("✓")} ${chalk.blue("MongoDB Connected!")}`)
  } catch (err) {
    console.log(`${chalk.red("✗")} MongoDB connection error:`, err)
    process.exit(1)
  }
}

module.exports = connectDB
