const mongoose = require("mongoose")
const connectDB = async () => {
  try {
    await mongoose.connect(keys.database.url, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    })
    console.log(`${chalk.green("✓")} ${chalk.blue("MongoDB Connected!")}`)
  } catch (err) {
    console.log(`${chalk.red("✗")} MongoDB connection error:`, err)
    process.exit(1)
  }
}

module.exports = connectDB
