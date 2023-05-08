const mongoose = require("mongoose");

const { MONGO_URI } = process.env;

exports.connect = () => {
  mongoose
    .connect(MONGO_URI)
    .then(() => {
      console.log("Successfully connected to database");
    })
    .catch((err) => {
      console.log("Databsase connection failed. exiting now...");
      console.error(err);
      process.exit(1);
    });
};
