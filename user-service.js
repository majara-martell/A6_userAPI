require("dotenv").config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

let mongoDBConnectionString = process.env.MONGO_URL;

let Schema = mongoose.Schema;

let userSchema = new Schema({
    userName: {
        type: String,
        unique: true
    },
    password: String,
    favourites: [String],
    history: [String]
});

let User;
let isConnected = false;

module.exports.connect = async function () {
    if (isConnected && User) {
        console.log("Already connected to MongoDB");
        return Promise.resolve();
    }

    return new Promise(function (resolve, reject) {
        console.log("Attempting to connect to MongoDB...");
        console.log("Connection string exists:", !!mongoDBConnectionString);
        
        if (!mongoDBConnectionString) {
            reject(new Error("MONGO_URL environment variable is not set"));
            return;
        }

        let db = mongoose.createConnection(mongoDBConnectionString);

        db.on('error', (err) => {
            console.error("MongoDB connection error:", err);
            isConnected = false;
            reject(err);
        });

        db.once('open', () => {
            console.log("MongoDB connected successfully");
            User = db.model('User', userSchema);
            isConnected = true;
            resolve();
        });
    });
};

module.exports.registerUser = function (userData) {
    return new Promise(async function (resolve, reject) {
        try {
            // Ensure connection is established
            if (!User) {
                console.log("User model not initialized, connecting...");
                await module.exports.connect();
            }

            console.log("Registering user:", userData.userName);

            if (userData.password != userData.password2) {
                reject("Passwords do not match");
                return;
            }

            const hash = await bcrypt.hash(userData.password, 10);
            userData.password = hash;

            let newUser = new User(userData);

            newUser.save().then(() => {
                console.log("User registered successfully:", userData.userName);
                resolve("User " + userData.userName + " successfully registered");  
            }).catch(err => {
                console.error("Error saving user:", err);
                if (err.code == 11000) {
                    reject("User Name already taken");
                } else {
                    reject("There was an error creating the user: " + err);
                }
            });

        } catch (err) {
            console.error("Error in registerUser:", err);
            reject(err.toString());
        }
    });
};

module.exports.checkUser = function (userData) {
    return new Promise(function (resolve, reject) {

        User.findOne({ userName: userData.userName })
            .exec()
            .then(user => {
                if (!user) {
                    reject("Unable to find user " + userData.userName);
                    return;
                }

                bcrypt.compare(userData.password, user.password).then(res => {
                    if (res === true) {
                        resolve(user);
                    } else {
                        reject("Incorrect password for user " + userData.userName);
                    }
                }).catch(err => {
                    console.error("Error comparing passwords:", err);
                    reject("Password comparison failed");
                });
            }).catch(err => {
                console.error("Error finding user:", err);
                reject("Unable to find user " + userData.userName);
            });
    });
};

module.exports.getFavourites = function (id) {
    return new Promise(function (resolve, reject) {

        User.findById(id)
            .exec()
            .then(user => {
                if (!user) {
                    reject(`User not found with id: ${id}`);
                    return;
                }
                resolve(user.favourites)
            }).catch(err => {
                console.error("Error getting favourites:", err);
                reject(`Unable to get favourites for user with id: ${id}`);
            });
    });
}

module.exports.addFavourite = function (id, favId) {

    return new Promise(function (resolve, reject) {

        User.findById(id).exec().then(user => {
            if (!user) {
                reject(`User not found with id: ${id}`);
                return;
            }

            if (user.favourites.length < 50) {
                User.findByIdAndUpdate(id,
                    { $addToSet: { favourites: favId } },
                    { new: true }
                ).exec()
                    .then(user => { resolve(user.favourites); })
                    .catch(err => { reject(`Unable to update favourites for user with id: ${id}`); })
            } else {
                reject(`Unable to update favourites for user with id: ${id} - limit reached`);
            }

        }).catch(err => {
            console.error("Error finding user for addFavourite:", err);
            reject(`Unable to find user with id: ${id}`);
        });

    });
}

module.exports.removeFavourite = function (id, favId) {
    return new Promise(function (resolve, reject) {
        User.findByIdAndUpdate(id,
            { $pull: { favourites: favId } },
            { new: true }
        ).exec()
            .then(user => {
                if (!user) {
                    reject(`User not found with id: ${id}`);
                    return;
                }
                resolve(user.favourites);
            })
            .catch(err => {
                console.error("Error removing favourite:", err);
                reject(`Unable to update favourites for user with id: ${id}`);
            })
    });
}

module.exports.getHistory = function (id) {
    return new Promise(function (resolve, reject) {

        User.findById(id)
            .exec()
            .then(user => {
                if (!user) {
                    reject(`User not found with id: ${id}`);
                    return;
                }
                resolve(user.history)
            }).catch(err => {
                console.error("Error getting history:", err);
                reject(`Unable to get history for user with id: ${id}`);
            });
    });
}

module.exports.addHistory = function (id, historyId) {

    return new Promise(function (resolve, reject) {

        User.findById(id).exec().then(user => {
            if (!user) {
                reject(`User not found with id: ${id}`);
                return;
            }

            // FIXED: Check history length, not favourites length!
            if (user.history.length < 50) {
                User.findByIdAndUpdate(id,
                    { $addToSet: { history: historyId } },
                    { new: true }
                ).exec()
                    .then(user => { resolve(user.history); })
                    .catch(err => { reject(`Unable to update history for user with id: ${id}`); })
            } else {
                reject(`Unable to update history for user with id: ${id} - limit reached`);
            }
        }).catch(err => {
            console.error("Error finding user for addHistory:", err);
            reject(`Unable to find user with id: ${id}`);
        });
    });
}

module.exports.removeHistory = function (id, historyId) {
    return new Promise(function (resolve, reject) {
        User.findByIdAndUpdate(id,
            { $pull: { history: historyId } },
            { new: true }
        ).exec()
            .then(user => {
                if (!user) {
                    reject(`User not found with id: ${id}`);
                    return;
                }
                resolve(user.history);
            })
            .catch(err => {
                console.error("Error removing history:", err);
                reject(`Unable to update history for user with id: ${id}`);
            })
    });
}