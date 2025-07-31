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
    if (isConnected) return;

    try {
        // Connect using mongoose.connect (recommended)
        await mongoose.connect(mongoDBConnectionString, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        // Initialize the User model once connected
        User = mongoose.model("users", userSchema);

        isConnected = true;
    } catch (err) {
        throw err;
    }
};

module.exports.registerUser = function (userData) {
    return new Promise(function (resolve, reject) {

        if (userData.password != userData.password2) {
            reject("Passwords do not match");
        } else {

            bcrypt.hash(userData.password, 10).then(hash => {

                userData.password = hash;

                let newUser = new User(userData);

                newUser.save().then(() => {
                    resolve("User " + userData.userName + " successfully registered");  
                }).catch(err => {
                    if (err.code == 11000) {
                        reject("User Name already taken");
                    } else {
                        reject("There was an error creating the user: " + err);
                    }
                })
            }).catch(err => reject(err));
        }
    });
};

module.exports.checkUser = function (userData) {
    return new Promise(function (resolve, reject) {

        User.findOne({ userName: userData.userName })
            .exec()
            .then(user => {
                bcrypt.compare(userData.password, user.password).then(res => {
                    if (res === true) {
                        resolve(user);
                    } else {
                        reject("Incorrect password for user " + userData.userName);
                    }
                });
            }).catch(err => {
                reject("Unable to find user " + userData.userName);
            });
    });
};

module.exports.getFavourites = function (id) {
    return new Promise(function (resolve, reject) {

        User.findById(id)
            .exec()
            .then(user => {
                resolve(user.favourites)
            }).catch(err => {
                reject(`Unable to get favourites for user with id: ${id}`);
            });
    });
}

module.exports.addFavourite = function (id, favId) {

    return new Promise(function (resolve, reject) {

        User.findById(id).exec().then(user => {
            if (user.favourites.length < 50) {
                User.findByIdAndUpdate(id,
                    { $addToSet: { favourites: favId } },
                    { new: true }
                ).exec()
                    .then(user => { resolve(user.favourites); })
                    .catch(err => { reject(`Unable to update favourites for user with id: ${id}`); })
            } else {
                reject(`Unable to update favourites for user with id: ${id}`);
            }

        })

    });


}

module.exports.removeFavourite = function (id, favId) {
    return new Promise(function (resolve, reject) {
        User.findByIdAndUpdate(id,
            { $pull: { favourites: favId } },
            { new: true }
        ).exec()
            .then(user => {
                resolve(user.favourites);
            })
            .catch(err => {
                reject(`Unable to update favourites for user with id: ${id}`);
            })
    });
}

module.exports.getHistory = function (id) {
    return new Promise(function (resolve, reject) {

        User.findById(id)
            .exec()
            .then(user => {
                resolve(user.history)
            }).catch(err => {
                reject(`Unable to get history for user with id: ${id}`);
            });
    });
}

module.exports.addHistory = function (id, historyId) {

    return new Promise(function (resolve, reject) {

        User.findById(id).exec().then(user => {
            if (user.favourites.length < 50) {
                User.findByIdAndUpdate(id,
                    { $addToSet: { history: historyId } },
                    { new: true }
                ).exec()
                    .then(user => { resolve(user.history); })
                    .catch(err => { reject(`Unable to update history for user with id: ${id}`); })
            } else {
                reject(`Unable to update history for user with id: ${id}`);
            }
        })
    });
}

module.exports.removeHistory = function (id, historyId) {
    return new Promise(function (resolve, reject) {
        User.findByIdAndUpdate(id,
            { $pull: { history: historyId } },
            { new: true }
        ).exec()
            .then(user => {
                resolve(user.history);
            })
            .catch(err => {
                reject(`Unable to update history for user with id: ${id}`);
            })
    });
}