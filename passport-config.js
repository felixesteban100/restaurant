const bycrypt = require('bcrypt')
const localStrategy = require('passport-local').Strategy

function initialize(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email)
        if (user === null) {
            return done(null, false, { message: 'No hay usuarios con ese email.' })
        }

        try {
            if (await bycrypt.compare(password, user.password)) {
                return done(null, user)
            } else {
                return done(null, false, {message: 'Contraseña incorrecta.'})
            }
        } catch (error) {
            return done(null, false, {message: 'Usuario o contraseña incorrecto.'})
        }

    }
    passport.use(new localStrategy({ usernameField: 'email' }, authenticateUser))
    passport.serializeUser((user, done) => done(null, user.id))
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    })
}

module.exports = initialize