# hapi-auth-internal

You must register the `findUserByProvider` method in hapi server with server.method and specify the name used to register the method as value of `options.methods.findUserByProvider`

`findUserByProvider` = async(provider, {email, userId}) => {}
  If an user if found (and only 1), this method must return the user data object for jwt
  If more than 1 user found, throw an error.
  return null otherwise (or raise an error)

`resetUserPassword` = async(resetToken, password) => {}
`addUserIfNotExists` = async(resetToken, password) => {}
`addRecoveryToken` = (email) => {}
`sendMail` = async({from, to, subject, text, /* ...*/}) => {}


```js
{
  methods: {
    findUserByProvider: function(provider, {email, userId}) {},
    resetUserPassword: function({ resetToken, password }) {},
    addUserIfNotExists: function({ firstname, lastname, email, password, scope: [] }) {},
    addRecoveryToken: function(email) {},
    sendMail: function({from, to, subject, text, /* ...*/}) {},
  },
  password: {
    saltRounds: 10, // bcrypt options, used to generate salt for password
  },
  domain: {
    front: 'http://localhost:8080',
  },
}
```
