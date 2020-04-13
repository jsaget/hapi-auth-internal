'use strict'

import Bcrypt from 'bcrypt'
import Boom from '@hapi/boom'
import Joi from '@hapi/joi'



// const options = {
//   methods: {
  // getUserByEmail: () => {},
//     getUserByInternalProvider: function(email) {},
//     resetPassword: function({ resetToken, password }) {},
//     addUserIfNotExists: function({ firstname, lastname, email, password: passwd, scope: [] }) {},
//     addRecoveryToken: function(email) {},
//     mail: {
//       send: function() {},
//     },
//   },
//   password: {
//     saltRounds: 10,
//   },
//   domain: {
//     front: 'http://localhost:8080',
//   },
// }

const register = async (server, options = { saltRounds: 10 }) => {




  server.route({
    method: 'GET',
    path: '/test',
    options: {
      auth: {
        mode: 'try',
        access: {
          scope: false,
        },
      },
      validate: {
        query: Joi.object({
          email: Joi.string().email(),
          password: Joi.string().min(8),
        }),
      },
    },
    handler: async (request, h) => {
      console.log('/test - request.auth', request.auth)
      if (request.auth.isAuthenticated) {
        console.log('Already logged')
        await server.inject({
          method: 'GET',
          url: `/api/v1/auth/revoke-token?tokenId=${request.auth.credentials.jti}`,
          allowInternals: true,
          // auth: {
          //   strategy: 'jwt',
          //   credentials: {
          //     scope: ['auth']
          //   }
          // },
        })
        request.auth.credentials = null
      }

      const { email, password } = request.query

      const user = await options.methods.getUserByInternalProvider(email)
      console.log('login: user', user)
      if (!user) {
        // throw new Error('INVALID_CREDENTIAL')
        return Boom.unauthorized('INVALID_CREDENTIAL')
      }

      if (!(await Bcrypt.compare(password, user.providers.internal.password))) {
        return Boom.unauthorized('INVALID_CREDENTIAL')
      }

      if (user.isActive !== undefined && !user.isActive) {
        // throw new Error('INACTIVE_USER')
        return Boom.unauthorized('INACTIVE_USER')
      }

      // account has validation date
      const currentDate = Date.now()
      if (user.activeAfterDate && user.activeAfterDate < currentDate) {
        // throw new Error('NOT_YET_AVAILABLE_USER')
        return Boom.unauthorized('NOT_YET_AVAILABLE_USER')
      }
      if (user.expirationDate && user.expirationDate > currentDate) {
        // throw new Error('EXPIRED_USER')
        return Boom.unauthorized('EXPIRED_USER')
      }

      console.log('Fetch profile ...')
      const resp = await server.inject({
        method: 'GET',
        url: `/api/v1/auth/profile?provider=internal&email=${email}`,
        allowInternals: true,
        auth: {
          strategy: 'jwt',
          credentials: {
            scope: ['auth']
          }
        },
      })

      if (!resp) {
        return Boom.unauthorized('INVALID_CREDENTIAL')
      }

      console.log('rESP', resp.result)
      const token = resp.result
      console.log('TOKEN', token)
      return h.redirect('/api/v1/auth/attach-provider?mytoken=' + token)
    }
  })










  server.route({
    method: 'POST',
    path: '/signup',
    options: {
      auth: false,
      validate: {
        payload: Joi.object({
          firstname: Joi.string(),
          lastname: Joi.string(),
          email: Joi.string().email(),
          password: Joi.string().min(8),
        }),
      },
    },
    handler: async (request, h) => {
      console.log('Route /signup')
      console.log('request.payload', request.payload)
      const { firstname, lastname, email, password } = request.payload
      console.log('--', options)
      const passwd = await Bcrypt.hash(password, options.password.saltRounds)

      console.log('try to add user')
      await options.methods.addUserIfNotExists({ firstname, lastname, email, scope: ['user'], providers: { internal: {name: 'internal', email, password: passwd }} })
      return h.response({ status: 'OK' }).code(200)
    }
  })

  server.route({
    method: 'POST',
    path: '/login',
    options: {
      auth: {
        mode: 'try',
        access: {
          scope: false,
        },
      },
      validate: {
        payload: Joi.object({
          email: Joi.string().email(),
          password: Joi.string().min(8),
        }),
      },
    },
    handler: async (request, h) => {
      console.log('/login - request.auth', request.auth)
      if (request.auth.isAuthenticated) {
        console.log('Already logged')
        await server.inject({
          method: 'GET',
          url: `/api/v1/auth/revoke-token?tokenId=${request.auth.credentials.jti}`,
          allowInternals: true,
          // auth: {
          //   strategy: 'jwt',
          //   credentials: {
          //     scope: ['auth']
          //   }
          // },
        })
        request.auth.credentials = null
      }

      const { email, password } = request.payload

      const user = await options.methods.getUserByInternalProvider(email)
      console.log('login: user', user)
      if (!user) {
        // throw new Error('INVALID_CREDENTIAL')
        return Boom.unauthorized('INVALID_CREDENTIAL')
      }

      if (!(await Bcrypt.compare(password, user.providers.internal.password))) {
        return Boom.unauthorized('INVALID_CREDENTIAL')
      }

      if (user.isActive !== undefined && !user.isActive) {
        // throw new Error('INACTIVE_USER')
        return Boom.unauthorized('INACTIVE_USER')
      }

      // account has validation date
      const currentDate = Date.now()
      if (user.activeAfterDate && user.activeAfterDate < currentDate) {
        // throw new Error('NOT_YET_AVAILABLE_USER')
        return Boom.unauthorized('NOT_YET_AVAILABLE_USER')
      }
      if (user.expirationDate && user.expirationDate > currentDate) {
        // throw new Error('EXPIRED_USER')
        return Boom.unauthorized('EXPIRED_USER')
      }

      console.log('Fetch profile ...')
      const resp = await server.inject({
        method: 'GET',
        url: `/api/v1/auth/profile?provider=internal&email=${email}`,
        allowInternals: true,
        auth: {
          strategy: 'jwt',
          credentials: {
            scope: ['auth']
          }
        },
      })

      if (!resp) {
        return Boom.unauthorized('INVALID_CREDENTIAL')
      }

      console.log('rESP', resp.result)
      const token = resp.result
      return h.response(token).header('Authorization', 'Bearer: ' + token)
    }
  })

  server.route({
    method: 'GET',
    path: '/logout',
    options: {
      auth: {
        access: {
          scope: false,
        },
      },
    },
    handler: async (request, h) => {
      console.log('/logout #1')
      if (request.auth.isAuthenticated) {
        console.log('/logout #2')
        const credentials = request.auth.credentials
        console.log('/logout #2.1', credentials.jti)
        // jwtExpValidator.removeJwt(credentials.jti)
        await server.inject({
          method: 'GET',
          url: `/api/v1/auth/revoke-token?tokenId=${credentials.jti}`,
          allowInternals: true,
          auth: {
            strategy: 'jwt',
            credentials: {
              scope: ['auth'],
            },
          },
        })

        request.auth.credentials = null
      }
      console.log('/logout #3')
      return h.response({ status: 'ok' })
    }
  })

  server.route({
    method: 'GET',
    path: '/forgotten-password',
    options: {
      auth: false,
      validate: {
        query: Joi.object({
          email: Joi.string().email(),
        }),
      },
    },
    handler: async (request, h) => {
      const email = request.query.email
      const user = await options.methods.getUserByInternalProvider(email)

      if (!user) {
        // return h.response({ status: 'KO', code: 'EMAIL_NOT_FOUND'}).code(400)
        return Boom.notFound('EMAIL_NOT_FOUND')
      }

      const token = await options.methods.addRecoveryToken(email)
      const urlTarget = options.domain.front + '/auth/reset-password?token=' + token

      console.log('URL TARGET', urlTarget)
      await options.methods.mail.send({
        from: 'no-reply@chooseyourself.fr',
        to: email,
        subject: 'Récupération de mot de passe',
        text:
          "Une demande de réinitialisation de mot de passe a été faite pour cette adresse email. Si vous ne l'avez pas fait, nous vous conseillons de changer votre mot de passe, sinon cliquer sur le lien suivant " +
          urlTarget
      })

      return h.response({ status: 'OK' })
    }
  })

  server.route({
    method: 'POST',
    path: '/reset-password',
    options: {
      auth: false,
      validate: {
        payload: Joi.object({
          password: Joi.string(),
          resetToken: Joi.string(),
        }),
      },
    },
    handler: async (request, h) => {
      console.log('/reset-password')
      const { password, resetToken } = request.payload

      console.log('/reset-password', password, resetToken)
      await options.methods.resetPassword({ resetToken, password })

      return h.response({ status: 'OK' })
    }
  })
}

const plugin = {
  name: 'auth-internal',
  version: '1.0.0',
  dependencies: ['auth-jwt'],
  once: true,
  register,
}

export default plugin
