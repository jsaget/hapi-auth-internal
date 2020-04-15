"use strict";

import Bcrypt from "bcrypt";
import Boom from "@hapi/boom";
import Joi from "@hapi/joi";

const schemaOptions = Joi.object({
  methods: Joi.object({
    findUserByProvider: Joi.string().required(),
    resetUserPassword: Joi.string().required(),
    addUserIfNotExists: Joi.string().required(),
    addRecoveryToken: Joi.string().required(),
    sendMail: Joi.string().required(),
  }),
  password: Joi.object({
    saltRounds: Joi.number().required,
  }),
  domain: Joi.object({
    front: Joi.string().uri({ allowRelative: false, scheme: /https?/ }),
  }),
});

const register = async (server, options) => {
  schemaOptions.validate(options);

  // use to test the add provider
  // server.route({
  //   method: 'GET',
  //   path: '/test',
  //   options: {
  //     auth: {
  //       mode: 'try',
  //       access: {
  //         scope: false,
  //       },
  //     },
  //     validate: {
  //       query: Joi.object({
  //         email: Joi.string().email(),
  //         password: Joi.string().min(8),
  //       }),
  //     },
  //   },
  //   handler: async (request, h) => {
  //     console.log('/test - request.auth', request.auth)
  //     if (request.auth.isAuthenticated) {
  //       console.log('Already logged')
  //       await server.inject({
  //         method: 'GET',
  //         url: `/api/v1/auth/revoke-token?tokenId=${request.auth.credentials.jti}`,
  //         allowInternals: true,
  //         auth: {
  //           strategy: 'jwt',
  //           credentials: {
  //             scope: ['auth']
  //           }
  //         },
  //       })
  //       request.auth.credentials = null
  //     }

  //     const { email, password } = request.query
  //     const user = await options.methods.findUserByProvider('internal', {email})

  //     console.log('login: user', user)
  //     if (!user) {
  //       // throw new Error('INVALID_CREDENTIAL')
  //       return Boom.unauthorized('INVALID_CREDENTIAL')
  //     }

  //     if (!(await Bcrypt.compare(password, user.providers.internal.password))) {
  //       return Boom.unauthorized('INVALID_CREDENTIAL')
  //     }

  //     console.log('Fetch profile ...')
  //     const resp = await server.inject({
  //       method: 'GET',
  //       url: `/api/v1/auth/profile?provider=internal&email=${email}`,
  //       allowInternals: true,
  //       auth: {
  //         strategy: 'jwt',
  //         credentials: {
  //           scope: ['auth']
  //         }
  //       },
  //     })

  //     if (!resp) {
  //       return Boom.unauthorized('INVALID_CREDENTIAL')
  //     }

  //     console.log('rESP', resp.result)
  //     const token = resp.result
  //     console.log('TOKEN', token)
  //     return h.redirect('/api/v1/auth/attach-provider?mytoken=' + token)
  //   }
  // })

  server.route({
    method: "POST",
    path: "/signup",
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
      const { firstname, lastname, email, password } = request.payload;
      const passwd = await Bcrypt.hash(password, options.password.saltRounds);

      await server.methods[options.methods.addUserIfNotExists]({
        firstname,
        lastname,
        email,
        scope: ["user"],
        providers: { internal: { name: "internal", email, password: passwd } },
      });
      return h.response({ status: "OK" }).code(200);
    },
  });

  server.route({
    method: "POST",
    path: "/login",
    options: {
      auth: {
        mode: "try",
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
      console.log("/login - request.auth", request.auth);
      if (request.auth.isAuthenticated) {
        console.log("Already logged");
        await server.inject({
          method: "GET",
          url: `/api/v1/auth/revoke-token?tokenId=${request.auth.credentials.jti}`,
          allowInternals: true,
          auth: {
            strategy: "jwt",
            credentials: {
              scope: ["auth"],
            },
          },
        })
        request.auth.credentials = null
      }

      const { email, password } = request.payload
      const user = await server.methods[options.methods.findUserByProvider]("internal", { email })

      if (!user) {
        return Boom.unauthorized("INVALID_CREDENTIAL")
      }

      if (!(await Bcrypt.compare(password, user.providers.internal.password))) {
        return Boom.unauthorized("INVALID_CREDENTIAL")
      }

      const resp = await server.inject({
        method: "GET",
        url: `/api/v1/auth/profile?provider=internal&email=${email}`,
        allowInternals: true,
        auth: {
          strategy: "jwt",
          credentials: {
            scope: ["auth"],
          },
        },
      })

      if (!resp) {
        return Boom.unauthorized("INVALID_CREDENTIAL")
      }

      const token = resp.result;
      return h.response(token).header("Authorization", "Bearer: " + token)
    },
  })

  server.route({
    method: "GET",
    path: "/logout",
    options: {
      auth: {
        access: {
          scope: false,
        },
      },
    },
    handler: async (request, h) => {
      if (request.auth.isAuthenticated) {
        const credentials = request.auth.credentials
        await server.inject({
          method: "GET",
          url: `/api/v1/auth/revoke-token?tokenId=${credentials.jti}`,
          allowInternals: true,
          auth: {
            strategy: "jwt",
            credentials: {
              scope: ["auth"],
            },
          },
        })

        request.auth.credentials = null
      }

      return h.response({ status: "ok" })
    },
  })

  server.route({
    method: "GET",
    path: "/forgotten-password",
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
      const user = await server.methods[options.methods.findUserByProvider]("internal", { email })

      if (!user) {
        return Boom.notFound("EMAIL_NOT_FOUND")
      }

      const token = await server.methods[options.methods.addRecoveryToken](email)
      const urlTarget = options.domain.front + "/auth/reset-password?token=" + token

      await server.methods[options.methods.sendMail]({
        from: "no-reply@chooseyourself.fr",
        to: email,
        subject: "Récupération de mot de passe",
        text:
          "Une demande de réinitialisation de mot de passe a été faite pour cette adresse email. Si vous ne l'avez pas fait, nous vous conseillons de changer votre mot de passe, sinon cliquer sur le lien suivant " + urlTarget,
      })

      return h.response({ status: "OK" })
    },
  })

  server.route({
    method: "POST",
    path: "/reset-password",
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
      const { password, resetToken } = request.payload
      await server.methods[options.methods.resetUserPassword]({
        resetToken,
        password,
      })

      return h.response({ status: "OK" })
    },
  })
}

const plugin = {
  name: "hapi-auth-internal",
  version: "1.0.0",
  dependencies: ["hapi-auth-jwt"],
  once: true,
  register,
};

export default plugin;
