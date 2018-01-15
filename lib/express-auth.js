// External modules.
var _ = require('lodash')
var Passport = require('passport')

module.exports = function (options) {
  var seneca = this

  Passport.serializeUser(function (user, done) {
    done(null, user.user.id)
  })

  Passport.deserializeUser(function (id, done) {
    done(null)
  })

  function cmd_register_service (msg, respond) {
    seneca.log.info('registering auth service [' + msg.service + ']')
    Passport.use(msg.service, msg.plugin)
    registerService(msg.service, msg.conf)
    respond()
  }

  function registerService (service, conf) {
    seneca.add({role: 'auth', cmd: 'auth-' + service}, _blank_responder)
    seneca.add({role: 'auth', cmd: 'auth-' + service + '-callback'}, _blank_responder)

    var map = {}
    map['auth-' + service] = {GET: true, POST: true, name: service}
    map['auth-' + service + '-callback'] = {GET: true, POST: true, name: service + '/callback'}

    var middleware = configure_services(service, conf)
    seneca.act(
      'role:web',
      {
        routes: {
          prefix: options.prefix,
          pin: 'role:auth,cmd:*',
          middleware: middleware,
          map: map
        }
      })
    seneca.add({role: 'auth', trigger: 'service-login-' + service}, trigger_service_login)
  }

  function configure_services (service, conf) {
    conf = conf || {}
    var func = null
    return function (req, res, next) {
      if (service !== 'local') {
        func = function (err, user, info) {
          if (err) {
            return afterlogin(err, next)
          }
          seneca.act('role: auth, trigger: service-login-' + service, {service: service, user: user},
            function (err, user) {
              if (err) {
                return afterlogin(err, next)
              }
              seneca.act('role: user, cmd: login', {nick: user.nick, auto: true}, function (err, out) {
                if (!out.ok) return afterlogin(out.why, next)
                afterlogin(err, next, req, res)
              })
            }
          )
        }
      }

      Passport.authenticate(service, conf, func)(req, res, next)
    }
  }

  function buildservice () {
    var pp_init = Passport.initialize()

    function init_session (req, res, done) {
      seneca.act('role:auth,get:token', {req: req, res: res, tokenkey: options.tokenkey}, function (err, result) {
        if (err) return done(err)

        var token
        if (result) {
          token = result.token
        }

        if (token) {
          seneca.act('role:user,cmd:auth', {token: token}, function (err, out) {
            if (err) return done(err)

            if (out.ok) {
              if (!req.seneca) req.seneca = {}
              req.seneca.user = out.user
              req.seneca.login = out.login
              return done()
            }
            else {
              // dead login - get rid of the token
              seneca.act('role:auth,set:token', {req: req, res: res, tokenkey: options.tokenkey}, function () {
                return done()
              })
            }
          })
        }
        else {
          return done()
        }
      })
    }

    var restriction = (function () {
      if (_.isFunction(options.restrict)) return options.restrict

      return function (req, res, next) {
        for (var cI = 0; cI < checks.length; cI++) {
          var restrict = checks[cI](req)
          if (restrict && !req.user) {
            seneca.act('role: auth, cmd: redirect', {kind: req.url, req: req}, function (err, redirect) {
              if (err) {
                req.seneca.log.error('error ', err)
                return next(true)
              }

              if (redirect) {
                return next(null, {status: 302, redirect: options.redirect.restrict})
              }
              else {
                return next(null, {status: 401, body: {ok: false, why: 'restricted'}})
              }
            })
            break
          }
        }
        if (cI === checks.length) {
          next()
        }
      }
    })()

    return function (req, res, next) {
      if (exclude_url(req) && !include_url(req)) {
        return next()
      }
      if (!seneca.export('web/context')()) {
        return next('Cannot process, seneca-web dependency problem')
      }
      req.seneca = {}
      res.seneca = {}
      pp_init(req, res, function (err) {
        if (err) {
          return next(err)
        }

        init_session(req, res, function (err) {
          if (err) {
            return next(err)
          }

          restriction(req, res, next)
        })
      })
    }
  }

  // LOGIN START
  function afterlogin (err, next, req, res) {
    if (err) {
      return seneca.act('role: auth, do: respond', {err: err, action: 'login', req: req}, next)
    }

    if (req.user && req.user.ok) {
      req.seneca = req.seneca || {}
      req.seneca.user = req.user.user
      req.seneca.login = req.user.login

      seneca.act("role: 'auth', set: 'token'", {
        tokenkey: options.tokenkey, token: req.seneca.login.id, req: req, res: res
      }, function (err) {
        return seneca.act('role: auth, do: respond', {err: err, action: 'login', req: req}, next)
      })
    }
    else {
      seneca.act('role: auth, do: respond', {err: (req.user ? req.user.why : 'Unknown error'), action: 'login', req: req}, next)
    }
  }

  function cmd_login (msg, respond) {
    var req = msg.request$
    var res = msg.response$

    req.query = _.extend({}, req.query || {}, req.body || {})

    seneca.act("role: 'auth', hook: 'map_fields'", {action: 'login', data: msg.args.body}, function (err, userData) {
      if (err) {
        seneca.log.error('error ', err)
        // handle error
      }

      req.query.username =
        req.query.username
          ? req.query.username
          : (
          req.query.nick
            ? req.query.nick
            : (
            userData.username
              ? userData.username
              : userData.email
          )
        )

      Passport.authenticate('local')(req, res, function (loginerr, out) {
        seneca.act('role: auth, restrict: login', function (err, out) {
          if (loginerr || err || !(out && out.ok)) {
            seneca.act('role: auth, do: respond', {err: (loginerr || err || (out && out.why)), action: 'login', req: req}, respond)
          }
          else {
            afterlogin(err, respond, req, res)
          }
        })
      })
    })
  }

  // LOGIN END

  // LOGOUT START
  function cmd_logout (msg, respond) {
    var req = msg.request$
    var res = msg.response$

    // get token from request
    seneca.act("role: 'auth', get: 'token'", {tokenkey: options.tokenkey, req: req, res: res}, function (err, clienttoken) {
      if (err) {
        return seneca.act('role: auth, do: respond', {err: err, action: 'logout', req: req}, respond)
      }

      clienttoken = clienttoken.token
      // delete token
      seneca.act("role: 'auth', set: 'token'", {tokenkey: options.tokenkey, req: req, res: res}, function (err) {
        if (err) {
          return seneca.act('role: auth, do: respond', {err: err, action: 'logout', req: req}, respond)
        }

        var servertoken
        if (req.seneca) {
          servertoken = req.seneca.login && req.seneca.login.token
          delete req.seneca.user
          delete req.seneca.login
        }

        var token = clienttoken || servertoken || ''
        seneca.act("role:'user',cmd:'logout'", {token: token}, function (err) {
          if (err) {
            seneca.log('error ', err)

            return seneca.act('role: auth, do: respond', {err: err, action: 'logout', req: req}, respond)
          }

          try {
            req.logout()
          }
          catch (err) {
            seneca.log('error ', err)
            return seneca.act('role: auth, do: respond', {err: err, action: 'logout', req: req}, respond)
          }

          return seneca.act('role: auth, do: respond', {err: err, action: 'logout', req: req}, respond)
        })
      })
    })
  }
  // LOGOUT END

  // default service login trigger
  function trigger_service_login (msg, respond) {
    var seneca = this

    if (!msg.user) {
      return respond(null, {ok: false, why: 'no-user'})
    }

    var user_data = msg.user
    var q = {}
    if (user_data.identifier) {
      q[msg.service + '_id'] = user_data.identifier
      user_data[msg.service + '_id'] = user_data.identifier
    }
    else {
      return respond(null, {ok: false, why: 'no-identifier'})
    }

    seneca.act("role: 'user', get: 'user'", q, function (err, data) {
      if (err) return respond(null, {ok: false, why: 'no-identifier'})

      if (!data.ok) return respond(null, {ok: false, why: data.why})

      var user = data.user
      if (!user) {
        seneca.act("role:'user',cmd:'register'", user_data, function (err, out) {
          if (err) {
            return respond(null, {ok: false, why: err})
          }

          respond(null, out.user)
        })
      }
      else {
        seneca.act("role:'user',cmd:'update'", user_data, function (err, out) {
          if (err) {
            return respond(null, {ok: false, why: err})
          }

          respond(null, out.user)
        })
      }
    })
  }


  seneca.add({role: 'auth', cmd: 'login'}, cmd_login)
  seneca.add({role: 'auth', cmd: 'logout'}, cmd_logout)
  seneca.add({role: 'auth', cmd: 'register_service'},
    cmd_register_service)

  function _blank_responder (err, out) {
    out(err)
  }

  // function authcontext (req, res, msg, act, respond) {
  //   var user = req.seneca && req.seneca.user
  //   if (user) {
  //     msg.user = user
  //   }

  //   var login = req.seneca && req.seneca.login
  //   if (login) {
  //     msg.login = login
  //   }

  //   act(msg, function (err, out) {
  //     if (err) {
  //       seneca.log.debug(err)
  //       out = out || {}

  //       return respond(null, out)
  //     }

  //     return respond(null, out)
  //   })
  // }

  function checkurl (match, done) {
    seneca.act("role:'auth',cmd: 'urlmatcher'", {spec: match}, function (err, checks) {
      if (err) return done(err)

      return done(null, function (req) {
        for (var i = 0; i < checks.length; i++) {
          if (checks[i](req)) {
            return true
          }
        }
        return false
      })
    })
  }

  var exclude_url
  checkurl(options.exclude, function (err, response) {
    if (err) return

    exclude_url = response
  })

  var include_url
  checkurl(options.include, function (err, response) {
    if (err) return

    include_url = response
  })

  var checks
  if (!_.isFunction(options.restrict)) {
    seneca.act("role:'auth', cmd: 'urlmatcher'", {spec: options.restrict}, function (err, result) {
      if (!err) {
        checks = result
      }
    })
  }

  function init (args, done) {
    seneca.add('role: auth, cmd: login', cmd_login)
    seneca.add('role: auth, cmd: logout', cmd_logout)
    seneca.add({role: 'auth', cmd: 'register_service'},
      cmd_register_service)

    var context = seneca.export('web/context')()
    context.use(buildservice())

    var mapping = {
      login: {POST: true, GET: true},
      logout: {POST: true, GET: true},
      register: {POST: true},
      instance: {GET: true}, // this is deprecated - use user instead
      create_reset: {POST: true},
      load_reset: {POST: true},
      execute_reset: {POST: true},
      confirm: {POST: true},
      update_user: {POST: true},
      user: {GET: true},
      change_password: {POST: true}
    }

    _.each(mapping, (value, key) => {
      mapping[key].name = options.urlpath[key]
    })

    seneca.act(
      'role:web',
      {
        routes: {
          prefix: options.prefix,
          pin: 'role:auth,cmd:*',
          map: mapping
        }
      })


    done()
  }

  seneca.add('init: express-auth-plugin', init)

  seneca.add('role: auth, restrict: login', function (args, done) {
    done(null, {ok: true, why: 'no-restrict'})
  })


  return {
    name: 'express-auth-plugin'
  }
}
