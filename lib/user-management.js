
module.exports = function (options) {
  var seneca = this

  // TODO: should this be in user
  function alias_fields (userData, respond) {
    var data = userData.data
    data.nick =
      data.nick
        ? data.nick
        : data.username
        ? data.username
        : data.email
    return respond(null, data)
  }

  function cmd_register (msg, respond) {
    var seneca = this
    var req = msg.request$
    var res = msg.response$

    seneca.act("role: 'auth', hook: 'map_fields'", {action: 'register', data: msg.args.body}, function (err, details) {
      if (err) return handle_error(err, details, respond)

      seneca.act("role:'user',cmd:'register'", details, function (err, out) {
        if (err || !out.ok) {
          return handle_error(err, out, respond)
        }

        seneca.act("role:'user',cmd:'login'", {nick: out.user.nick, auto: true}, function (err, out) {
          if (err || !out.ok) {
            return handle_error(err, out, respond)
          }

          req.seneca.user = out.user
          req.seneca.login = out.login
          seneca.act("role: 'auth', set: 'token'", {
            tokenkey: options.tokenkey, token: req.seneca.login.id, req: req, res: res
          }, function (err) {
            return handle_error(err, out, respond)
          })
        })
      })
    })

    function handle_error (err, out, done) {
      var err_message = err || out.ok === false ? out.why : null
      return seneca.act('role: auth, do: respond, action: register', {err: err_message, req: req}, done)
    }
  }
  // TODO: Call do_respond to enable redirect
  function cmd_create_reset (msg, respond) {
    seneca.act("role: 'auth', hook: 'map_fields'", {action: 'create_reset', data: msg.args.body}, function (err, userData) {
      if (err) {
        return respond(err, userData)
      }

      var nick = userData.nick
      var email = userData.email

      var args = {}
      if (void 0 !== nick) args.nick = nick
      if (void 0 !== email) args.email = email

      seneca.act("role:'user',cmd:'create_reset'", args, function (err, data) {
        if (data) {
          delete data.reset
          delete data.user
        }
        respond(err, data)
      })
    })
  }
  // TODO: Call do_respond to enable redirect
  function cmd_load_reset (msg, respond) {
    var token = msg.args.body.token

    seneca.act("role:'user',cmd:'load_reset'", {token: token}, function (err, out) {
      if (err || !out.ok) {
        return respond(err, out)
      }

      return respond(null, {
        ok: out.ok,
        active: out.reset.active,
        nick: out.user.nick
      })
    })
  }

  // TODO: Call respond to enable redirect
  function cmd_execute_reset (msg, respond) {
    var token = msg.args.body.token
    var password = msg.args.body.password
    var repeat = msg.args.body.repeat
    seneca.act("role:'user',cmd:'execute_reset'", {token: token, password: password, repeat: repeat}, respond)
  }
  // TODO: Call do_respond to enable redirect
  function cmd_confirm (msg, respond) {
    var code = msg.args.body.code
    seneca.act("role:'user',cmd:'confirm'", {code: code}, respond)
  }

  function cmd_update_user (msg, respond) {
    var req = msg.request$
    seneca.act("role: 'auth', hook: 'map_fields'", {action: 'update', data: msg.args.body}, function (err, userData) {
      if (err) {
        return seneca.act('role: auth, do: respond', {err: err, action: 'update', req: req}, respond)
      }
      seneca.act("role:'user',cmd:'update'", userData, respond)
    })
  }

  function cmd_change_password (msg, respond) {
    var user = msg.user

    seneca.act("role:'user',cmd:'change_password'", {
      user: user || msg.request$.seneca.user,
      password: msg.args.body.password,
      repeat: msg.args.body.repeat
    }, respond)
  }

  function cmd_user (msg, respond) {
    var seneca = this

    var user = msg.user || msg.request$.seneca.user
    var login = msg.login || msg.request$.seneca.login

    if (!user || !login || !login.active) {
      return respond(null, {ok: true})
    }

    seneca.act("role:'auth', cmd:'clean'", {user: user, login: login}, function (err, out) {
      if (err) {
        return respond(err)
      }

      out.ok = true
      out = seneca.util.clean(out)

      return respond(null, out)
    })
  }

  function cmd_clean (msg, respond) {
    var seneca = this

    var user = msg.user && seneca.util.clean(msg.user.data$()) || null
    var login = msg.login && seneca.util.clean(msg.login.data$()) || null

    if (user) {
      delete user.pass
      delete user.salt
      delete user.active
      delete user.accounts
      delete user.confirmcode
      delete user.repeat
    }

    return respond(null, {user: user, login: login})
  }

  seneca.add({role: 'auth', cmd: 'register'}, cmd_register)
  seneca.add({role: 'auth', cmd: 'user'}, cmd_user)
  seneca.add({role: 'auth', cmd: 'instance'}, cmd_user)
  seneca.add({role: 'auth', cmd: 'clean'}, cmd_clean)

  seneca.add({role: 'auth', cmd: 'create_reset'}, cmd_create_reset)
  seneca.add({role: 'auth', cmd: 'load_reset'}, cmd_load_reset)
  seneca.add({role: 'auth', cmd: 'execute_reset'}, cmd_execute_reset)
  seneca.add({role: 'auth', cmd: 'confirm'}, cmd_confirm)

  seneca.add({role: 'auth', cmd: 'update_user'}, cmd_update_user)
  seneca.add({role: 'auth', cmd: 'change_password'}, cmd_change_password)
  seneca.add({role: 'auth', hook: 'map_fields'}, alias_fields)

  return {
    name: 'auth-usermanagement'
  }
}
