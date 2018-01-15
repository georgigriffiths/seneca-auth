module.exports = function () {
  var seneca = this

  function do_respond (msg, next) {
    var err = msg.err
    var action = msg.action
    var forceStatus = msg.forceStatus
    var forceRedirect = msg.forceRedirect
    var req = msg.req

    seneca.log.debug('do_respond', msg.err, msg.action)

    seneca.act('role:auth, cmd: redirect', {kind: action, req: req}, function (errRedirect, redirect) {
      if (err) {
        if (redirect) {
          seneca.log.debug('redirect', 'fail', redirect.fail)
          return next(null, {status: forceStatus || 301, redirect: forceRedirect || redirect.fail})
        }
        return next(null, {status: forceStatus || 200, redirect: forceRedirect, body: {ok: false, why: err}})
      }

      seneca.act('role:auth, cmd:clean', {user: req.seneca.user, login: req.seneca.login}, function (err, out) {
        if (err) {
          seneca.log.error('error ', err)
          return next(err)
        }

        if (redirect || forceRedirect) {
          seneca.log.debug('redirect', 'win', redirect.win)
          return next(null, {status: forceStatus || 301, redirect: forceRedirect || redirect.win})
        }

        out.ok = true
        out.status = forceStatus || 200
        return next(null, out)
      })
    })
  }

  seneca.add({role: 'auth', do: 'respond'}, do_respond)

  return {
    name: 'auth-common'
  }
}
