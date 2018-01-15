var Assert = require('assert')
var _ = require('lodash')

exports.init = function (options, cb) {
  var agent
  var request = require('supertest')
  var express = require('express')
  var bodyparser = require('body-parser')

  var si = require('seneca')({ log: 'silent' })

  si.use('basic')

  si.use('entity')

  var app = express()
  app.use(bodyparser.json())

  si.use('web', {
    context: app,
    adapter: require('seneca-web-adapter-express'),
    options: {parseBody: false}
  })
  agent = request(app)

  si.ready(function (err) {
    if (err) {
      return process.exit(!console.error(err))
    }

    si.use('mem-store', {web: {
      dump: false
    }})
    si.use('user')
    si.use(require('..'), _.extend({secure: true, restrict: '/api'}, options || {}))

    si.ready(function (err) {
      if (err) {
        return process.exit(!console.error(err))
      }
      si.add({role: 'test', cmd: 'service'}, function (args, cb) {
        return cb(null, {ok: true, test: true})
      })
      si.add({role: 'test', cmd: 'service2'}, function (args, cb) {
        return cb(null, {ok: true, test: true})
      })
      si.act({
        role: 'web',
        plugin: 'test',
        routes: {
          prefix: '/api',
          pin: 'role:test,cmd:*',
          map: {
            service: {GET: true},
            service2: {GET: true}
          }
        }
      })

      cb(null, agent, si)
    })
  })
}

exports.log = function (res) {
  // uncomment next lines for logging of req/responses
  // console.log('\n****************************************')
  // console.log('REQUEST URL : ', JSON.stringify(res.req.path))
  // console.log('REQUEST     : ', JSON.stringify(res))
  // console.log('STATUS      : ', JSON.stringify(res.status))
  // console.log('RESPONSE    : ', JSON.stringify(res.text))
  // console.log('****************************************')
  return
}

exports.checkCookie = function (res) {
  for (var i in res.header['set-cookie']) {
    if (res.header['set-cookie'][i].indexOf('seneca-login') === 0) {
      return res.header['set-cookie'][i].match(/seneca-login=(.*); path/)[1]
    }
  }
  throw new Error('missing seneca-login cookie')
}

exports.checkHeader = function (res) {
  Assert(res.header['x-auth-token'])
  return res.header['x-auth-token']
}
