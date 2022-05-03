var mongoose = require('mongoose');
var passport = require('passport');
var config = require('../config/database');
require('../config/passport')(passport);
var express = require('express');
var jwt = require('jsonwebtoken');
var router = express.Router();
var User = require("../models/user");
var Book = require("../models/book");

router.post('/signup', function(req, res) {
    if (!req.body.username || !req.body.password) {
      res.json({success: false, msg: 'Please pass username and password.'});
    } else {
      var newUser = new User({
        username: req.body.username,
        password: req.body.password
      });
      // salvar o usuário
      newUser.save(function(err) {
        if (err) {
          return res.json({success: false, msg: 'Username already exists.'});
        }
        res.json({success: true, msg: 'Successful created new user.'});
      });
    }
  });

  //Rota de login ou sign-in.

  router.post('/signin', function(req, res) {
    User.findOne({
      username: req.body.username
    }, function(err, user) {
      if (err) throw err;
  
      if (!user) {
        res.status(401).send({success: false, msg: 'Falha na Autenticação. Usuário não encontrado.'});
      } else {
        // verificar se a senha está correta
        user.comparePassword(req.body.password, function (err, isMatch) {
          if (isMatch && !err) {
            // Se o usuário e senha estão corretos, cria o token
            var token = jwt.sign(user.toJSON(), config.secret);
            // returna a informação junto com o token como JSON
            res.json({success: true, token: 'JWT ' + token});
          } else {
            res.status(401).send({success: false, msg: 'Falha na Autenticação. Senha incorreta.'});
          }
        });
      }
    });
  });

// Crea a rota para adicionar um novo livro. 
//Rota restrita para usuários autorizados.

router.post('/book', passport.authenticate('jwt', { session: false}), function(req, res) {
    var token = getToken(req.headers);
    if (token) {
      console.log(req.body);
      var newBook = new Book({
        isbn: req.body.isbn,
        title: req.body.title,
        author: req.body.author,
        publisher: req.body.publisher
      });
  
      newBook.save(function(err) {
        if (err) {
          return res.json({success: false, msg: 'Save book failed.'});
        }
        res.json({success: true, msg: 'Successful created new book.'});
      });
    } else {
      return res.status(403).send({success: false, msg: 'Unauthorized.'});
    }
  });

  //Rota para listar os livros. 
  //Rota restrita para usuários autorizados.

  router.get('/book', passport.authenticate('jwt', { session: false}), function(req, res) {
    var token = getToken(req.headers);
    if (token) {
      Book.find(function (err, books) {
        if (err) return next(err);
        res.json(books);
      });
    } else {
      return res.status(403).send({success: false, msg: 'Unauthorized.'});
    }
  });

// Função para analisar o token de autorização dos cabeçalhos de solicitação.

getToken = function (headers) {
    if (headers && headers.authorization) {
      var parted = headers.authorization.split(' ');
      if (parted.length === 2) {
        return parted[1];
      } else {
        return null;
      }
    } else {
      return null;
    }
  };

module.exports = router;