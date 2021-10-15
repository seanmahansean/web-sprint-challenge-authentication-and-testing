const e = require("express")
const Users = require("../auth/auth-model")

async function checkUsernameFree(req, res, next){
  try{
    const users = await Users.findBy({username: req.body.username})
    if(!users.length){
      next()
    }else{
      next({status: 422, message: "username taken"})
    }
  }catch(err){
    next()
  }
}

function checkUserPass(req, res, next){
  try{
    const user = req.body
    if(!user.username || !user.password){
      next({status: 422, message: "username and password required"})
    }else{
      next()
    }
  }catch(err){
    next(err)
  }
}

async function verifyCredentials(req, res, next){
  try{
    const user = await Users.findBy({username: req.body.username})
    const pass = await Users.findBy({password: req.body.password})
    if(!user || !pass){
      next({status: 422, message: "invalid credentials"})
    }else{
      next()
    }
  }catch(err){
    next(err)
  }
}

module.exports = {
  checkUsernameFree,
  checkUserPass,
  verifyCredentials
}
