'use strict';
const express=require('express');
function createPostgresAuthRouter(){return express.Router();}
function createLegacyRouter(){const timer=setInterval(()=>{},600000);timer.unref();const router=express.Router();router.close=()=>clearInterval(timer);return router;}
module.exports={createPostgresAuthRouter,createLegacyRouter};
