'use strict';
// Trusted rehearsal code: forbid model/installed service sockets in all Node children.
const endpoint=new URL(process.env.PG_ADMIN_DATABASE_URL);
if(endpoint.protocol!=='postgresql:'||endpoint.hostname!=='127.0.0.1'||!/^\d+$/.test(endpoint.port))throw Error('REHEARSAL_NETWORK_CONFIGURATION');
const port=Number(endpoint.port),net=require('node:net'),connect=net.Socket.prototype.connect;
const {allowedDatabaseConnect}=require('../../tests/fixtures/fullBackendBootControls');
net.Socket.prototype.connect=function(...args){if(!allowedDatabaseConnect(args,{host:'127.0.0.1',port}))throw Error('REHEARSAL_NETWORK_DENIED');return connect.apply(this,args);};
global.fetch=async()=>{throw Error('REHEARSAL_PROVIDER_DENIED');};
