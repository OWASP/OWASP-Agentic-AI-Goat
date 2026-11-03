import React,{useCallback,useEffect,useMemo,useRef,useState} from 'react';
import axios from 'axios';
import LegacyFileSsiWorkshop from './LegacyFileSsiWorkshop';
import {createLegacyFileSsiController} from '../../utils/legacyFileSsiController.mjs';
import {useAuth} from '../../context/AuthContext';
import {useWorkshopConfig} from '../../context/WorkshopConfigContext';
// Staged route component; axios uses the application's canonical bearer interceptor.
export default function LegacyFileSsiWorkshopPage(){
 const {user}=useAuth();
 const {registerReconciler}=useWorkshopConfig();
 const readToken=()=>{try{return localStorage.getItem('token')||'';}catch{return null;}};
 const token=readToken()??'';
 const sessionKey=`${user?.id??'anonymous'}:${token}`;
 const controller=useMemo(()=>{
  const headers=token?{Authorization:`Bearer ${token}`}:{};
  const pinned={
   get:(url,config={})=>axios.get(url,{...config,headers:{...(config.headers||{}),...headers}}),
   post:(url,data,config={})=>axios.post(url,data,{...config,headers:{...(config.headers||{}),...headers}}),
  };
  return createLegacyFileSsiController({http:pinned});
 },[sessionKey,token]);
 const [snapshot,setSnapshot]=useState(null),[snapshotSessionKey,setSnapshotSessionKey]=useState(''),[error,setError]=useState(''),[errorSessionKey,setErrorSessionKey]=useState('');
 const scopeRef=useRef(null);
 const identityRef=useRef(sessionKey);identityRef.current=sessionKey;
 const isCurrent=scope=>scopeRef.current===scope&&scope.mounted&&scope.controller===controller&&Boolean(scope.token)&&identityRef.current===scope.sessionKey&&readToken()===scope.token;
 const refresh=useCallback(async({background=false,signal}={})=>{
  const scope=scopeRef.current;
  if(!scope||!isCurrent(scope)) return false;
  const noAck=()=>{if(background&&isCurrent(scope))throw new Error('File and SSI revision refresh was superseded');return false;};
  if(signal?.aborted)return noAck();
  if(scope.mutationBusy){if(background)throw new Error('File and SSI revision refresh overlaps a mutation');return false;}
  scope.refreshController?.abort();
  const requestController=new AbortController();
  const forwardAbort=()=>requestController.abort();
  signal?.addEventListener?.('abort',forwardAbort,{once:true});
  if(signal?.aborted)forwardAbort();
  scope.refreshController=requestController;
  const epoch=++scope.refreshEpoch;
  try{
   const next=await controller.snapshot({signal:requestController.signal});
   if(!isCurrent(scope)||scope.refreshEpoch!==epoch||requestController.signal.aborted)return noAck();
   setSnapshot(next);setSnapshotSessionKey(scope.sessionKey);setError('');setErrorSessionKey('');return true;
  }catch(e){
   if(!isCurrent(scope)||scope.refreshEpoch!==epoch||requestController.signal.aborted)return noAck();
   if(!background){setSnapshot(null);setSnapshotSessionKey('');}
   setError(background?'File and SSI workshop could not be refreshed. Showing the last known state.':'File and SSI workshop is unavailable.');
   setErrorSessionKey(scope.sessionKey);throw e;
  }finally{signal?.removeEventListener?.('abort',forwardAbort);if(scope.refreshController===requestController)scope.refreshController=null;}
 },[controller]);
 const runAttempt=useCallback(async args=>{
  const scope=scopeRef.current;
  if(!scope||!isCurrent(scope))throw Object.assign(new Error('Retired File and SSI session'),{code:'LEGACY_FILE_SSI_RETIRED'});
  if(scope.mutationBusy)throw Object.assign(new Error('File and SSI operation is already in progress'),{code:'LEGACY_FILE_SSI_MUTATION_BUSY'});
  scope.mutationBusy=true;
  scope.refreshController?.abort();++scope.refreshEpoch;
  const requestController=new AbortController();scope.requests.add(requestController);
  try{
   const result=await controller.attempt({...args,signal:requestController.signal});
   if(!isCurrent(scope)||requestController.signal.aborted)throw Object.assign(new Error('Retired File and SSI session'),{code:'LEGACY_FILE_SSI_RETIRED'});
   return result;
  }finally{scope.requests.delete(requestController);scope.mutationBusy=false;}
 },[controller]);
 const runReset=useCallback(async()=>{
  const scope=scopeRef.current;
  if(!scope||!isCurrent(scope))throw Object.assign(new Error('Retired File and SSI session'),{code:'LEGACY_FILE_SSI_RETIRED'});
  if(scope.mutationBusy)throw Object.assign(new Error('File and SSI operation is already in progress'),{code:'LEGACY_FILE_SSI_MUTATION_BUSY'});
  scope.mutationBusy=true;
  scope.refreshController?.abort();++scope.refreshEpoch;
  const requestController=new AbortController();scope.requests.add(requestController);
  try{
   const result=await controller.reset({signal:requestController.signal});
   if(!isCurrent(scope)||requestController.signal.aborted)throw Object.assign(new Error('Retired File and SSI session'),{code:'LEGACY_FILE_SSI_RETIRED'});
   return result;
  }finally{scope.requests.delete(requestController);scope.mutationBusy=false;}
 },[controller]);
 const runModeChange=useCallback(async mode=>{
  const scope=scopeRef.current;
  if(!scope||!isCurrent(scope))throw Object.assign(new Error('Retired File and SSI session'),{code:'LEGACY_FILE_SSI_RETIRED'});
  if(scope.mutationBusy)throw Object.assign(new Error('File and SSI operation is already in progress'),{code:'LEGACY_FILE_SSI_MUTATION_BUSY'});
  scope.mutationBusy=true;
  scope.refreshController?.abort();++scope.refreshEpoch;
  const requestController=new AbortController();scope.requests.add(requestController);
  try{
   const result=await controller.setMode({mode,signal:requestController.signal});
   if(!isCurrent(scope)||requestController.signal.aborted)throw Object.assign(new Error('Retired File and SSI session'),{code:'LEGACY_FILE_SSI_RETIRED'});
   return result;
  }finally{scope.requests.delete(requestController);scope.mutationBusy=false;}
 },[controller]);
 useEffect(()=>{
  const scope={controller,sessionKey,token,mounted:true,refreshEpoch:0,refreshController:null,requests:new Set(),mutationBusy:false};scopeRef.current=scope;
  refresh().catch(()=>{});
  return()=>{scope.mounted=false;scope.refreshController?.abort();for(const request of scope.requests)request.abort();scope.requests.clear();if(scopeRef.current===scope)scopeRef.current=null;};
 },[controller,sessionKey,refresh]);
 useEffect(()=>registerReconciler((_revision,{signal}={})=>refresh({background:true,signal})),[registerReconciler,refresh]);
 const visibleSnapshot=snapshotSessionKey===sessionKey?snapshot:null;
 const visibleError=errorSessionKey===sessionKey?error:'';
 return <LegacyFileSsiWorkshop key={sessionKey} loading={!visibleSnapshot&&!visibleError} pageError={visibleError} snapshot={visibleSnapshot} onAttempt={runAttempt} onReset={runReset} onModeChange={runModeChange} onRefresh={refresh}/>;
}
