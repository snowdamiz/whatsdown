import { createServer } from 'node:http';

export function createIpLimiter({now=Date.now,capacity=6,perMinute=6,maxClients=4096}={}) {
  for(const value of [capacity,perMinute,maxClients])if(!Number.isSafeInteger(value)||value<1||value>65536)throw new Error('Invalid relay rate limit');
  const clients=new Map();let clock=0;
  const refill=(entry,time)=>Math.min(capacity,entry.tokens+(time-entry.at)*perMinute/60000);
  return Object.freeze({take(ip) {
    const time=now();if(!Number.isSafeInteger(time)||time<clock)return false;clock=time;
    let entry=clients.get(ip);
    if(!entry) {
      if(clients.size>=maxClients)for(const [key,value] of clients)if(refill(value,time)===capacity)clients.delete(key);
      if(clients.size>=maxClients)return false;
      entry={tokens:capacity,at:time};clients.set(ip,entry);
    }
    entry.tokens=refill(entry,time);entry.at=time;
    if(entry.tokens<1)return false;entry.tokens--;return true;
  }});
}

function receive(request,timeoutMs) {
  return new Promise((resolve,reject)=>{
    const chunks=[];let size=0;
    const finish=(error,value)=>{
      clearTimeout(timer);request.off('data',data);request.off('end',end);request.off('aborted',abort);request.off('error',abort);
      if(error){request.pause();reject(error);}else resolve(value);
    };
    const data=chunk=>{size+=chunk.length;if(size>8192)finish(413);else chunks.push(chunk);};
    const end=()=>finish(size?null:400,Buffer.concat(chunks));
    const abort=()=>finish(400);
    const timer=setTimeout(()=>finish(408),timeoutMs);
    request.on('data',data);request.once('end',end);request.once('aborted',abort);request.once('error',abort);
  });
}

// Terminate TLS at the operator's edge. IPs come only from the socket; forwarded
// headers are never trusted. A reverse proxy must also enforce per-client limits
// at its public boundary, since all proxied traffic shares its socket identity.
export function createRelayHttpServer({submit,limiter=createIpLimiter(),maxInFlight=16,bodyTimeoutMs=5000,admissionTimeoutMs=60000}) {
  if(typeof submit!=='function'||!Number.isSafeInteger(maxInFlight)||maxInFlight<1||maxInFlight>64||
    !Number.isSafeInteger(bodyTimeoutMs)||bodyTimeoutMs<1||bodyTimeoutMs>10000||
    !Number.isSafeInteger(admissionTimeoutMs)||admissionTimeoutMs<1||admissionTimeoutMs>60000)throw new Error('Invalid relay HTTP configuration');
  let inFlight=0;
  const server=createServer({maxHeaderSize:8192,headersTimeout:5000,requestTimeout:10000,keepAliveTimeout:1000,connectionsCheckingInterval:1000},async(request,response)=>{
    request.on('error',()=>{});
    const send=(status,value)=>{
      if(response.destroyed||response.writableEnded)return;
      const body=Buffer.from(JSON.stringify(value));
      response.writeHead(status,{'Content-Type':'application/json','Content-Length':body.length,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
        ...(status>=400?{Connection:'close'}:{}),...(status===429?{'Retry-After':'60'}:{}),...(status===405?{Allow:'POST'}:{})});response.end(body);
    };
    if(request.url!=='/v1/fork-evidence'){send(404,{error:'not_found'});return;}
    if(request.method!=='POST'){send(405,{error:'method_not_allowed'});return;}
    if(!limiter.take(request.socket.remoteAddress??'unknown')){send(429,{error:'rate_limited'});return;}
    if(inFlight>=maxInFlight){send(503,{error:'busy'});return;}
    if(request.headers['content-type']?.trim().toLowerCase()!=='application/octet-stream'||
      (request.headers['content-encoding']!==undefined&&request.headers['content-encoding']!=='identity')){send(415,{error:'binary_evidence_required'});return;}
    const length=request.headers['content-length'];
    if(length!==undefined&&(!/^\d+$/.test(length)||BigInt(length)>8192n)){send(413,{error:'evidence_too_large'});return;}
    const controller=new AbortController();const disconnect=()=>{if(!response.writableFinished)controller.abort();};
    response.once('close',disconnect);inFlight++;
    let deadline;
    try{
      const bytes=await receive(request,bodyTimeoutMs);
      const result=await Promise.race([submit(bytes,{signal:controller.signal}),new Promise((_,reject)=>{
        deadline=setTimeout(()=>{controller.abort();reject(new Error('admission timeout'));},admissionTimeoutMs);
      })]);
      send(result.status==='settled'?200:202,result);
    }catch(error){
      const code=[400,408,413].includes(error)?error:503;
      send(code,{error:code===503?'admission_unavailable':code===413?'evidence_too_large':code===408?'body_timeout':'invalid_body'});
    }finally{clearTimeout(deadline);response.off('close',disconnect);inFlight--;}
  });
  server.maxConnections=64;server.maxRequestsPerSocket=32;
  return server;
}
