import { NextRequest, NextResponse } from 'next/server';
import { ObjectId } from 'mongodb';
import { requireBusinessAdmin } from '@/lib/auth';
import { getDb } from '@/lib/mongodb';
import { apiError } from '@/lib/http';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const session = await requireBusinessAdmin();
    const state = req.nextUrl.searchParams.get('state') || '';
    const db = await getDb();
    const row: any = await db.collection('metaOAuthStates').findOne({ state, channelId: new ObjectId(params.id), tenantId: new ObjectId(session.tenantId), userId: new ObjectId(session.userId), type: 'whatsapp', expiresAt: { $gt: new Date() } });
    if (!row) return NextResponse.json({ error: 'This WhatsApp setup link expired. Start again from Channels.' }, { status: 400 });
    if (!process.env.META_APP_ID || !process.env.META_WHATSAPP_CONFIG_ID) return NextResponse.json({ error: 'WhatsApp Embedded Signup is not configured for this app yet.' }, { status: 503 });
    const origin = process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin;
    const redirect = `${origin}/api/channels/${params.id}/meta/oauth/callback`;
    const configId = JSON.stringify(process.env.META_WHATSAPP_CONFIG_ID);
    const appId = JSON.stringify(process.env.META_APP_ID);
    const redirectUri = JSON.stringify(redirect);
    const stateJs = JSON.stringify(state);
    const callback = JSON.stringify(`/api/channels/${params.id}/meta/oauth/whatsapp/complete`);
    const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect WhatsApp</title></head><body style="font:16px system-ui;max-width:620px;margin:48px auto;padding:24px;color:#172033"><h1 style="font-size:24px">Connect WhatsApp Business</h1><p>Continue to Meta to choose your business and phone number, then approve access for this workspace.</p><button id="connect" style="padding:12px 18px;border:0;border-radius:8px;background:#0866ff;color:#fff;font-weight:600;cursor:pointer">Continue with Meta</button><p id="status" role="status" style="color:#b42318"></p><script>
      const appId=${appId}, configId=${configId}, redirectUri=${redirectUri}, state=${stateJs}, completeUrl=${callback};
      window.fbAsyncInit=function(){FB.init({appId, cookie:true, xfbml:false, version:${JSON.stringify(process.env.META_GRAPH_VERSION || 'v22.0')}});};
      (function(d,s,id){const js=d.createElement(s);js.id=id;js.src='https://connect.facebook.net/en_US/sdk.js';js.onerror=()=>document.getElementById('status').textContent='Could not load Meta. Check your connection and try again.';d.getElementsByTagName(s)[0].parentNode.insertBefore(js,d.getElementsByTagName(s)[0]);})(document,'script','facebook-jssdk');
      document.getElementById('connect').onclick=function(){document.getElementById('status').textContent='Opening Meta…';FB.login(function(response){if(!response.authResponse){document.getElementById('status').textContent='Meta authorization was cancelled. You can try again.';return;}const auth=response.authResponse;const payload={state,code:auth.code,accessToken:auth.accessToken,expiresIn:auth.expiresIn,grantedScopes:auth.grantedScopes||''};fetch(completeUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}).then(async r=>{const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not finish WhatsApp setup');location.href=d.redirectUrl;}).catch(e=>{document.getElementById('status').textContent=e.message;});},{config_id:configId,response_type:'code',override_default_response_type:true,extras:{setup:{},featureType:'whatsapp_business_app_onboarding',sessionInfoVersion:'3'},redirect_uri:redirectUri,state});};
    </script></body></html>`;
    return new NextResponse(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; script-src 'unsafe-inline' https://connect.facebook.net; connect-src 'self' https://connect.facebook.net https://www.facebook.com; frame-src https://www.facebook.com; style-src 'unsafe-inline'" } });
  } catch (e) { return apiError(e); }
}
