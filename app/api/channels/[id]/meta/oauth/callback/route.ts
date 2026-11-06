import { NextRequest, NextResponse } from 'next/server';
import { ObjectId } from 'mongodb';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { getDb } from '@/lib/mongodb';
import { apiError } from '@/lib/http';

const graph = () => `https://graph.facebook.com/${process.env.META_GRAPH_VERSION || 'v22.0'}`;
const appOrigin = (req: NextRequest) => process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin;

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    if (!ObjectId.isValid(params.id)) return NextResponse.json({ error: 'Invalid channel id' }, { status: 400 });
    const state = req.nextUrl.searchParams.get('state') || '';
    const code = req.nextUrl.searchParams.get('code');
    const providerError = req.nextUrl.searchParams.get('error_description') || req.nextUrl.searchParams.get('error');
    const db = await getDb();
    const row: any = await db.collection('metaOAuthStates').findOne({ state, channelId: new ObjectId(params.id), expiresAt: { $gt: new Date() } });
    if (!row || !process.env.AUTH_SECRET) return NextResponse.json({ error: 'OAuth state expired or invalid' }, { status: 400 });
    const expected = createHmac('sha256', process.env.AUTH_SECRET).update(state).digest();
    const actual = Buffer.from(row.sig || '', 'hex');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return NextResponse.json({ error: 'OAuth state signature invalid' }, { status: 400 });
    const origin = appOrigin(req);
    const fail = async (message: string, status = 400) => {
      await db.collection('metaOAuthStates').updateOne({ _id: row._id }, { $set: { lastError: message, updatedAt: new Date() } });
      return NextResponse.redirect(`${origin}/channels?meta=error&reason=${encodeURIComponent(message)}`, { status: 303 });
    };
    if (providerError || !code) {
      await db.collection('metaOAuthStates').deleteOne({ _id: row._id });
      return NextResponse.redirect(`${origin}/channels?meta=error`);
    }
    if (!process.env.META_APP_ID || !process.env.META_APP_SECRET) return fail('Meta authorization is not configured for this app yet.', 503);
    const redirect = `${origin}/api/channels/${params.id}/meta/oauth/callback`;
    const exchangeUrl = new URL(`${graph()}/oauth/access_token`);
    exchangeUrl.searchParams.set('client_id', process.env.META_APP_ID);
    exchangeUrl.searchParams.set('client_secret', process.env.META_APP_SECRET);
    exchangeUrl.searchParams.set('redirect_uri', redirect);
    exchangeUrl.searchParams.set('code', code);
    const exchangeRes = await fetch(exchangeUrl);
    const exchanged: any = await exchangeRes.json().catch(() => ({}));
    if (!exchangeRes.ok || !exchanged.access_token) return fail(exchanged?.error?.message || 'Meta token exchange failed. Please reconnect.', 502);

    let accounts: any[] = [];
    if (row.type === 'whatsapp') {
      // Embedded Signup returns WABA and phone number IDs in the signed OAuth state.
      const wabaId = String(row.wabaId || '');
      const phoneNumberId = String(row.phoneNumberId || '');
      if (!wabaId || !phoneNumberId) return fail('Meta did not return a WhatsApp business account and phone number. Check the Embedded Signup setup and try again.', 422);
      const accountUrl = new URL(`${graph()}/${encodeURIComponent(wabaId)}/phone_numbers`);
      accountUrl.searchParams.set('fields', 'id,display_phone_number,verified_name');
      accountUrl.searchParams.set('access_token', exchanged.access_token);
      const accountRes = await fetch(accountUrl);
      const accountData: any = await accountRes.json().catch(() => ({}));
      if (!accountRes.ok) return fail(accountData?.error?.message || 'Could not verify WhatsApp business assets. Please reconnect.', 502);
      const phone = (accountData.data || []).find((x: any) => String(x.id) === phoneNumberId);
      if (!phone) return fail('The selected phone number is not available in the authorized WhatsApp Business Account.', 422);
      accounts = [{ id: wabaId, name: phone.verified_name || phone.display_phone_number || 'WhatsApp Business', pageId: '', phoneNumberId, whatsappBusinessAccountId: wabaId, token: exchanged.access_token, displayPhoneNumber: phone.display_phone_number }];
    } else {
      const pagesUrl = new URL(`${graph()}/me/accounts`);
      pagesUrl.searchParams.set('fields', 'id,name,access_token,instagram_business_account{id,username}');
      pagesUrl.searchParams.set('access_token', exchanged.access_token);
      const pagesRes = await fetch(pagesUrl);
      const pages: any = await pagesRes.json().catch(() => ({}));
      if (!pagesRes.ok) return fail(pages?.error?.message || 'Could not list eligible Facebook Pages. Please reconnect.', 502);
      accounts = (pages.data || []).flatMap((page: any) => row.type === 'instagram'
        ? page.instagram_business_account ? [{ id: String(page.instagram_business_account.id), name: page.instagram_business_account.username || page.name, token: page.access_token, pageId: String(page.id), pageName: page.name }] : []
        : [{ id: String(page.id), name: page.name, token: page.access_token, pageId: String(page.id), pageName: page.name }]);
    }
    await db.collection('metaOAuthStates').updateOne({ _id: row._id }, { $set: { accounts } });
    return NextResponse.redirect(`${origin}/api/channels/${params.id}/meta/oauth/select?state=${encodeURIComponent(state)}`);
  } catch (e) { return apiError(e); }
}
