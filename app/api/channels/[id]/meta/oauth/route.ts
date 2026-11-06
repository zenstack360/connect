import { NextRequest, NextResponse } from 'next/server';
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { ObjectId } from 'mongodb';
import { requireBusinessAdmin } from '@/lib/auth';
import { getDb } from '@/lib/mongodb';
import { apiError } from '@/lib/http';

export async function GET(_req: NextRequest, { params }: { params: { id: string } }) {
  try { const s = await requireBusinessAdmin(); if (!ObjectId.isValid(params.id)) return NextResponse.json({ error: 'Invalid channel id' }, { status: 400 }); if (!process.env.META_APP_ID || !process.env.META_APP_SECRET) return NextResponse.json({ error: 'Meta authorization is not configured for this app yet. Ask your workspace administrator to finish Meta setup.' }, { status: 503 }); if (!process.env.AUTH_SECRET || process.env.AUTH_SECRET.length < 32) return NextResponse.json({ error: 'Workspace authentication is not configured securely. Ask your administrator for help.' }, { status: 503 }); if (!process.env.CREDENTIAL_ENCRYPTION_KEY || !/^[a-f\d]{64}$/i.test(process.env.CREDENTIAL_ENCRYPTION_KEY)) return NextResponse.json({ error: 'Secure channel credential storage is not configured. Ask your administrator for help.' }, { status: 503 });
    const db = await getDb(); const tenantId = new ObjectId(s.tenantId); const channel = await db.collection('channels').findOne({ _id: new ObjectId(params.id), tenantId, type: { $in: ['whatsapp','messenger','instagram'] } }); if (!channel) return NextResponse.json({ error: 'Meta channel not found' }, { status: 404 });
    const nonce = randomBytes(24).toString('hex'); const state = `${tenantId}.${params.id}.${channel.type}.${nonce}`; const sig = createHmac('sha256', process.env.AUTH_SECRET!).update(state).digest('hex');
    const redirect = `${process.env.NEXT_PUBLIC_APP_URL || _req.nextUrl.origin}/api/channels/${params.id}/meta/oauth/callback`;
    if (channel.type === 'whatsapp' && !process.env.META_WHATSAPP_CONFIG_ID) return NextResponse.json({ error: 'WhatsApp Embedded Signup is not configured for this app yet. Ask your workspace administrator to finish Meta setup.' }, { status: 503 });
    await db.collection('metaOAuthStates').insertOne({ state, sig, tenantId, channelId: channel._id, type: channel.type, userId: new ObjectId(s.userId), expiresAt: new Date(Date.now() + 10 * 60_000), createdAt: new Date() });
    const scope = channel.type === 'whatsapp' ? 'whatsapp_business_management,whatsapp_business_messaging,business_management' : channel.type === 'messenger' ? 'pages_show_list,pages_messaging,pages_manage_metadata,pages_read_engagement' : 'instagram_basic,instagram_manage_messages,pages_show_list,pages_manage_metadata,pages_read_engagement';
    const url = new URL(`https://www.facebook.com/${process.env.META_GRAPH_VERSION || 'v22.0'}/dialog/oauth`); url.searchParams.set('client_id', process.env.META_APP_ID); url.searchParams.set('redirect_uri', redirect); url.searchParams.set('state', state); url.searchParams.set('scope', scope); url.searchParams.set('response_type', 'code');
    if (channel.type === 'whatsapp') {
      // Embedded Signup requires the Meta JS SDK to report the selected WABA and phone IDs.
      // The OAuth dialog redirect carries authorization back after this browser step.
      const origin = process.env.NEXT_PUBLIC_APP_URL || _req.nextUrl.origin;
      return NextResponse.redirect(`${origin}/api/channels/${params.id}/meta/oauth/whatsapp?state=${encodeURIComponent(state)}`);
    }
    return NextResponse.redirect(url);
  } catch (e) { return apiError(e); }
}

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try { const s = await requireBusinessAdmin(); const body = await req.json(); const db = await getDb(); const row: any = await db.collection('metaOAuthStates').findOne({ state: body.state, channelId: new ObjectId(params.id), userId: new ObjectId(s.userId), tenantId: new ObjectId(s.tenantId), expiresAt: { $gt: new Date() } });
    if (!row || !process.env.AUTH_SECRET) return NextResponse.json({ error: 'OAuth state expired or invalid' }, { status: 400 }); const expected = createHmac('sha256', process.env.AUTH_SECRET).update(row.state).digest(); const actual = Buffer.from(row.sig, 'hex'); if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return NextResponse.json({ error: 'OAuth state signature invalid' }, { status: 400 });
    const channel: any = await db.collection('channels').findOne({ _id: row.channelId, tenantId: row.tenantId, type: row.type }); if (!channel) return NextResponse.json({ error: 'Channel no longer exists' }, { status: 404 });
    return NextResponse.json({ error: 'Meta OAuth callback processing moved to the callback route' }, { status: 410 });
  } catch (e) { return apiError(e); }
}
