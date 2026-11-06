import { NextRequest, NextResponse } from 'next/server';
import { ObjectId } from 'mongodb';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { requireBusinessAdmin } from '@/lib/auth';
import { getDb } from '@/lib/mongodb';
import { apiError } from '@/lib/http';

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const session = await requireBusinessAdmin();
    const body = await req.json();
    const state = String(body.state || '');
    const db = await getDb();
    const row: any = await db.collection('metaOAuthStates').findOne({ state, channelId: new ObjectId(params.id), tenantId: new ObjectId(session.tenantId), userId: new ObjectId(session.userId), type: 'whatsapp', expiresAt: { $gt: new Date() } });
    if (!row || !process.env.AUTH_SECRET) return NextResponse.json({ error: 'WhatsApp setup expired. Start again from Channels.' }, { status: 400 });
    const expected = createHmac('sha256', process.env.AUTH_SECRET).update(state).digest();
    const actual = Buffer.from(row.sig || '', 'hex');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return NextResponse.json({ error: 'WhatsApp setup state is invalid. Start again from Channels.' }, { status: 400 });
    const payload = body.data || body;
    let event: any = {};
    try { event = typeof payload === 'string' ? JSON.parse(payload) : payload; } catch { return NextResponse.json({ error: 'Meta returned invalid signup data. Please try again.' }, { status: 400 }); }
    if (event.event && event.event !== 'FINISH') return NextResponse.json({ error: 'WhatsApp setup was not completed in Meta.' }, { status: 400 });
    const data = event.data || event;
    const wabaId = String(data.waba_id || data.wabaId || data.business_account_id || '');
    const phoneNumberId = String(data.phone_number_id || data.phoneNumberId || '');
    if (!wabaId || !phoneNumberId) return NextResponse.json({ error: 'Meta did not return a WhatsApp business account and phone number. Finish Embedded Signup and try again.' }, { status: 422 });
    await db.collection('metaOAuthStates').updateOne({ _id: row._id }, { $set: { wabaId, phoneNumberId, updatedAt: new Date() } });
    const redirectUrl = `${process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin}/api/channels/${params.id}/meta/oauth/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(String(body.code || ''))}`;
    return NextResponse.json({ redirectUrl });
  } catch (e) { return apiError(e); }
}
