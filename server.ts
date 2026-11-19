import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import {
  evaluateAdminAuthorization,
  extractBearerToken,
  fetchFirebasePublicCerts,
  isValidFirebaseUid,
  loadFirebaseAppletConfig,
  parseAllowedAdminEmails,
  verifyFirebaseIdTokenWithCerts,
} from './server/adminAuth.ts';
import type { VerifiedFirebaseToken } from './server/adminAuth.ts';
import {
  commitServerTimestampDoc,
  deleteFirestoreDoc,
  getFirestoreDoc,
  listFirestoreCollection,
} from './server/firestoreRest.ts';
import {
  RazorpayApiError,
  createRazorpayOrderOnApi,
  getRazorpayConfigStatus,
  getServerRazorpayCredentials,
  sanitizeSecretValue,
  validateRazorpayOrderRequest,
  validateRazorpayVerifyRequest,
  verifyRazorpaySignature,
  verifyRazorpayWebhookSignature,
} from './server/razorpay.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const IS_PROD = process.env.NODE_ENV === 'production';

function parseCliFlag(flagName: string): string | undefined {
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === flagName && args[i + 1] && !args[i + 1].startsWith('-')) {
      return args[i + 1];
    }
    if (arg.startsWith(`${flagName}=`)) {
      return arg.slice(flagName.length + 1);
    }
  }
  return undefined;
}

function resolveListenConfig(): { port: number; host: string } {
  const cliPortRaw = parseCliFlag('--port') ?? parseCliFlag('-p');
  const cliHost = parseCliFlag('--host') ?? parseCliFlag('-h');
  const envPortRaw = process.env.PORT;
  const nginxPortRaw = process.env.NGINX_PORT;
  const defaultAppPort = Number.parseInt(process.env.DEFAULT_APP_PORT ?? '3000', 10) || 3000;

  let port = defaultAppPort;
  if (cliPortRaw) {
    const parsedCliPort = Number.parseInt(cliPortRaw, 10);
    if (Number.isFinite(parsedCliPort) && parsedCliPort > 0) {
      port = parsedCliPort;
    }
  } else if (envPortRaw) {
    const parsedEnvPort = Number.parseInt(envPortRaw, 10);
    const isProxiedByNginx = Boolean(nginxPortRaw && envPortRaw === nginxPortRaw);
    if (Number.isFinite(parsedEnvPort) && parsedEnvPort > 0 && !isProxiedByNginx) {
      port = parsedEnvPort;
    }
  }

  const host = cliHost || process.env.HOST || '0.0.0.0';
  return { port, host };
}

const { port: PORT, host: HOST } = resolveListenConfig();

const firebaseConfig = loadFirebaseAppletConfig(__dirname);
const allowedAdminEmails = parseAllowedAdminEmails(process.env.ADMIN_ALLOWED_EMAILS);

interface AdminRequest extends Request {
  adminToken?: VerifiedFirebaseToken;
  adminIdTokenRaw?: string;
  adminRole?: 'super_admin' | 'admin';
}

function makeSafeId(prefix: string): string {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

async function writeAdminAuditLog(params: {
  actorUid: string;
  actorEmail: string;
  action: string;
  targetType: string;
  targetId: string;
  summary: string;
  idToken: string;
}) {
  const logId = makeSafeId('log');
  await commitServerTimestampDoc(firebaseConfig, {
    docPath: `auditLogs/${logId}`,
    idToken: params.idToken,
    existsPrecondition: false,
    fields: {
      logId: { value: logId },
      actorUid: { value: params.actorUid.slice(0, 128) },
      actorEmail: { value: params.actorEmail.slice(0, 160) },
      action: { value: params.action.slice(0, 80) },
      targetType: { value: params.targetType.slice(0, 40) },
      targetId: { value: params.targetId.slice(0, 128) },
      summary: { value: params.summary.slice(0, 300) },
    },
    serverTimestampFields: ['createdAt'],
  });
}

async function requireAdmin(req: AdminRequest, res: Response, next: NextFunction) {
  try {
    const rawToken = extractBearerToken(req.headers.authorization);
    if (!rawToken) {
      res.status(401).json({
        error: 'Authentication required. Please sign in with your authorized administrator account.',
      });
      return;
    }

    const certs = await fetchFirebasePublicCerts();
    const verified = verifyFirebaseIdTokenWithCerts(rawToken, firebaseConfig.projectId, certs);

    let firestoreAdminRecord: { active?: boolean; role?: string } | null = null;
    try {
      firestoreAdminRecord = await getFirestoreDoc<{ active?: boolean; role?: string }>(
        firebaseConfig,
        `admins/${verified.uid}`,
        rawToken
      );
    } catch {
      firestoreAdminRecord = null;
    }

    const authz = evaluateAdminAuthorization({
      token: verified,
      allowedEmails: allowedAdminEmails,
      firestoreAdminRecord,
    });

    if (!authz.authorized) {
      res.status(403).json({
        error: authz.reason ?? 'Forbidden: Administrator authorization required.',
      });
      return;
    }

    req.adminToken = verified;
    req.adminIdTokenRaw = rawToken;
    req.adminRole = authz.role ?? 'admin';
    next();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid authentication token.';
    res.status(401).json({ error: message });
  }
}

async function startServer() {
  const app = express();
  const httpServer = http.createServer(app);
  app.disable('x-powered-by');
  app.use(
    express.json({
      limit: '512kb',
      verify: (req, _res, buf) => {
        (req as Request & { rawBody?: string }).rawBody = buf.toString('utf8');
      },
    })
  );

  const issuedRazorpayOrders = new Map<
    string,
    { caseId: string; serviceId: string; amountInr: number; amountPaise: number; verified: boolean }
  >();
  const processedWebhookEvents = new Set<string>();

  // -------------------------------------------------------------------------
  // Public Health & Shared Website Read Config
  // -------------------------------------------------------------------------
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'cr-remover-backend',
      firebaseProjectId: firebaseConfig.projectId,
      firestoreDatabaseId: firebaseConfig.firestoreDatabaseId,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/public/site-config', async (_req, res) => {
    try {
      const [contentDocs, serviceDocs, faqDocs] = await Promise.all([
        listFirestoreCollection(firebaseConfig, 'siteContent').catch(() => []),
        listFirestoreCollection(firebaseConfig, 'servicePlans').catch(() => []),
        listFirestoreCollection(firebaseConfig, 'faqs').catch(() => []),
      ]);
      res.json({
        content: contentDocs,
        servicePlans: serviceDocs.filter((plan) => plan.active !== false),
        faqs: faqDocs.filter((faq) => faq.active !== false),
      });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to load public site config.',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Server-Side Razorpay Payment Gateway API Routes
  // -------------------------------------------------------------------------
  app.get('/api/payments/razorpay/config', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(getRazorpayConfigStatus());
  });

  app.post('/api/payments/razorpay/order', async (req, res) => {
    const creds = getServerRazorpayCredentials();
    if (!creds.ok) {
      res.status(creds.statusCode === 503 ? 422 : creds.statusCode).json({ error: creds.error });
      return;
    }

    const validation = validateRazorpayOrderRequest(req.body);
    if (!validation.ok) {
      res.status(400).json({ error: validation.error });
      return;
    }
    const { caseId, plan, amountInr, amountPaise, platform, creatorName } = validation.data;

    try {
      const order = await createRazorpayOrderOnApi({
        keyId: creds.keyId,
        keySecret: creds.keySecret,
        amountInr,
        receipt: caseId,
        notes: {
          caseId,
          serviceId: plan.id,
          serviceTitle: plan.title,
          platform,
          creatorName,
        },
      });

      if (issuedRazorpayOrders.size >= 1000) {
        const oldestKey = issuedRazorpayOrders.keys().next().value;
        if (oldestKey) issuedRazorpayOrders.delete(oldestKey);
      }
      issuedRazorpayOrders.set(order.id, {
        caseId,
        serviceId: plan.id,
        amountInr,
        amountPaise,
        verified: false,
      });

      res.json({
        orderId: order.id,
        amountPaise: order.amount,
        amountInr,
        currency: order.currency,
        keyId: creds.keyId,
        caseId,
        serviceTitle: plan.title,
        mode: creds.mode,
      });
    } catch (err) {
      const statusCode = err instanceof RazorpayApiError ? err.statusCode : 400;
      res.status(statusCode).json({
        error: err instanceof Error ? err.message : 'Unable to create Razorpay order.',
      });
    }
  });

  app.post('/api/payments/razorpay/verify', (req, res) => {
    const creds = getServerRazorpayCredentials();
    if (!creds.ok) {
      res.status(creds.statusCode === 503 ? 422 : creds.statusCode).json({ error: creds.error });
      return;
    }

    const validation = validateRazorpayVerifyRequest(req.body);
    if (!validation.ok) {
      res.status(400).json({ verified: false, error: validation.error });
      return;
    }
    const { caseId, razorpayOrderId, razorpayPaymentId, razorpaySignature } = validation.data;

    const issuedOrder = issuedRazorpayOrders.get(razorpayOrderId);
    if (issuedOrder && issuedOrder.caseId !== caseId) {
      res.status(400).json({
        verified: false,
        error: 'Razorpay order ID does not match the submitted Case ID.',
      });
      return;
    }

    const verified = verifyRazorpaySignature({
      orderId: razorpayOrderId,
      paymentId: razorpayPaymentId,
      signature: razorpaySignature,
      secret: creds.keySecret,
    });

    if (!verified) {
      res.status(400).json({
        verified: false,
        error: 'Razorpay payment signature verification failed.',
      });
      return;
    }

    if (issuedOrder) {
      issuedOrder.verified = true;
    }

    res.json({
      verified: true,
      caseId,
      razorpayOrderId,
      razorpayPaymentId,
      amountInr: issuedOrder?.amountInr,
      paidAt: new Date().toISOString(),
    });
  });

  app.post('/api/payments/razorpay/webhook', (req, res) => {
    const webhookSecret = sanitizeSecretValue(process.env.RAZORPAY_WEBHOOK_SECRET);
    if (!webhookSecret) {
      res.status(503).json({
        error: 'RAZORPAY_WEBHOOK_SECRET is not configured on the server.',
      });
      return;
    }

    const signature = String(req.headers['x-razorpay-signature'] ?? '');
    const rawBody = (req as Request & { rawBody?: string }).rawBody ?? '';
    if (!verifyRazorpayWebhookSignature({ rawBody, signature, secret: webhookSecret })) {
      res.status(400).json({ error: 'Invalid Razorpay webhook signature.' });
      return;
    }

    const eventId = String(req.headers['x-razorpay-event-id'] ?? '').trim();
    if (eventId && processedWebhookEvents.has(eventId)) {
      res.json({ received: true, duplicate: true });
      return;
    }
    if (eventId) {
      if (processedWebhookEvents.size >= 2000) {
        const oldest = processedWebhookEvents.keys().next().value;
        if (oldest) processedWebhookEvents.delete(oldest);
      }
      processedWebhookEvents.add(eventId);
    }

    res.json({ received: true, duplicate: false });
  });

  // -------------------------------------------------------------------------
  // Server-Authorized Admin API Routes
  // -------------------------------------------------------------------------
  app.get('/api/admin/session', requireAdmin, async (req: AdminRequest, res) => {
    const token = req.adminToken!;
    const rawToken = req.adminIdTokenRaw!;

    try {
      const existingAdmin = await getFirestoreDoc(firebaseConfig, `admins/${token.uid}`, rawToken);
      if (!existingAdmin) {
        await commitServerTimestampDoc(firebaseConfig, {
          docPath: `admins/${token.uid}`,
          idToken: rawToken,
          existsPrecondition: false,
          fields: {
            uid: { value: token.uid },
            email: { value: token.email },
            displayName: { value: token.name.slice(0, 100) },
            role: { value: req.adminRole ?? 'admin' },
            active: { value: true },
          },
          serverTimestampFields: ['createdAt', 'updatedAt'],
        });
      }
    } catch {
      // Non-blocking bootstrap sync; security rules still protect every collection
    }

    res.json({
      authorized: true,
      uid: token.uid,
      email: token.email,
      displayName: token.name,
      picture: token.picture ?? null,
      role: req.adminRole,
      projectId: firebaseConfig.projectId,
      firestoreDatabaseId: firebaseConfig.firestoreDatabaseId,
    });
  });

  app.get('/api/admin/overview', requireAdmin, async (req: AdminRequest, res) => {
    try {
      const idToken = req.adminIdTokenRaw!;
      const [orders, payments, users, admins, analytics, auditLogs, siteContent, servicePlans, faqs, settings] =
        await Promise.all([
          listFirestoreCollection(firebaseConfig, 'orders', idToken),
          listFirestoreCollection(firebaseConfig, 'payments', idToken),
          listFirestoreCollection(firebaseConfig, 'users', idToken),
          listFirestoreCollection(firebaseConfig, 'admins', idToken),
          listFirestoreCollection(firebaseConfig, 'analyticsDaily', idToken),
          listFirestoreCollection(firebaseConfig, 'auditLogs', idToken),
          listFirestoreCollection(firebaseConfig, 'siteContent', idToken),
          listFirestoreCollection(firebaseConfig, 'servicePlans', idToken),
          listFirestoreCollection(firebaseConfig, 'faqs', idToken),
          listFirestoreCollection(firebaseConfig, 'settings', idToken),
        ]);

      res.json({
        orders,
        payments,
        users,
        admins,
        analytics,
        auditLogs,
        siteContent,
        servicePlans,
        faqs,
        settings,
      });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to load admin overview.',
      });
    }
  });

  app.patch('/api/admin/orders/:caseId', requireAdmin, async (req: AdminRequest, res) => {
    const { caseId } = req.params;
    if (!isValidFirebaseUid(caseId)) {
      res.status(400).json({ error: 'Invalid caseId format.' });
      return;
    }

    const allowedStatuses = new Set([
      'awaiting_payment',
      'verifying_payment',
      'dispute_filed',
      'claim_released',
      'rejected',
    ]);
    const allowedApps = new Set(['phonepe', 'gpay', 'paytm', 'qr', 'none']);

    const { status, adminNotes, paymentApp, utrNumber } = req.body as {
      status?: string;
      adminNotes?: string;
      paymentApp?: string;
      utrNumber?: string;
    };

    if (status !== undefined && !allowedStatuses.has(status)) {
      res.status(400).json({ error: 'Invalid order status value.' });
      return;
    }
    if (paymentApp !== undefined && !allowedApps.has(paymentApp)) {
      res.status(400).json({ error: 'Invalid paymentApp value.' });
      return;
    }
    if (utrNumber !== undefined && utrNumber !== '' && !/^\d{12}$/.test(utrNumber)) {
      res.status(400).json({ error: 'UTR number must be 12 digits.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      const existing = await getFirestoreDoc<Record<string, unknown>>(
        firebaseConfig,
        `orders/${caseId}`,
        idToken
      );
      if (!existing) {
        res.status(404).json({ error: `Order ${caseId} not found.` });
        return;
      }

      const nextStatus = status ?? String(existing.status);
      const nextNotes = adminNotes !== undefined ? String(adminNotes).slice(0, 1000) : String(existing.adminNotes ?? '');
      const nextPaymentApp = paymentApp ?? String(existing.paymentApp ?? 'none');
      const nextUtr = utrNumber !== undefined ? String(utrNumber).slice(0, 16) : String(existing.utrNumber ?? '');

      const updateFields: Record<string, { value: unknown; isTimestamp?: boolean }> = {
        status: { value: nextStatus },
        adminNotes: { value: nextNotes },
        paymentApp: { value: nextPaymentApp },
        utrNumber: { value: nextUtr },
      };
      const mask = ['status', 'adminNotes', 'paymentApp', 'utrNumber', 'updatedAt'];

      await commitServerTimestampDoc(firebaseConfig, {
        docPath: `orders/${caseId}`,
        idToken,
        existsPrecondition: true,
        fields: updateFields,
        updateMaskFields: mask,
        serverTimestampFields: ['updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'ORDER_UPDATED',
        targetType: 'order',
        targetId: caseId,
        summary: `Updated order ${caseId} status to ${nextStatus}`,
        idToken,
      });

      res.json({ ok: true, caseId, status: nextStatus });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to update order.',
      });
    }
  });

  app.patch('/api/admin/payments/:paymentId', requireAdmin, async (req: AdminRequest, res) => {
    const { paymentId } = req.params;
    if (!isValidFirebaseUid(paymentId)) {
      res.status(400).json({ error: 'Invalid paymentId format.' });
      return;
    }

    const allowedStates = new Set(['pending', 'verified', 'rejected', 'refunded']);
    const { verificationStatus, notes } = req.body as {
      verificationStatus?: string;
      notes?: string;
    };

    if (!verificationStatus || !allowedStates.has(verificationStatus)) {
      res.status(400).json({ error: 'Invalid verificationStatus value.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      const paymentDoc = await getFirestoreDoc<Record<string, unknown>>(
        firebaseConfig,
        `payments/${paymentId}`,
        idToken
      );
      if (!paymentDoc) {
        res.status(404).json({ error: `Payment ${paymentId} not found.` });
        return;
      }

      const nextNotes = notes !== undefined ? String(notes).slice(0, 500) : String(paymentDoc.notes ?? '');

      await commitServerTimestampDoc(firebaseConfig, {
        docPath: `payments/${paymentId}`,
        idToken,
        existsPrecondition: true,
        fields: {
          verificationStatus: { value: verificationStatus },
          verifiedByUid: { value: actor.uid },
          notes: { value: nextNotes },
        },
        updateMaskFields: ['verificationStatus', 'verifiedByUid', 'notes', 'verifiedAt', 'updatedAt'],
        serverTimestampFields: ['verifiedAt', 'updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'PAYMENT_VERIFICATION_UPDATED',
        targetType: 'payment',
        targetId: paymentId,
        summary: `Marked payment ${paymentId} as ${verificationStatus}`,
        idToken,
      });

      res.json({ ok: true, paymentId, verificationStatus });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to update payment record.',
      });
    }
  });

  app.patch('/api/admin/users/:uid', requireAdmin, async (req: AdminRequest, res) => {
    const { uid } = req.params;
    if (!isValidFirebaseUid(uid)) {
      res.status(400).json({ error: 'Invalid user UID format.' });
      return;
    }

    const { role, status } = req.body as { role?: string; status?: string };
    const allowedRoles = new Set(['creator', 'moderator', 'admin']);
    const allowedStatuses = new Set(['active', 'suspended']);

    if (role !== undefined && !allowedRoles.has(role)) {
      res.status(400).json({ error: 'Invalid role.' });
      return;
    }
    if (status !== undefined && !allowedStatuses.has(status)) {
      res.status(400).json({ error: 'Invalid status.' });
      return;
    }

    const actor = req.adminToken!;
    if (uid === actor.uid && (status === 'suspended' || (role && role !== 'admin'))) {
      res.status(400).json({ error: 'Administrators cannot suspend or demote their own active account.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;

    try {
      const existingUser = await getFirestoreDoc<Record<string, unknown>>(
        firebaseConfig,
        `users/${uid}`,
        idToken
      );
      if (!existingUser) {
        res.status(404).json({ error: `User ${uid} not found.` });
        return;
      }

      const nextRole = role ?? String(existingUser.role ?? 'creator');
      const nextStatus = status ?? String(existingUser.status ?? 'active');

      await commitServerTimestampDoc(firebaseConfig, {
        docPath: `users/${uid}`,
        idToken,
        existsPrecondition: true,
        fields: {
          role: { value: nextRole },
          status: { value: nextStatus },
        },
        updateMaskFields: ['role', 'status', 'updatedAt'],
        serverTimestampFields: ['updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'USER_UPDATED',
        targetType: 'user',
        targetId: uid,
        summary: `Updated user ${uid} role=${nextRole}, status=${nextStatus}`,
        idToken,
      });

      res.json({ ok: true, uid, role: nextRole, status: nextStatus });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to update user.',
      });
    }
  });

  app.put('/api/admin/content/:sectionId', requireAdmin, async (req: AdminRequest, res) => {
    const { sectionId } = req.params;
    if (!isValidFirebaseUid(sectionId)) {
      res.status(400).json({ error: 'Invalid sectionId.' });
      return;
    }

    const body = req.body as Record<string, unknown>;
    const headline = String(body.headline ?? '').trim();
    if (!headline || headline.length > 220) {
      res.status(400).json({ error: 'Headline is required (1..220 chars).' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      await commitServerTimestampDoc(firebaseConfig, {
        docPath: `siteContent/${sectionId}`,
        idToken,
        fields: {
          sectionId: { value: sectionId },
          eyebrow: { value: String(body.eyebrow ?? '').slice(0, 120) },
          headline: { value: headline },
          subheadline: { value: String(body.subheadline ?? '').slice(0, 500) },
          primaryCta: { value: String(body.primaryCta ?? '').slice(0, 80) },
          secondaryCta: { value: String(body.secondaryCta ?? '').slice(0, 80) },
          qrImageUrl: { value: String(body.qrImageUrl ?? '').slice(0, 300) },
          footerTagline: { value: String(body.footerTagline ?? '').slice(0, 200) },
          updatedByUid: { value: actor.uid },
        },
        serverTimestampFields: ['updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'CONTENT_UPDATED',
        targetType: 'siteContent',
        targetId: sectionId,
        summary: `Updated website content section ${sectionId}`,
        idToken,
      });

      res.json({ ok: true, sectionId });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to save website content.',
      });
    }
  });

  app.put('/api/admin/service-plans/:serviceId', requireAdmin, async (req: AdminRequest, res) => {
    const { serviceId } = req.params;
    if (!isValidFirebaseUid(serviceId)) {
      res.status(400).json({ error: 'Invalid serviceId.' });
      return;
    }

    const body = req.body as Record<string, unknown>;
    const title = String(body.title ?? '').trim();
    const subtitle = String(body.subtitle ?? '').trim();
    const priceInr = Number(body.priceInr);
    const sortOrder = Number.parseInt(String(body.sortOrder ?? 1), 10);

    if (title.length < 2 || title.length > 120) {
      res.status(400).json({ error: 'Title must be 2..120 chars.' });
      return;
    }
    if (subtitle.length < 2 || subtitle.length > 300) {
      res.status(400).json({ error: 'Subtitle must be 2..300 chars.' });
      return;
    }
    if (!Number.isFinite(priceInr) || priceInr < 1 || priceInr > 1000000) {
      res.status(400).json({ error: 'priceInr must be between 1 and 1,000,000.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      await commitServerTimestampDoc(firebaseConfig, {
        docPath: `servicePlans/${serviceId}`,
        idToken,
        fields: {
          serviceId: { value: serviceId },
          code: { value: String(body.code ?? '01').slice(0, 10) },
          title: { value: title },
          subtitle: { value: subtitle },
          priceInr: { value: priceInr },
          turnaround: { value: String(body.turnaround ?? '24-48 hours').slice(0, 60) },
          scope: { value: String(body.scope ?? '1 Claim').slice(0, 60) },
          active: { value: Boolean(body.active ?? true) },
          sortOrder: { value: Number.isFinite(sortOrder) ? Math.max(0, Math.min(1000, sortOrder)) : 1 },
        },
        serverTimestampFields: ['updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'SERVICE_PLAN_SAVED',
        targetType: 'servicePlan',
        targetId: serviceId,
        summary: `Saved service plan ${serviceId} (₹${priceInr})`,
        idToken,
      });

      res.json({ ok: true, serviceId });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to save service plan.',
      });
    }
  });

  app.delete('/api/admin/service-plans/:serviceId', requireAdmin, async (req: AdminRequest, res) => {
    const { serviceId } = req.params;
    if (!isValidFirebaseUid(serviceId)) {
      res.status(400).json({ error: 'Invalid serviceId.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      await deleteFirestoreDoc(firebaseConfig, `servicePlans/${serviceId}`, idToken);
      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'SERVICE_PLAN_DELETED',
        targetType: 'servicePlan',
        targetId: serviceId,
        summary: `Deleted service plan ${serviceId}`,
        idToken,
      });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to delete service plan.',
      });
    }
  });

  app.put('/api/admin/faqs/:faqId', requireAdmin, async (req: AdminRequest, res) => {
    const { faqId } = req.params;
    if (!isValidFirebaseUid(faqId)) {
      res.status(400).json({ error: 'Invalid faqId.' });
      return;
    }

    const body = req.body as Record<string, unknown>;
    const question = String(body.question ?? '').trim();
    const answer = String(body.answer ?? '').trim();
    const sortOrder = Number.parseInt(String(body.sortOrder ?? 1), 10);

    if (question.length < 5 || question.length > 240) {
      res.status(400).json({ error: 'Question must be 5..240 chars.' });
      return;
    }
    if (answer.length < 5 || answer.length > 1200) {
      res.status(400).json({ error: 'Answer must be 5..1200 chars.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      await commitServerTimestampDoc(firebaseConfig, {
        docPath: `faqs/${faqId}`,
        idToken,
        fields: {
          faqId: { value: faqId },
          question: { value: question },
          answer: { value: answer },
          sortOrder: { value: Number.isFinite(sortOrder) ? Math.max(0, Math.min(1000, sortOrder)) : 1 },
          active: { value: Boolean(body.active ?? true) },
        },
        serverTimestampFields: ['updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'FAQ_SAVED',
        targetType: 'faq',
        targetId: faqId,
        summary: `Saved FAQ ${faqId}`,
        idToken,
      });

      res.json({ ok: true, faqId });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to save FAQ.',
      });
    }
  });

  app.delete('/api/admin/faqs/:faqId', requireAdmin, async (req: AdminRequest, res) => {
    const { faqId } = req.params;
    if (!isValidFirebaseUid(faqId)) {
      res.status(400).json({ error: 'Invalid faqId.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      await deleteFirestoreDoc(firebaseConfig, `faqs/${faqId}`, idToken);
      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'FAQ_DELETED',
        targetType: 'faq',
        targetId: faqId,
        summary: `Deleted FAQ ${faqId}`,
        idToken,
      });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to delete FAQ.',
      });
    }
  });

  app.put('/api/admin/settings', requireAdmin, async (req: AdminRequest, res) => {
    const body = req.body as Record<string, unknown>;
    const siteName = String(body.siteName ?? '').trim();
    const supportEmail = String(body.supportEmail ?? '').trim();
    const supportWhatsapp = String(body.supportWhatsapp ?? '').trim();
    const upiDisplayLabel = String(body.upiDisplayLabel ?? '').trim();
    const upiMerchantName = String(body.upiMerchantName ?? '').trim();

    if (!siteName || siteName.length > 80) {
      res.status(400).json({ error: 'Site name is required (1..80 chars).' });
      return;
    }
    if (!supportEmail || !supportEmail.includes('@') || supportEmail.length > 160) {
      res.status(400).json({ error: 'Valid support email is required.' });
      return;
    }
    if (!upiDisplayLabel || upiDisplayLabel.length > 80) {
      res.status(400).json({ error: 'UPI display label is required.' });
      return;
    }
    if (!upiMerchantName || upiMerchantName.length > 80) {
      res.status(400).json({ error: 'UPI merchant name is required.' });
      return;
    }

    const idToken = req.adminIdTokenRaw!;
    const actor = req.adminToken!;

    try {
      await commitServerTimestampDoc(firebaseConfig, {
        docPath: 'settings/general',
        idToken,
        fields: {
          settingId: { value: 'general' },
          siteName: { value: siteName },
          supportEmail: { value: supportEmail },
          supportWhatsapp: { value: supportWhatsapp.slice(0, 32) },
          upiDisplayLabel: { value: upiDisplayLabel },
          upiMerchantName: { value: upiMerchantName },
          maintenanceMode: { value: Boolean(body.maintenanceMode) },
          allowNewOrders: { value: Boolean(body.allowNewOrders ?? true) },
          strictUtrValidation: { value: Boolean(body.strictUtrValidation ?? true) },
          updatedByUid: { value: actor.uid },
        },
        serverTimestampFields: ['updatedAt'],
      });

      await writeAdminAuditLog({
        actorUid: actor.uid,
        actorEmail: actor.email,
        action: 'SETTINGS_UPDATED',
        targetType: 'settings',
        targetId: 'general',
        summary: `Updated general platform settings`,
        idToken,
      });

      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to save settings.',
      });
    }
  });

  // Return JSON 404 for unknown API paths
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API route not found.' });
  });

  // -------------------------------------------------------------------------
  // Separate Entry Routing: /admin* -> Admin Website, / -> Main Website
  // -------------------------------------------------------------------------
  if (!IS_PROD) {
    const vite = await createViteServer({
      server: {
        middlewareMode: { server: httpServer },
      },
      appType: 'custom',
    });

    app.use(vite.middlewares);

    app.get(/^\/admin(\/.*)?$/, async (req, res, next) => {
      try {
        const adminHtmlPath = path.resolve(__dirname, 'admin.html');
        const template = fs.readFileSync(adminHtmlPath, 'utf8');
        const html = await vite.transformIndexHtml(req.originalUrl, template);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(html);
      } catch (err) {
        next(err);
      }
    });

    app.get(/^\/(?!api(\/|$)).*$/, async (req, res, next) => {
      try {
        const mainHtmlPath = path.resolve(__dirname, 'index.html');
        const template = fs.readFileSync(mainHtmlPath, 'utf8');
        const html = await vite.transformIndexHtml(req.originalUrl, template);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(html);
      } catch (err) {
        next(err);
      }
    });
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir, { index: false }));

    app.get(/^\/admin(\/.*)?$/, (_req, res) => {
      res.sendFile(path.resolve(distDir, 'admin.html'));
    });

    app.get(/^\/(?!api(\/|$)).*$/, (_req, res) => {
      res.sendFile(path.resolve(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, HOST, () => {
    console.log(`CR Remover server listening on http://${HOST}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
