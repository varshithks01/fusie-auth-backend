/**
 * Microsoft OAuth Device Code Flow Auth Server
 *
 * This Express server handles Microsoft authentication using device code flow.
 * No browser popups needed - user enters code at microsoft.com/devicelogin.
 *
 * Common issues:
 * - Graph 400 on chat messages: Remove $select (from is a navigation property)
 * - displayName null: Missing User.ReadBasic.All permission
 * - Group conversation 403: Missing Group.Read.All permission
 * - Members empty after permission change: Delete .ms-token-cache.json and sign in again
 */

import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { PublicClientApplication } from '@azure/msal-node';

const app = express();
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://fusie.online',
    'https://www.fusie.online',
  ]
}));
app.use(express.json());

// Azure AD app settings
const MS_CLIENT_ID = '00946c62-ee88-4549-93bd-272cb8594142';
const MS_TENANT_ID = '79c55a7b-4415-4435-b474-cc5d1af5635c';

// All 13 required scopes (3 require admin consent)
const MS_SCOPES = [
  'User.Read',
  'User.ReadBasic.All',
  'Mail.Read',
  'Chat.Read',
  'Calendars.Read',
  'offline_access',
  'Team.ReadBasic.All',
  'Channel.ReadBasic.All',
  'ChannelMessage.Read.All',    // Requires admin consent
  'GroupMember.Read.All',        // Requires admin consent
  'Group.Read.All',              // Requires admin consent
];

// Persistent token cache file
const CACHE_FILE = path.join(process.cwd(), '.ms-token-cache.json');

function readCache() {
  try {
    return fs.existsSync(CACHE_FILE) ? fs.readFileSync(CACHE_FILE, 'utf8') : '';
  } catch (_) {
    return '';
  }
}

function writeCache(data) {
  try {
    fs.writeFileSync(CACHE_FILE, data, 'utf8');
  } catch (_) {
    // Ignore write errors
  }
}

function clearCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      fs.unlinkSync(CACHE_FILE);
    }
  } catch (_) {
    // Ignore delete errors
  }
}

// MSAL public client with persistent cache
const pca = new PublicClientApplication({
  auth: {
    clientId: MS_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${MS_TENANT_ID}`
  },
  cache: {
    cachePlugin: {
      beforeCacheAccess: async (ctx) => {
        const c = readCache();
        if (c) ctx.tokenCache.deserialize(c);
      },
      afterCacheAccess: async (ctx) => {
        if (ctx.cacheHasChanged) writeCache(ctx.tokenCache.serialize());
      },
    },
  },
});

// In-memory state
let deviceFlowState = null;
let tokenResult = null;
let polling = false;

// POST /api/ms-auth/initiate
// Starts device code flow and returns code for user to enter
app.post('/api/ms-auth/initiate', async (req, res) => {
  console.log('[auth] Initiating device code flow...');
  tokenResult = null;
  deviceFlowState = null;
  polling = false;

  try {
    await new Promise((resolve, reject) => {
      pca.acquireTokenByDeviceCode({
        scopes: MS_SCOPES,
        deviceCodeCallback: (response) => {
          deviceFlowState = {
            userCode: response.userCode,
            verificationUri: response.verificationUri,
            message: response.message,
            expiresAt: Date.now() + (response.expiresIn || 900) * 1000
          };
          polling = true;
          console.log(`[auth] Device code: ${response.userCode}`);
          console.log(`[auth] Visit: ${response.verificationUri}`);
          resolve();
        },
      })
        .then(result => {
          tokenResult = result;
          polling = false;
          console.log('[auth] Device code flow completed successfully');
        })
        .catch(err => {
          polling = false;
          console.error('[auth] Device code flow error:', err.message);
          if (!deviceFlowState) reject(err);
        });
    });

    res.json(deviceFlowState);
  } catch (err) {
    console.error('[auth] Failed to initiate:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ms-auth/poll
// Frontend polls this to check if user completed sign-in
app.get('/api/ms-auth/poll', (req, res) => {
  if (tokenResult) {
    const a = tokenResult.account;
    res.json({
      status: 'complete',
      accessToken: tokenResult.accessToken,
      displayName: a?.name || a?.username || 'User',
      email: a?.username || ''
    });
  } else if (deviceFlowState && Date.now() > deviceFlowState.expiresAt) {
    console.log('[auth] Device code expired');
    res.json({ status: 'expired' });
  } else if (polling) {
    res.json({ status: 'pending' });
  } else {
    res.json({ status: 'idle' });
  }
});

// GET /api/ms-auth/token
// Called on page load to restore session from cache
app.get('/api/ms-auth/token', async (req, res) => {
  // Return in-memory token if available
  if (tokenResult?.accessToken) {
    const a = tokenResult.account;
    return res.json({
      accessToken: tokenResult.accessToken,
      displayName: a?.name || a?.username || 'User',
      email: a?.username || ''
    });
  }

  // Try to get token silently from cache
  try {
    const accounts = await pca.getTokenCache().getAllAccounts();
    if (accounts.length > 0) {
      const silent = await pca.acquireTokenSilent({
        scopes: MS_SCOPES,
        account: accounts[0]
      });
      tokenResult = silent;
      const a = silent.account;
      console.log('[auth] Session restored from cache for:', a?.username);
      return res.json({
        accessToken: silent.accessToken,
        displayName: a?.name || a?.username || 'User',
        email: a?.username || ''
      });
    }
  } catch (err) {
    console.log('[auth] Failed to restore from cache:', err.message);
  }

  res.json({ accessToken: null });
});

// POST /api/ms-auth/logout
// Signs out and clears cache
app.post('/api/ms-auth/logout', async (req, res) => {
  console.log('[auth] Logging out...');
  try {
    const accounts = await pca.getTokenCache().getAllAccounts();
    if (accounts.length > 0) {
      await pca.getTokenCache().removeAccount(accounts[0]);
    }
  } catch (_) {
    // Ignore errors
  }

  tokenResult = null;
  deviceFlowState = null;
  polling = false;
  clearCache();

  console.log('[auth] Logged out successfully');
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log(`║  Auth Server Running on http://0.0.0.0:${PORT}            ║`);
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('✓ Device code flow ready');
  console.log('✓ CORS enabled for http://localhost:3000');
  console.log('✓ Token cache: .ms-token-cache.json');
  console.log('');
});
