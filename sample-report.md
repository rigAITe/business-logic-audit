# Sample Audit Report: Trading Platform

> **Target:** Trading platform with React Native mobile app and Node.js/Express backend  
> **Scope:** Business logic vulnerabilities across backend API, webhook handlers, and mobile client  
> **Date:** 2026-02-15  
> **Findings:** 9 total — 3 Critical, 3 High, 2 Medium, 1 Low

---

## Domain Discovery

| Aspect                    | Details                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Business Entities**     | Users, Wallets (crypto + fiat), Transactions, Exchange Rates, KYC Records                              |
| **Critical Operations**   | Buy/sell crypto, fiat withdrawal, wallet funding, KYC submission                                       |
| **Value Flows**           | Fiat → Crypto wallet, Crypto wallet → Fiat, User → Platform fees                                       |
| **State Machines**        | Transaction lifecycle (pending → confirmed → settled), KYC (submitted → reviewing → approved/rejected) |
| **Trust Boundaries**      | User, Admin, Webhook (payment provider), Mobile client                                                 |
| **External Integrations** | Paystack (fiat payments), CoinGecko (rates), Smile Identity (KYC)                                      |
| **Architecture**          | React Native mobile app + Node.js/Express API + MongoDB                                                |

**Applicable patterns:** Fintech/Payments, Crypto/Web3, + all universal, frontend, and mobile patterns.

---

## Finding 1: Webhook Signature Bypass

**Severity:** Critical  
**Location:** `src/webhooks/paystack.controller.ts:L34-L58`  
**Layer:** Backend  
**Pattern:** Pattern 6 — Webhook / Callback Integrity

### Description

The Paystack webhook handler processes payment confirmations without verifying the cryptographic signature. An attacker can forge webhook payloads to credit arbitrary amounts to any wallet.

### Vulnerable Code

```typescript
// src/webhooks/paystack.controller.ts:L34-L58
router.post("/webhooks/paystack", async (req, res) => {
  const { event, data } = req.body;

  if (event === "charge.success") {
    // ❌ No signature verification before processing
    const user = await User.findOne({ email: data.customer.email });
    await Wallet.updateOne(
      { userId: user._id, currency: "NGN" },
      { $inc: { balance: data.amount / 100 } },
    );
    await Transaction.create({
      userId: user._id,
      amount: data.amount / 100,
      status: "completed",
    });
  }

  res.sendStatus(200);
});
```

### Attack Scenario

1. Attacker sends a POST to `/webhooks/paystack` with a forged payload containing `event: "charge.success"` and an arbitrary `amount`
2. The handler credits the forged amount to the attacker's wallet
3. Attacker initiates a crypto purchase with the fraudulent fiat balance
4. **Impact:** Direct financial loss — attacker can generate unlimited fiat balance

### Recommended Fix

```typescript
import crypto from "crypto";

router.post("/webhooks/paystack", async (req, res) => {
  // ✅ Verify signature BEFORE processing
  const hash = crypto
    .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (hash !== req.headers["x-paystack-signature"]) {
    return res.sendStatus(401);
  }

  // ✅ Validate against internal state
  const { event, data } = req.body;
  if (event === "charge.success") {
    const pendingTx = await Transaction.findOne({
      reference: data.reference,
      status: "pending",
    });
    if (!pendingTx) return res.sendStatus(200); // Unknown reference, ignore

    if (pendingTx.expectedAmount !== data.amount / 100) {
      logger.warn("Amount mismatch on webhook", {
        expected: pendingTx.expectedAmount,
        received: data.amount / 100,
      });
      return res.sendStatus(200);
    }

    // Process with idempotency check...
  }
  res.sendStatus(200);
});
```

---

## Finding 2: Race Condition on Crypto Purchase

**Severity:** Critical  
**Location:** `src/services/trade.service.ts:L89-L112`  
**Layer:** Backend  
**Pattern:** Pattern 1 — Race Conditions / Double-Processing

### Description

The buy-crypto operation reads the user's fiat balance, checks sufficiency, then deducts — all without row-level locking. Concurrent requests can both pass the balance check and deduct, resulting in a negative balance and free crypto.

### Vulnerable Code

```typescript
// src/services/trade.service.ts:L89-L112
async function buyCrypto(userId: string, amount: number, coin: string) {
  const wallet = await Wallet.findOne({ userId, currency: "NGN" }); // ❌ No lock

  if (wallet.balance < amount) {
    throw new Error("Insufficient balance");
  }

  const rate = await getExchangeRate(coin, "NGN");
  const cryptoAmount = amount / rate;

  // ❌ TOCTOU: balance could have changed between read and write
  await Wallet.updateOne(
    { userId, currency: "NGN" },
    { $inc: { balance: -amount } },
  );

  await Wallet.updateOne(
    { userId, currency: coin },
    { $inc: { balance: cryptoAmount } },
  );
}
```

### Attack Scenario

1. Attacker has ₦10,000 balance and sends 5 concurrent buy requests for ₦10,000 each
2. All 5 requests read balance as ₦10,000 and pass the sufficiency check
3. All 5 deductions execute, leaving balance at -₦40,000
4. Attacker receives ₦50,000 worth of crypto for ₦10,000
5. **Impact:** Direct financial loss — crypto created from nothing

### Recommended Fix

```typescript
async function buyCrypto(userId: string, amount: number, coin: string) {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // ✅ Atomic deduction with balance check
    const result = await Wallet.findOneAndUpdate(
      { userId, currency: "NGN", balance: { $gte: amount } },
      { $inc: { balance: -amount } },
      { session, new: true },
    );

    if (!result) {
      throw new Error("Insufficient balance");
    }

    const rate = await getExchangeRate(coin, "NGN");
    const cryptoAmount = amount / rate;

    await Wallet.updateOne(
      { userId, currency: coin },
      { $inc: { balance: cryptoAmount } },
      { session },
    );

    await session.commitTransaction();
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
}
```

---

## Finding 3: KYC State Machine Bypass

**Severity:** Critical  
**Location:** `src/controllers/user.controller.ts:L201-L218`  
**Layer:** Backend  
**Pattern:** Pattern 2 — State Machine Bypass

### Description

The withdrawal endpoint checks if the user's KYC status is `approved`, but a user can call the KYC approval endpoint directly to set their own status without completing the actual verification.

### Vulnerable Code

```typescript
// src/controllers/user.controller.ts:L201-L218
router.put("/api/users/:id/kyc-status", authMiddleware, async (req, res) => {
  // ❌ No admin-only check — any authenticated user can call this
  // ❌ No state transition validation
  const { status } = req.body;
  await User.updateOne({ _id: req.params.id }, { kycStatus: status });
  res.json({ message: "KYC status updated" });
});
```

### Attack Scenario

1. User registers and submits invalid/no KYC documents
2. User directly calls `PUT /api/users/{their-id}/kyc-status` with `{ "status": "approved" }`
3. User now has KYC approval without verification and can withdraw funds
4. **Impact:** Complete KYC bypass — enables money laundering, regulatory violation

### Recommended Fix

```typescript
// Only allow KYC status updates from admin or internal webhook
router.put(
  "/api/users/:id/kyc-status",
  authMiddleware,
  adminOnly,
  async (req, res) => {
    const { status } = req.body;
    const user = await User.findById(req.params.id);

    // ✅ Validate state transition
    const validTransitions = {
      submitted: ["reviewing"],
      reviewing: ["approved", "rejected"],
      rejected: ["submitted"], // Allow re-submission
    };

    if (!validTransitions[user.kycStatus]?.includes(status)) {
      return res.status(400).json({ error: "Invalid status transition" });
    }

    await User.updateOne({ _id: req.params.id }, { kycStatus: status });
    res.json({ message: "KYC status updated" });
  },
);
```

---

## Finding 4: Exchange Rate Client-Side Trust

**Severity:** High  
**Location:** `src/mobile/screens/TradeScreen.tsx:L45-L67`, `src/routes/trade.routes.ts:L23-L41`  
**Layer:** Full-Stack  
**Pattern:** Pattern F2 — Client-Side State Manipulation, Fintech — Exchange Rate Integrity

### Description

The mobile app fetches the exchange rate, calculates the crypto amount locally, and sends both the rate and the calculated amount to the server. The server uses the client-supplied rate instead of fetching its own.

### Vulnerable Code

```typescript
// Mobile app — src/mobile/screens/TradeScreen.tsx:L45-L67
const handleBuy = async () => {
  const rate = displayedRate; // ❌ Rate from client state
  const cryptoAmount = fiatAmount / rate;
  await api.post("/trade/buy", {
    amount: fiatAmount,
    coin,
    rate, // ❌ Client supplies the rate
    cryptoAmount, // ❌ Client supplies the calculated amount
  });
};

// Server — src/routes/trade.routes.ts:L23-L41
router.post("/trade/buy", authMiddleware, async (req, res) => {
  const { amount, coin, rate, cryptoAmount } = req.body;
  // ❌ Server trusts client-supplied rate and amount
  await executeTrade(req.user.id, amount, coin, rate, cryptoAmount);
});
```

### Attack Scenario

1. Attacker intercepts the API request and modifies `rate` to 1 (instead of the actual rate of ~1,500 NGN/USD)
2. Server processes the trade at the attacker-supplied rate
3. Attacker gets 1,500x more crypto than they should
4. **Impact:** Severe financial loss through exchange rate manipulation

### Recommended Fix

```typescript
// Server should NEVER trust client-supplied rates
router.post("/trade/buy", authMiddleware, async (req, res) => {
  const { amount, coin } = req.body; // ✅ Only accept amount and coin

  const rate = await getServerAuthoritativeRate(coin, "NGN"); // ✅ Server fetches rate
  const cryptoAmount = amount / rate; // ✅ Server calculates

  await executeTrade(req.user.id, amount, coin, rate, cryptoAmount);
});
```

---

## Finding 5: Insecure Token Storage on Mobile

**Severity:** High  
**Location:** `src/mobile/utils/auth.ts:L12-L25`  
**Layer:** Mobile  
**Pattern:** Pattern M2 — Insecure Local Storage

### Description

The mobile app stores the JWT access token and refresh token in React Native's `AsyncStorage`, which is unencrypted plaintext on both iOS and Android. On a rooted/jailbroken device, any app can read these tokens.

### Vulnerable Code

```typescript
// src/mobile/utils/auth.ts:L12-L25
export const saveTokens = async (accessToken: string, refreshToken: string) => {
  // ❌ AsyncStorage is unencrypted plaintext
  await AsyncStorage.setItem("access_token", accessToken);
  await AsyncStorage.setItem("refresh_token", refreshToken);
};

export const getAccessToken = async () => {
  return AsyncStorage.getItem("access_token");
};
```

### Attack Scenario

1. User installs a malicious app on a rooted Android device
2. Malicious app reads `/data/data/com.cryptotrade/databases/RKStorage` (AsyncStorage backing file)
3. Attacker extracts both tokens and makes authenticated API calls
4. **Impact:** Full account takeover — attacker can trade, withdraw, and modify profile

### Recommended Fix

```typescript
import * as SecureStore from "expo-secure-store";
// Or: import { Keychain } from 'react-native-keychain';

export const saveTokens = async (accessToken: string, refreshToken: string) => {
  // ✅ Uses iOS Keychain / Android Keystore — encrypted, hardware-backed
  await SecureStore.setItemAsync("access_token", accessToken);
  await SecureStore.setItemAsync("refresh_token", refreshToken);
};
```

---

## Finding 6: Deep Link OAuth Callback Interception

**Severity:** High  
**Location:** `src/mobile/navigation/linking.ts:L8-L15`, `app.json:L23`  
**Layer:** Mobile  
**Pattern:** Pattern M3 — Deep Link / URL Scheme Hijacking

### Description

The app uses a custom URL scheme (`cryptotrade://`) for OAuth callback redirects. On Android, any app can register the same custom scheme, intercepting the OAuth authorization code.

### Vulnerable Code

```json
// app.json
{
  "expo": {
    "scheme": "cryptotrade"
  }
}
```

```typescript
// src/mobile/navigation/linking.ts:L8-L15
const linking = {
  prefixes: ["cryptotrade://"],
  config: {
    screens: {
      OAuthCallback: "oauth/callback", // ❌ Custom scheme for sensitive callback
    },
  },
};
```

### Attack Scenario

1. Attacker publishes a benign-looking app that also registers the `cryptotrade://` scheme
2. When user completes Google OAuth, Android shows a disambiguation dialog or the malicious app intercepts the redirect
3. Attacker captures the authorization code and exchanges it for tokens
4. **Impact:** Account takeover via OAuth code interception

### Recommended Fix

Use Universal Links (iOS) / App Links (Android) instead of custom URL schemes for sensitive callbacks:

```json
// app.json — use verified domain instead of custom scheme
{
  "expo": {
    "ios": {
      "associatedDomains": ["applinks:auth.cryptotrade.com"]
    },
    "android": {
      "intentFilters": [
        {
          "action": "VIEW",
          "autoVerify": true,
          "data": {
            "scheme": "https",
            "host": "auth.cryptotrade.com",
            "pathPrefix": "/oauth/callback"
          }
        }
      ]
    }
  }
}
```

---

## Finding 7: Transaction Amount Accepts Negative Values

**Severity:** Medium  
**Location:** `src/routes/trade.routes.ts:L23-L41`  
**Layer:** Backend  
**Pattern:** Pattern 3 — Input Boundary Violations

### Description

The buy endpoint accepts the `amount` field without validating that it's positive. A negative amount reverses the balance operations, potentially extracting value.

### Vulnerable Code

```typescript
// src/routes/trade.routes.ts:L23-L41
router.post("/trade/buy", authMiddleware, async (req, res) => {
  const { amount, coin } = req.body;
  // ❌ No validation that amount > 0
  await executeTrade(req.user.id, amount, coin);
});
```

### Attack Scenario

1. Attacker sends `{ "amount": -10000, "coin": "BTC" }`
2. Balance deduction becomes an addition: `balance -= -10000` → `balance += 10000`
3. **Impact:** Free fiat credit by exploiting sign inversion

### Recommended Fix

```typescript
import { z } from "zod";

const tradeSchema = z.object({
  amount: z.number().positive().max(10_000_000), // ✅ Positive, bounded
  coin: z.enum(["BTC", "ETH", "USDT"]),
});

router.post("/trade/buy", authMiddleware, async (req, res) => {
  const { amount, coin } = tradeSchema.parse(req.body);
  await executeTrade(req.user.id, amount, coin);
});
```

---

## Finding 8: Admin Endpoint Exposed in Production Bundle

**Severity:** Medium  
**Location:** `src/mobile/services/api.ts:L78-L85`  
**Layer:** Mobile  
**Pattern:** Pattern F5 — Sensitive Data in the Bundle

### Description

The mobile app's API service file contains commented-out but present admin endpoint URLs and a test API key, all of which ship in the production JavaScript bundle.

### Vulnerable Code

```typescript
// src/mobile/services/api.ts:L78-L85
// ❌ These ship in the production bundle even when commented out
// const ADMIN_API = 'https://admin-internal.cryptotrade.com/api/v1';
// const TEST_KEY = 'sk_test_abc123_not_for_production';
const ADMIN_ENDPOINTS = {
  adjustBalance: "/admin/wallets/adjust", // ❌ Internal endpoint exposed
  overrideKyc: "/admin/users/kyc-override", // ❌ Internal endpoint exposed
};
```

### Attack Scenario

1. Attacker decompiles the APK or inspects the JavaScript bundle
2. Discovers internal admin API domain and endpoint paths
3. Uses this information to probe admin APIs for further vulnerabilities
4. **Impact:** Information disclosure enabling targeted attacks on admin infrastructure

### Recommended Fix

Remove all admin endpoints, test keys, and internal URLs from the mobile codebase entirely. Admin functionality should exist only in a separate, server-side admin tool.

---

## Finding 9: Fee Percentage Accepts Values Over 100%

**Severity:** Low  
**Location:** `src/config/fees.ts:L8-L15`  
**Layer:** Backend  
**Pattern:** Fintech — Fee and Markup Manipulation

### Description

Admin-configurable fee percentages have no upper bound validation. While currently set to reasonable values, there's no guard preventing a misconfiguration that sets fees above 100%.

### Vulnerable Code

```typescript
// src/config/fees.ts:L8-L15
const feeConfig = {
  tradeFeePercent: parseFloat(process.env.TRADE_FEE_PERCENT || "1.5"),
  withdrawalFeePercent: parseFloat(process.env.WITHDRAWAL_FEE_PERCENT || "0.5"),
  // ❌ No validation on range — could be set to 150% or -5%
};
```

### Attack Scenario

1. A misconfigured environment variable sets `TRADE_FEE_PERCENT=150`
2. Users are charged 150% of their trade as a fee, resulting in negative post-fee amounts
3. Depending on implementation, this could create value inversions
4. **Impact:** Low — requires admin misconfiguration, but absent guard creates unnecessary risk

### Recommended Fix

```typescript
const feeConfig = {
  tradeFeePercent: validateRange(
    parseFloat(process.env.TRADE_FEE_PERCENT || "1.5"),
    0,
    25,
  ),
  withdrawalFeePercent: validateRange(
    parseFloat(process.env.WITHDRAWAL_FEE_PERCENT || "0.5"),
    0,
    10,
  ),
};

function validateRange(value: number, min: number, max: number): number {
  if (isNaN(value) || value < min || value > max) {
    throw new Error(
      `Fee config out of range: ${value} (expected ${min}-${max})`,
    );
  }
  return value;
}
```

---

## Summary

| #   | Finding                               | Severity     | Layer      | Pattern              |
| --- | ------------------------------------- | ------------ | ---------- | -------------------- |
| 1   | Webhook signature bypass              | **Critical** | Backend    | Pattern 6            |
| 2   | Race condition on crypto purchase     | **Critical** | Backend    | Pattern 1            |
| 3   | KYC state machine bypass              | **Critical** | Backend    | Pattern 2            |
| 4   | Exchange rate client-side trust       | **High**     | Full-Stack | Pattern F2 + Fintech |
| 5   | Insecure token storage on mobile      | **High**     | Mobile     | Pattern M2           |
| 6   | Deep link OAuth callback interception | **High**     | Mobile     | Pattern M3           |
| 7   | Transaction amount accepts negatives  | **Medium**   | Backend    | Pattern 3            |
| 8   | Admin endpoints in production bundle  | **Medium**   | Mobile     | Pattern F5           |
| 9   | Fee percentage unbounded              | **Low**      | Backend    | Fintech              |

### Recommendations Priority

1. **Immediate** (Critical): Fix webhook signature verification, add transaction locking, restrict KYC endpoint to admin
2. **Urgent** (High): Server-side rate enforcement, migrate to secure token storage, switch to Universal/App Links for OAuth
3. **Important** (Medium): Add input validation schema, remove admin endpoints from mobile bundle
4. **Planned** (Low): Add fee range validation
