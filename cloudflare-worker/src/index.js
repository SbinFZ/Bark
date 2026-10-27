/**
 * Serverless Bark Push Server on Cloudflare Workers
 * Domain: https://bark.aboycando.app
 * Bundle ID / APNs Topic: bark.aboycando.app
 * Team: EDGEWISE PTE. LTD. (258YT6DJD6)
 * Official Signature: BySbinAuto v3sj
 */

let cachedJwt = null;
let cachedJwtExp = 0;
let cachedCryptoKey = null;

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function generateShortKey(length = 22) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += BASE58_ALPHABET[bytes[i] % BASE58_ALPHABET.length];
  }
  return out;
}

function base64UrlEncode(input) {
  let bytes;
  if (typeof input === "string") {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else {
    bytes = input;
  }
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function getApnsJwt(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedJwt && now < cachedJwtExp) {
    return cachedJwt;
  }
  if (!env.APNS_P8_KEY) {
    throw new Error("Missing APNS_P8_KEY secret in Worker environment");
  }
  if (!cachedCryptoKey) {
    const keyBuffer = pemToArrayBuffer(env.APNS_P8_KEY);
    cachedCryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  }
  const header = base64UrlEncode(
    JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID || "STYSL54DAQ" })
  );
  const claims = base64UrlEncode(
    JSON.stringify({ iss: env.APNS_TEAM_ID || "258YT6DJD6", iat: now })
  );
  const signingInput = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    cachedCryptoKey,
    new TextEncoder().encode(signingInput)
  );
  cachedJwt = `${signingInput}.${base64UrlEncode(signature)}`;
  cachedJwtExp = now + 3000; // Refresh every 50 minutes
  return cachedJwt;
}

function jsonResponse(code, message, data = undefined, extra = {}) {
  const body = {
    code,
    message,
    timestamp: Math.floor(Date.now() / 1000),
    ...extra,
  };
  if (data !== undefined) {
    body.data = data;
  }
  return new Response(JSON.stringify(body), {
    status: code >= 200 && code < 600 ? code : 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "Content-Type, Authorization",
    },
  });
}

async function parseRequestParams(request, url) {
  const params = {};
  for (const [k, v] of url.searchParams.entries()) {
    params[k] = v;
  }
  if (request.method === "POST" || request.method === "PUT") {
    const contentType = (request.headers.get("content-type") || "").toLowerCase();
    try {
      if (contentType.includes("application/json")) {
        const j = await request.json();
        if (j && typeof j === "object") {
          Object.assign(params, j);
        }
      } else if (
        contentType.includes("application/x-www-form-urlencoded") ||
        contentType.includes("multipart/form-data")
      ) {
        const form = await request.formData();
        for (const [k, v] of form.entries()) {
          params[k] = typeof v === "string" ? v : String(v);
        }
      } else {
        const raw = await request.text();
        if (raw) {
          try {
            const j = JSON.parse(raw);
            if (j && typeof j === "object") Object.assign(params, j);
          } catch {
            for (const [k, v] of new URLSearchParams(raw).entries()) {
              params[k] = v;
            }
          }
        }
      }
    } catch {
      // Ignore body parse errors
    }
  }
  return params;
}

async function handleRegister(request, url, env) {
  const params = await parseRequestParams(request, url);
  const deviceToken = String(
    params.devicetoken || params.device_token || params.deviceToken || ""
  )
    .trim()
    .toLowerCase();
  let key = String(params.key || params.device_key || params.deviceKey || "").trim();

  if (!deviceToken || !/^[0-9a-f]{64,128}$/.test(deviceToken)) {
    return jsonResponse(400, "device token is invalid");
  }

  // Check if key exists or if this deviceToken already has a registered key
  if (key) {
    const existing = await env.BARK_DEVICES.get(`key:${key}`, { type: "json" });
    if (!existing) {
      // If user passed an unknown key or we want to bind it, allow binding
    }
  } else {
    const mappedKey = await env.BARK_DEVICES.get(`token:${deviceToken}`);
    if (mappedKey) {
      key = mappedKey;
    } else {
      key = generateShortKey(22);
    }
  }

  const existingRecord =
    (await env.BARK_DEVICES.get(`key:${key}`, { type: "json" })) || {};
  const record = {
    key,
    device_token: deviceToken,
    apns_env: existingRecord.apns_env || "sandbox",
    updated_at: new Date().toISOString(),
  };

  await env.BARK_DEVICES.put(`key:${key}`, JSON.stringify(record));
  await env.BARK_DEVICES.put(`token:${deviceToken}`, key);

  return jsonResponse(200, "success", {
    key,
    device_key: key,
    device_token: deviceToken,
  });
}

async function resolveDeviceRecord(keyOrToken, env) {
  const clean = String(keyOrToken || "").trim();
  if (!clean) return null;

  const record = await env.BARK_DEVICES.get(`key:${clean}`, { type: "json" });
  if (record && record.device_token) {
    return record;
  }

  // Also allow pushing directly using a raw 64-char hex APNs device token
  if (/^[0-9a-fA-F]{64,128}$/.test(clean)) {
    const tokenLower = clean.toLowerCase();
    const mappedKey = await env.BARK_DEVICES.get(`token:${tokenLower}`);
    if (mappedKey) {
      const mappedRec = await env.BARK_DEVICES.get(`key:${mappedKey}`, {
        type: "json",
      });
      if (mappedRec) return mappedRec;
    }
    return {
      key: tokenLower,
      device_token: tokenLower,
      apns_env: "sandbox",
    };
  }
  return null;
}

function buildApnsPayload(rawParams) {
  // Normalize keys to lowercase for Bark extension compatibility
  const norm = {};
  for (const [k, v] of Object.entries(rawParams)) {
    if (v !== undefined && v !== null && v !== "") {
      norm[k.toLowerCase()] = v;
    }
  }

  const isDelete = String(norm.delete || "") === "1";
  if (isDelete) {
    return {
      isBackground: true,
      payload: {
        aps: {
          "content-available": 1,
          "mutable-content": 1,
        },
        delete: "1",
        id: String(norm.id || ""),
      },
    };
  }

  const title = norm.title !== undefined ? String(norm.title) : undefined;
  const subtitle = norm.subtitle !== undefined ? String(norm.subtitle) : undefined;
  const markdown = norm.markdown !== undefined ? String(norm.markdown) : undefined;
  let body = norm.body !== undefined ? String(norm.body) : undefined;

  if (!body && markdown) {
    body = markdown;
  }
  if (!title && !subtitle && !body && !norm.ciphertext) {
    body = "Notification";
  }

  const levelRaw = String(norm.level || "active");
  const interruptionMap = {
    passive: "passive",
    active: "active",
    timesensitive: "time-sensitive",
    critical: "time-sensitive",
  };
  const interruptionLevel =
    interruptionMap[levelRaw.toLowerCase()] || "active";

  let sound = norm.sound !== undefined ? String(norm.sound) : "1107";
  if (levelRaw.toLowerCase() === "critical" && !norm.sound) {
    sound = "alarm.caf";
  } else if (sound && sound !== "1107" && !sound.endsWith(".caf")) {
    sound = `${sound}.caf`;
  }

  const group = norm.group !== undefined ? String(norm.group) : undefined;

  const aps = {
    alert: {
      ...(title !== undefined ? { title } : {}),
      ...(subtitle !== undefined ? { subtitle } : {}),
      ...(body !== undefined ? { body } : {}),
    },
    sound,
    category: "myNotificationCategory",
    "mutable-content": 1,
    "interruption-level": interruptionLevel,
  };

  if (group) {
    aps["thread-id"] = group;
  }
  if (norm.badge !== undefined) {
    const b = parseInt(norm.badge, 10);
    if (!Number.isNaN(b)) aps.badge = b;
  }

  const extFields = {};
  const passthroughKeys = [
    "group",
    "level",
    "icon",
    "image",
    "url",
    "markdown",
    "copy",
    "autocopy",
    "isarchive",
    "call",
    "volume",
    "ciphertext",
    "id",
    "action",
    "ttl",
  ];
  for (const k of passthroughKeys) {
    if (norm[k] !== undefined) {
      extFields[k] = String(norm[k]);
    }
  }
  if (levelRaw.toLowerCase() === "critical" && !extFields.call) {
    extFields.call = "1";
  }

  return {
    isBackground: false,
    id: extFields.id,
    ttl: norm.ttl ? parseInt(norm.ttl, 10) : undefined,
    payload: {
      aps,
      ...extFields,
    },
  };
}

async function sendToApns(deviceRecord, apnsData, env) {
  const jwt = await getApnsJwt(env);
  const topic = env.APNS_TOPIC || "bark.aboycando.app";
  const primaryEnv = deviceRecord.apns_env || "sandbox";
  const fallbackEnv = primaryEnv === "sandbox" ? "production" : "sandbox";

  async function attempt(targetEnv) {
    const host =
      targetEnv === "sandbox"
        ? "https://api.sandbox.push.apple.com"
        : "https://api.push.apple.com";
    const headers = {
      authorization: `bearer ${jwt}`,
      "apns-topic": topic,
      "apns-push-type": apnsData.isBackground ? "background" : "alert",
      "apns-priority": apnsData.isBackground ? "5" : "10",
    };
    if (apnsData.id && /^[0-9a-fA-F-]{36}$/.test(apnsData.id)) {
      headers["apns-id"] = apnsData.id;
    }
    const resp = await fetch(`${host}/3/device/${deviceRecord.device_token}`, {
      method: "POST",
      headers,
      body: JSON.stringify(apnsData.payload),
    });
    const text = await resp.text();
    let json = {};
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { raw: text };
    }
    return {
      ok: resp.status === 200,
      status: resp.status,
      reason: json.reason || text || "",
      apnsId: resp.headers.get("apns-id") || "",
      env: targetEnv,
    };
  }

  let res = await attempt(primaryEnv);
  if (
    !res.ok &&
    (res.reason === "BadDeviceToken" ||
      res.reason === "BadEnvironmentKeyInToken" ||
      res.reason === "DeviceTokenNotForTopic")
  ) {
    const retryRes = await attempt(fallbackEnv);
    if (retryRes.ok) {
      res = retryRes;
      if (deviceRecord.key && deviceRecord.key.length < 64) {
        deviceRecord.apns_env = fallbackEnv;
        deviceRecord.updated_at = new Date().toISOString();
        await env.BARK_DEVICES.put(
          `key:${deviceRecord.key}`,
          JSON.stringify(deviceRecord)
        );
      }
    }
  }
  return res;
}

async function handlePush(params, env) {
  const keys = [];
  if (Array.isArray(params.device_keys)) {
    keys.push(...params.device_keys);
  } else if (typeof params.device_keys === "string" && params.device_keys) {
    try {
      const parsed = JSON.parse(params.device_keys);
      if (Array.isArray(parsed)) keys.push(...parsed);
      else keys.push(...params.device_keys.split(","));
    } catch {
      keys.push(...params.device_keys.split(","));
    }
  }
  const singleKey = params.device_key || params.key || params.deviceKey;
  if (singleKey) {
    keys.push(singleKey);
  }

  const uniqueKeys = [...new Set(keys.map((k) => String(k).trim()).filter(Boolean))];
  if (uniqueKeys.length === 0) {
    return jsonResponse(400, "device key is empty");
  }

  const apnsData = buildApnsPayload(params);
  const results = [];

  for (const k of uniqueKeys) {
    const rec = await resolveDeviceRecord(k, env);
    if (!rec) {
      results.push({ device_key: k, code: 400, message: `failed to get device token: ${k}` });
      continue;
    }
    const apnsRes = await sendToApns(rec, apnsData, env);
    results.push({
      device_key: k,
      code: apnsRes.ok ? 200 : apnsRes.status || 400,
      message: apnsRes.ok ? "success" : apnsRes.reason || "APNs push failed",
      apns_id: apnsRes.apnsId,
      env: apnsRes.env,
    });
  }

  if (results.length === 1) {
    const r = results[0];
    if (r.code === 200) {
      return jsonResponse(200, "success");
    }
    return jsonResponse(r.code, r.message);
  }

  return jsonResponse(200, "success", results);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "Content-Type, Authorization",
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (path === "/ping") {
        return jsonResponse(200, "pong");
      }

      if (path === "/healthz") {
        return new Response("ok", { status: 200 });
      }

      if (path === "/info" || path === "/") {
        return jsonResponse(200, "success", {
          version: "v2.2.6-cloudflare-worker",
          build: "2026-10-27",
          arch: "cloudflare-edge/v8",
          commit: "BySbinAuto v3sj",
          topic: env.APNS_TOPIC || "bark.aboycando.app",
        });
      }

      if (path === "/register") {
        return await handleRegister(request, url, env);
      }

      const params = await parseRequestParams(request, url);

      if (path === "/push") {
        return await handlePush(params, env);
      }

      // Path routing: /:device_key, /:device_key/:body, /:device_key/:title/:body, /:device_key/:title/:subtitle/:body
      const segments = path
        .slice(1)
        .split("/")
        .map((s) => {
          try {
            return decodeURIComponent(s.replace(/\+/g, "%20"));
          } catch {
            return s;
          }
        });

      if (segments.length >= 1 && segments[0]) {
        params.device_key = segments[0];
        if (segments.length === 2) {
          params.body = segments[1];
        } else if (segments.length === 3) {
          params.title = segments[1];
          params.body = segments[2];
        } else if (segments.length >= 4) {
          params.title = segments[1];
          params.subtitle = segments[2];
          params.body = segments.slice(3).join("/");
        }
        return await handlePush(params, env);
      }

      return jsonResponse(404, "not found");
    } catch (err) {
      return jsonResponse(500, `internal error: ${err.message || String(err)}`);
    }
  },
};
