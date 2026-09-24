import { connect } from "cloudflare:sockets";
const GLOBAL_TRAFFIC_CACHE = new Map();
const GLOBAL_USER_MULTIPLIER = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_ACTIVE_IPS = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
const LOGIN_ATTEMPTS = new Map();
let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;
const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 128 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 32 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 128 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const DNS_CACHE_MAX_ENTRIES = 2048;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function parseTrafficMultiplier(value) {
	if (value === null || value === undefined || value === "") return 1;
	const n = parseFloat(value);
	if (!isFinite(n) || n <= 0) return 1;
	// clamp extreme values
	if (n > 1000) return 1000;
	return n;
}
function formatTrafficMultiplierBadge(value) {
	const n = parseTrafficMultiplier(value);
	// show up to 2 decimal places without trailing zeros
	const s = (Math.round(n * 100) / 100).toString();
	return s + "X";
}
function getEffectiveTrafficGb(realGb, multiplier) {
	const m = parseTrafficMultiplier(multiplier);
	const g = Number(realGb) || 0;
	return g * m;
}
function getLiveRealGb(user) {
	if (!user || !user.username) return Number(user && user.used_gb) || 0;
	return (Number(user.used_gb) || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
}
function getLiveDailyRealGb(user) {
	if (!user || !user.username) return Number(user && user.daily_used_gb) || 0;
	return (Number(user.daily_used_gb) || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
}

const TLS_PORTS = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);
function safeDecodeURI(value) {
	try {
		return decodeURIComponent(value);
	} catch (e) {
		return value;
	}
}
async function readJsonBody(request) {
	try {
		const body = await request.json();
		return body && typeof body === "object" ? body : {};
	} catch (e) {
		return {};
	}
}
async function fetchWithFallback(path, options = {}) {
	const primaryUrl = `https://hoplimit.shop/${path}`;
	const fallbackUrl = `https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/main/${path}`;
	try {
		const res = await fetch(primaryUrl, options);
		if (res.ok) return res;
	} catch (e) { }
	return await fetch(fallbackUrl, options);
}
async function fetchUpdateSource(path, options = {}) {
	const url = `https://raw.githubusercontent.com/sepehr-gamer/Caspian-pannel/main/${path}`;
	return await fetch(url, options);
}
const PANEL_VERSION = "5.2.0";
const TEHRAN_OFFSET_MS = (3 * 60 + 30) * 60 * 1000;
const DAILY_RESET_HOUR = 3;
const DAILY_RESET_MINUTE = 30;
function getLastDailyResetBoundary(nowMs) {
	const tehranNow = nowMs + TEHRAN_OFFSET_MS;
	const dayMs = 86400000;
	const tehranMidnight = Math.floor(tehranNow / dayMs) * dayMs;
	let boundaryTehran = tehranMidnight + (DAILY_RESET_HOUR * 60 + DAILY_RESET_MINUTE) * 60 * 1000;
	if (boundaryTehran > tehranNow) boundaryTehran -= dayMs;
	return boundaryTehran - TEHRAN_OFFSET_MS;
}
function getNextDailyLockBoundary(nowMs) {
	return getLastDailyResetBoundary(nowMs) + 86400000;
}
async function evaluateDailyLock(env, user, username, liveDailyGb, ctx) {
	const now = Date.now();
	if (!user.daily_limit_gb || user.daily_limit_gb <= 0) return false;
	if (user.daily_lock_until && now < user.daily_lock_until) return true;
	const step = user.daily_lock_step || 0;
	if (liveDailyGb >= step + user.daily_limit_gb) {
		const lockKey = username + "_daily_lock";
		if (!GLOBAL_WRITE_LOCK.get(lockKey)) {
			GLOBAL_WRITE_LOCK.set(lockKey, true);
			const newStep = Math.floor(liveDailyGb / user.daily_limit_gb) * user.daily_limit_gb;
			const lockUntil = getNextDailyLockBoundary(now);
			user.daily_lock_until = lockUntil;
			user.daily_lock_step = newStep;
			const writeLock = async () => {
				try {
					await env.DB.prepare("UPDATE users SET daily_lock_until = ?, daily_lock_step = ? WHERE username = ?").bind(lockUntil, newStep, username).run();
				} finally {
					GLOBAL_WRITE_LOCK.delete(lockKey);
				}
			};
			if (ctx) ctx.waitUntil(writeLock());
			else writeLock();
		}
		return true;
	}
	return false;
}
function getTehranDayKey(nowMs) {
	const tehran = new Date(nowMs + TEHRAN_OFFSET_MS);
	const y = tehran.getUTCFullYear();
	const m = String(tehran.getUTCMonth() + 1).padStart(2, "0");
	const d = String(tehran.getUTCDate()).padStart(2, "0");
	return y + "-" + m + "-" + d;
}
async function ensureTrafficDailyTable(env) {
	try {
		await env.DB.prepare("CREATE TABLE IF NOT EXISTS traffic_daily (day_key TEXT PRIMARY KEY, total_gb REAL DEFAULT 0, updated_at INTEGER DEFAULT 0)").run();
	} catch (e) {}
}
async function recordPanelDailyTraffic(env, deltaGb) {
	if (!deltaGb || !(deltaGb > 0)) return;
	const dayKey = getTehranDayKey(Date.now());
	const now = Date.now();
	try {
		await ensureTrafficDailyTable(env);
		const row = await env.DB.prepare("SELECT total_gb FROM traffic_daily WHERE day_key = ?").bind(dayKey).first();
		if (row) {
			await env.DB.prepare("UPDATE traffic_daily SET total_gb = ?, updated_at = ? WHERE day_key = ?").bind((Number(row.total_gb) || 0) + deltaGb, now, dayKey).run();
		} else {
			await env.DB.prepare("INSERT INTO traffic_daily (day_key, total_gb, updated_at) VALUES (?, ?, ?)").bind(dayKey, deltaGb, now).run();
		}
	} catch (e) {
		try {
			await ensureTrafficDailyTable(env);
			await env.DB.prepare("INSERT INTO traffic_daily (day_key, total_gb, updated_at) VALUES (?, ?, ?)").bind(dayKey, deltaGb, now).run();
		} catch (e2) {}
	}
}
let localLastAutoResetCheck = 0;
async function checkAutoResets(env, ctx) {
	const now = Date.now();
	if (now - localLastAutoResetCheck < 3600000) return;
	try {
		const cache = caches.default;
		const cacheReq = new Request("https://internal.caspian/auto_reset");
		if (await cache.match(cacheReq)) return;
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_auto_reset_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 3600000) {
			localLastAutoResetCheck = dbLastCheck;
			const ttl = Math.floor((3600000 - (now - dbLastCheck)) / 1000);
			if (ttl > 0 && ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": `max-age=${ttl}` } })));
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_auto_reset_check', ?)").bind(String(now)).run();
		localLastAutoResetCheck = now;
		if (ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": "max-age=3600" } })));
		const todayUtc = Math.floor(now / 86400000) * 86400000;
		await env.DB.prepare(`UPDATE users SET used_gb = 0, is_active = 1, last_reset_vol_time = ? WHERE auto_reset_vol_days > 0 AND ? >= (last_reset_vol_time + (auto_reset_vol_days * 86400000))`).bind(todayUtc, todayUtc).run();
		await env.DB.prepare(`UPDATE users SET used_req = 0, is_active = 1, last_reset_req_time = ? WHERE auto_reset_req_days > 0 AND ? >= (last_reset_req_time + (auto_reset_req_days * 86400000))`).bind(todayUtc, todayUtc).run();
	} catch (e) { }
}
let GLOBAL_IPS_CACHE = {};
let GLOBAL_IPS_LAST_FETCH = 0;
async function getCachedIps() {
	const now = Date.now();
	if (now - GLOBAL_IPS_LAST_FETCH < 86400000 && Object.keys(GLOBAL_IPS_CACHE).length > 0) {
		return GLOBAL_IPS_CACHE;
	}
	try {
		const res = await fetchWithFallback("ips.txt");
		if (!res.ok) return GLOBAL_IPS_CACHE;
		const text = await res.text();
		const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0 && !l.includes("#") && !l.startsWith("[source"));
		if (lines.length > 0) {
			GLOBAL_IPS_CACHE = { "all": lines };
			GLOBAL_IPS_LAST_FETCH = now;
		}
	} catch (e) {}
	return GLOBAL_IPS_CACHE;
}
function getRandomIps(cachedIpsData, operator, count) {
	let availableIps = [];
	Object.values(cachedIpsData).forEach((ips) => (availableIps = availableIps.concat(ips)));
	availableIps = [...new Set(availableIps)];
	if (availableIps.length === 0) return [];
	if (count >= availableIps.length) return availableIps;
	const shuffled = availableIps.slice();
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled.slice(0, count);
}
async function checkAutoRotates(env, ctx) {
}
let cachedVipCountries = [];
let lastVipCountriesFetch = 0;
async function replaceBrokenProxy(username, env, oldProxy) {
	try {
		if (GLOBAL_WRITE_LOCK.get(username + "_proxy_rotate")) return;
		GLOBAL_WRITE_LOCK.set(username + "_proxy_rotate", true);
		
		const user = await env.DB.prepare("SELECT id, user_socks5, auto_rotate_user_proxy FROM users WHERE username = ?").bind(username).first();
		if (!user || user.auto_rotate_user_proxy !== 1 || !user.user_socks5) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		let proxyList = [];
		let isArrayMode = false;
		try {
			if (user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
				isArrayMode = true;
			} else {
				proxyList = [user.user_socks5];
			}
		} catch (e) {
			proxyList = [user.user_socks5];
		}
		
		let matchIndex = -1;
		for (let i = 0; i < proxyList.length; i++) {
			let itemStr = typeof proxyList[i] === "object" && proxyList[i] !== null ? proxyList[i].proxy : proxyList[i];
			if (itemStr === oldProxy) {
				matchIndex = i;
				break;
			}
		}
		if (matchIndex === -1) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		let countryCode = typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null && proxyList[matchIndex].country ? proxyList[matchIndex].country : "all";
		
		if (countryCode === "all" || countryCode === "UN") {
			try {
				const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
				const s = await connectProxy(oldProxy, "ip-api.com", 80, payload);
				const reader = s.readable.getReader();
				let resStr = "";
				const dec = new TextDecoder();
				const timeoutId = setTimeout(() => {
					try { s.close(); } catch (e) { }
				}, 2000);
				try {
					while (true) {
						const res = await reader.read();
						if (res.done || !res.value) break;
						resStr += dec.decode(res.value, { stream: true });
						if (resStr.includes("countryCode")) break;
					}
				} finally {
					clearTimeout(timeoutId);
					try { s.close(); } catch (e) { }
				}
				const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
				if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
			} catch (e) { }
			
			if (countryCode === "all" || countryCode === "UN") {
				try {
					let remain = oldProxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) remain = remain.substring(1, remain.indexOf("]"));
					else if (remain.includes(":")) remain = remain.substring(0, remain.lastIndexOf(":"));
					const geoRes = await fetch(`http://ip-api.com/json/${remain}?fields=countryCode`);
					const geoData = await geoRes.json();
					if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
				} catch (e) { }
			}
		}
		
		let newProxy = null;
		let finalCountry = null;
		const upperCountry = (countryCode || "ALL").toUpperCase();
		const sources = [];
		const isOldProxyVIP = oldProxy.includes("@") || oldProxy.includes("t.me/");
		
		if (cachedVipCountries.length === 0 || Date.now() - lastVipCountriesFetch > 3600000) {
			try {
				const ghRes = await fetchWithFallback("vip-list", {
					headers: { "User-Agent": "Mozilla/5.0" },
				});
				if (ghRes.ok) {
					const files = await ghRes.json();
					cachedVipCountries = files.filter((f) => f.name.endsWith(".txt")).map((f) => f.name.replace(".txt", "").toUpperCase());
					lastVipCountriesFetch = Date.now();
				}
			} catch (e) { }
		}
		
		let fallbackVIPs = cachedVipCountries.length > 0 ? [...cachedVipCountries] : ["DE", "US", "GB", "NL", "FR", "TR"];
		for (let i = fallbackVIPs.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[fallbackVIPs[i], fallbackVIPs[j]] = [fallbackVIPs[j], fallbackVIPs[i]];
		}
		
		if (upperCountry !== "ALL" && upperCountry !== "UN") {
			sources.push({ url: `proxy_vip/${upperCountry}.txt`, type: "repo", country: upperCountry });
		}
		for (const fc of fallbackVIPs) {
			if (fc !== upperCountry) {
				sources.push({ url: `proxy_vip/${fc}.txt`, type: "repo", country: fc });
			}
		}
		
		if (!isOldProxyVIP) {
			if (upperCountry !== "ALL" && upperCountry !== "UN") {
				sources.push({ url: `proxy/${upperCountry}.txt`, type: "repo", country: upperCountry });
			}
			sources.push({ url: `proxy/ALL.txt`, type: "repo", country: "ALL" });
		}
		
		for (const src of sources) {
			try {
				const res = await fetchWithFallback(src.url);
				if (!res.ok) continue;
				const text = await res.text();
				const lines = text
					.split("\n")
					.map((l) => l.trim())
					.filter((l) => l.length > 5);
					
				if (lines.length > 0) {
					for (let i = lines.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[lines[i], lines[j]] = [lines[j], lines[i]];
					}
					
					const testLimit = (src.country === upperCountry) ? 15 : 3;
					
					const testBatch = lines.slice(0, testLimit).flatMap((line) => {
						if (line.match(/^(socks4|socks5|socks|http|https|tg):\/\//i) || line.includes("t.me/socks")) {
							return [line];
						}
						if (src.type === "socks5") return [`socks5://${line}`];
						if (src.type === "http") return [`http://${line}`];
						return [`socks5://${line}`, `http://${line}`];
					});
					
					try {
						newProxy = await Promise.any(
							testBatch.map((p) => {
								return new Promise(async (resolve, reject) => {
									let sock = null;
									const timeoutId = setTimeout(() => {
										try { sock && sock.close(); } catch (e) { }
										reject(new Error("timeout"));
									}, 4000); 
									try {
										const payload = TEXT_ENCODER.encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
										sock = await connectProxy(p, "1.1.1.1", 80, payload);
										const reader = sock.readable.getReader();
										const res = await reader.read();
										clearTimeout(timeoutId);
										try { sock.close(); } catch (e) { }
										if (res.done || !res.value) reject(new Error("empty"));
										else resolve(p);
									} catch (e) {
										clearTimeout(timeoutId);
										try { sock && sock.close(); } catch (err) { }
										reject(e);
									}
								});
							})
						);
					} catch (e) {
						continue;
					}
					
					if (newProxy) {
						finalCountry = src.country; 
						break;
					}
				}
			} catch (e) { }
		}
		
		if (newProxy) {
			let finalProxyVal = newProxy;
			if (isArrayMode) {
				if (typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null) {
					proxyList[matchIndex].proxy = newProxy;
					if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
						proxyList[matchIndex].country = finalCountry;
					}
				} else {
					if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
						proxyList[matchIndex] = { proxy: newProxy, country: finalCountry };
					} else {
						proxyList[matchIndex] = newProxy;
					}
				}
				finalProxyVal = JSON.stringify(proxyList);
			} else {
				if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
					finalProxyVal = JSON.stringify([{ proxy: newProxy, country: finalCountry }]);
				}
			}
			await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE id = ?").bind(finalProxyVal, user.id).run();
		}
	} catch (e) {
	} finally {
		GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
	}
}
const SSCrypto = {
	async evpBytesToKey(password, keyLen) {
		const pass = new TextEncoder().encode(password);
		const key = new Uint8Array(keyLen);
		let hash = new Uint8Array(0);
		let offset = 0;
		while (offset < keyLen) {
			const data = new Uint8Array(hash.length + pass.length);
			data.set(hash);
			data.set(pass, hash.length);
			const digest = await crypto.subtle.digest("MD5", data);
			hash = new Uint8Array(digest);
			const len = Math.min(hash.length, keyLen - offset);
			key.set(hash.slice(0, len), offset);
			offset += len;
		}
		return key;
	},
	async deriveSubkey(password, salt) {
		const masterKey = await this.evpBytesToKey(password, 32);
		const keyMaterial = await crypto.subtle.importKey(
			"raw", masterKey, { name: "HKDF" }, false, ["deriveKey"]
		);
		return await crypto.subtle.deriveKey(
			{ name: "HKDF", hash: "SHA-1", salt: salt, info: new TextEncoder().encode("ss-subkey") },
			keyMaterial,
			{ name: "AES-GCM", length: 256 },
			false,
			["encrypt", "decrypt"]
		);
	},
	incrementNonce(nonce) {
		for (let i = 0; i < nonce.length; i++) {
			nonce[i]++;
			if (nonce[i] !== 0) break;
		}
	},
	async decryptChunk(key, nonce, encryptedData) {
		try {
			const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, encryptedData);
			this.incrementNonce(nonce);
			return new Uint8Array(decrypted);
		} catch (e) {
			return null;
		}
	},
	async encryptChunk(key, nonce, data) {
		try {
			const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data);
			this.incrementNonce(nonce);
			return new Uint8Array(encrypted);
		} catch (e) {
			return null;
		}
	}
};
export default {
	async fetch(request, env, ctx) {
		if (!env.DB) {
			return new Response("Database binding 'DB' is missing in Cloudflare Workers settings.", { status: 500 });
		}
		try {
			try {
				await DbService.ensureSchema(env.DB);
			} catch (e) { }
			trackRequest(env, ctx);
			if (schemaEnsured) {
				ctx.waitUntil(checkAutoResets(env, ctx));
				ctx.waitUntil(checkAutoRotates(env, ctx));
			}
			const url = new URL(request.url);
			if (Router.isWebSocketUpgrade(request)) {
				return await Router.handleWebSocket(request, env, ctx);
			}
			if (Router.isSubscriptionPath(url.pathname)) {
				return await Router.handleSubscription(url, env);
			}
			if (url.pathname === "/icon.svg" || url.pathname === "/favicon.ico" || url.pathname === "/icon.png" || url.pathname === "/apple-touch-icon.png") {
				return new Response(CASPIAN_ICON_SVG, {
					headers: {
						"Content-Type": "image/svg+xml; charset=utf-8",
						"Cache-Control": "public, max-age=604800, immutable",
					},
				});
			}
			if (url.pathname === "/manifest.json") {
				return new Response(PWA_MANIFEST, {
					headers: {
						"Content-Type": "application/manifest+json; charset=utf-8",
						"Cache-Control": "public, max-age=86400",
					},
				});
			}
			if (url.pathname === "/sw.js") {
				return new Response(PWA_SERVICE_WORKER, {
					headers: {
						"Content-Type": "application/javascript; charset=utf-8",
						"Cache-Control": "no-cache",
					},
				});
			}
			if (url.pathname.startsWith("/api/")) {
				return await Router.handleApi(request, url, env, ctx);
			}
			if (url.pathname === "/panel" || url.pathname === "/login") {
				return await Router.handlePanel(request, env);
			}
			if (url.pathname.startsWith("/status/")) {
				return await Router.handleUserStatus(request, url, env);
			}
			let gfxSetting = 'false';
			try {
				const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
				if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
			} catch (e) {}
			return new Response(HTML_TEMPLATES.nginx.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			let msg = err.message || "";
			if (msg.toLowerCase().includes("d1") && (msg.toLowerCase().includes("limit") || msg.toLowerCase().includes("exceeded") || msg.toLowerCase().includes("daily row"))) {
				return new Response(JSON.stringify({ error: "سهمیه دیتابیس شما تمام شده و ساعت 3:30 درست میشه" }), { 
					status: 500, 
					headers: { "Content-Type": "application/json; charset=utf-8" } 
				});
			}
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	// این تابع توسط Cron Trigger کلادفلر اجرا می‌شود (هر ۳ ساعت یک‌بار طبق
	// تنظیمات wrangler.toml / پنل Triggers در داشبورد ورکر). اپراتور کاربران
	// آنلاین را دوباره از روی active_ips تازه می‌کند و رکوردهای قدیمی/منقضی
	// (بیش از ۲۴ ساعت بدون دیده‌شدن) را از connected_operators پاک می‌کند.
	async scheduled(event, env, ctx) {
		if (!env.DB) return;
		try {
			ctx.waitUntil(refreshAllUsersOperators(env));
		} catch (e) {}
	},
};
const CASPIAN_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <radialGradient id="caspianBg" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#0e2348"/>
      <stop offset="100%" stop-color="#020617"/>
    </radialGradient>
    <filter id="caspianGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="0" stdDeviation="16" flood-color="#3b82f6" flood-opacity="0.6"/>
    </filter>
  </defs>
  <rect width="512" height="512" rx="128" fill="#000000"/>
  <rect x="48" y="48" width="416" height="416" rx="96" fill="url(#caspianBg)" stroke="#3b82f6" stroke-width="16" filter="url(#caspianGlow)"/>
  <rect x="56" y="56" width="400" height="400" rx="88" fill="none" stroke="#60a5fa" stroke-width="4" stroke-opacity="0.4"/>
  <g transform="translate(128, 128) scale(10.666)" filter="url(#caspianGlow)">
    <path d="M13 10V3L4 14h7v7l9-11h-7z" fill="#38bdf8" fill-opacity="0.3" stroke="#60a5fa" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
</svg>`;
const PWA_MANIFEST = JSON.stringify({
	name: "CASPIAN Panel",
	short_name: "CASPIAN Panel",
	description: "پنل مدیریت پیشرفته کانفیگ و کاربران کاسپین",
	start_url: "/panel",
	scope: "/",
	display: "standalone",
	background_color: "#000000",
	theme_color: "#000000",
	dir: "rtl",
	lang: "fa-IR",
	orientation: "any",
	icons: [
		{
			src: "/icon.svg",
			sizes: "192x192 512x512",
			type: "image/svg+xml",
			purpose: "any maskable"
		},
		{
			src: "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%20512%20512%22%20width%3D%22512%22%20height%3D%22512%22%3E%0A%20%20%3Cdefs%3E%0A%20%20%20%20%3CradialGradient%20id%3D%22caspianBg%22%20cx%3D%2250%25%22%20cy%3D%2250%25%22%20r%3D%2250%25%22%3E%0A%20%20%20%20%20%20%3Cstop%20offset%3D%220%25%22%20stop-color%3D%22%230e2348%22%2F%3E%0A%20%20%20%20%20%20%3Cstop%20offset%3D%22100%25%22%20stop-color%3D%22%23020617%22%2F%3E%0A%20%20%20%20%3C%2FradialGradient%3E%0A%20%20%20%20%3Cfilter%20id%3D%22caspianGlow%22%20x%3D%22-20%25%22%20y%3D%22-20%25%22%20width%3D%22140%25%22%20height%3D%22140%25%22%3E%0A%20%20%20%20%20%20%3CfeDropShadow%20dx%3D%220%22%20dy%3D%220%22%20stdDeviation%3D%2216%22%20flood-color%3D%22%233b82f6%22%20flood-opacity%3D%220.6%22%2F%3E%0A%20%20%20%20%3C%2Ffilter%3E%0A%20%20%3C%2Fdefs%3E%0A%20%20%3Crect%20width%3D%22512%22%20height%3D%22512%22%20rx%3D%22128%22%20fill%3D%22%23000000%22%2F%3E%0A%20%20%3Crect%20x%3D%2248%22%20y%3D%2248%22%20width%3D%22416%22%20height%3D%22416%22%20rx%3D%2296%22%20fill%3D%22url(%23caspianBg)%22%20stroke%3D%22%233b82f6%22%20stroke-width%3D%2216%22%20filter%3D%22url(%23caspianGlow)%22%2F%3E%0A%20%20%3Crect%20x%3D%2256%22%20y%3D%2256%22%20width%3D%22400%22%20height%3D%22400%22%20rx%3D%2288%22%20fill%3D%22none%22%20stroke%3D%22%2360a5fa%22%20stroke-width%3D%224%22%20stroke-opacity%3D%220.4%22%2F%3E%0A%20%20%3Cg%20transform%3D%22translate(128%2C%20128)%20scale(10.666)%22%20filter%3D%22url(%23caspianGlow)%22%3E%0A%20%20%20%20%3Cpath%20d%3D%22M13%2010V3L4%2014h7v7l9-11h-7z%22%20fill%3D%22%2338bdf8%22%20fill-opacity%3D%220.3%22%20stroke%3D%22%2360a5fa%22%20stroke-width%3D%221.6%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%2F%3E%0A%20%20%3C%2Fg%3E%0A%3C%2Fsvg%3E",
			sizes: "192x192 512x512",
			type: "image/svg+xml",
			purpose: "any maskable"
		}
	],
	categories: ["utilities", "productivity"]
});
const PWA_SERVICE_WORKER = `
const CACHE_NAME = "caspian-pwa-cache-v1";
const STATIC_ASSETS = [
	"https://cdn.tailwindcss.com",
	"https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js",
	"https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js",
	"https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css",
	"https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css"
];
self.addEventListener("install", (e) => {
	self.skipWaiting();
	e.waitUntil(
		caches.open(CACHE_NAME).then((cache) => {
			return cache.addAll(STATIC_ASSETS).catch(() => {});
		})
	);
});
self.addEventListener("activate", (e) => {
	e.waitUntil(
		caches.keys().then((keys) => {
			return Promise.all(
				keys.map((k) => {
					if (k !== CACHE_NAME) return caches.delete(k);
				})
			);
		}).then(() => self.clients.claim())
	);
});
self.addEventListener("fetch", (e) => {
	const url = new URL(e.request.url);
	if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/sub/") || url.pathname.startsWith("/feed/") || url.pathname.startsWith("/clash/") || url.pathname.startsWith("/yaml/") || url.pathname.startsWith("/status/") || url.pathname.startsWith("/stream/")) {
		return;
	}
	if (STATIC_ASSETS.includes(e.request.url)) {
		e.respondWith(
			caches.match(e.request).then((cached) => cached || fetch(e.request).then((res) => {
				const clone = res.clone();
				caches.open(CACHE_NAME).then((cache) => cache.put(e.request, clone));
				return res;
			}))
		);
	}
});
`;

async function cleanupAccessLogs(env) {
	try {
		const cutoff = Date.now() - 24 * 60 * 60 * 1000;
		await env.DB.prepare("DELETE FROM access_logs WHERE created_at < ?").bind(cutoff).run();
	} catch (e) { }
}
async function recordAccessLog(env, request) {
	try {
		const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
		const ua = (request.headers.get("User-Agent") || "").slice(0, 300);
		const now = Date.now();
		await env.DB.prepare("INSERT INTO access_logs (ip, user_agent, created_at) VALUES (?, ?, ?)").bind(ip, ua, now).run();
		// opportunistic cleanup (~10%)
		if (Math.random() < 0.1) await cleanupAccessLogs(env);
	} catch (e) { }
}


function detectOperatorByIp(ip) {
	if (!ip || ip === "unknown") return null;
	let clean = String(ip).split(",")[0].trim();
	// strip CIDR / IPv6 compressed forms for comparison
	if (clean.includes("/")) clean = clean.split("/")[0];
	// IPv4 only for range tables
	const v4 = clean.includes(":") ? null : clean;
	if (!v4) return null;
	const parts = v4.split(".");
	if (parts.length !== 4) return null;
	const a = parseInt(parts[0], 10), b = parseInt(parts[1], 10), c = parseInt(parts[2], 10);
	if ([a,b,c].some(x => isNaN(x))) return null;

	// همراه اول (MCI) — common ranges
	if (
		(a === 5 && (b === 22 || b === 52 || b === 106 || (b >= 208 && b <= 216))) ||
		(a === 31 && (b === 2 || b === 14 || b === 56)) ||
		(a === 37 && (b === 129 || b === 254)) ||
		(a === 46 && (b === 51 || b === 100 || b === 209)) ||
		(a === 83 && b === 123) ||
		(a === 86 && (b === 55 || b === 57)) ||
		(a === 89 && (b === 165 || b === 196 || b === 198 || b === 235)) ||
		(a === 91 && (b === 98 || b === 99 || b === 133)) ||
		(a === 94 && b === 182) ||
		(a === 113 && b === 203) ||
		(a === 151 && b === 232) ||
		(a === 188 && b === 158) ||
		(a === 217 && b === 218)
	) return "همراه اول";

	// ایرانسل (MTN Irancell)
	if (
		(a === 2 && (b >= 144 && b <= 147)) ||
		(a === 5 && b >= 112 && b <= 127) ||
		(a === 11 && b === 0) ||
		(a === 37 && (b === 156 || b === 255)) ||
		(a === 78 && b === 38) ||
		(a === 92 && b === 114) ||
		(a === 151 && (b === 232 || b === 234 || b === 238)) ||
		(a === 188 && (b === 208 || b === 209 || b === 210 || b === 211 || b === 212 || b === 213 || b === 214 || b === 215)) ||
		(a === 223 && b === 25)
	) return "ایرانسل";

	// رایتل
	if (
		(a === 5 && (b === 72 || b === 73 || (b === 62 && c >= 192) || (b === 134 && c >= 128))) ||
		(a === 37 && b === 137) ||
		(a === 95 && b === 162) ||
		(a === 188 && b === 213)
	) return "رایتل";

	// مخابرات / ایران
	if (
		(a === 5 && (b === 53 || b === 74 || b === 75 || (b === 62 && c < 192))) ||
		(a === 2 && b === 176) ||
		(a === 79 && b === 175) ||
		(a === 85 && b === 15) ||
		(a === 91 && b >= 98 && b <= 99) ||
		(a === 217 && (b === 219 || b === 218))
	) return "مخابرات";

	// شاتل
	if ((a === 91 && b === 133) || (a === 178 && b === 216) || (a === 5 && b === 160)) return "شاتل";
	// آسیاتک
	if ((a === 78 && b === 39) || (a === 5 && b === 219) || (a === 37 && b === 152)) return "آسیاتک";
	// های‌وب
	if ((a === 5 && b === 232) || (a === 178 && b === 239)) return "های‌وب";

	return null;
}

function detectOperatorFromRequest(request, clientIP) {
	try {
		const cf = (request && request.cf) ? request.cf : {};
		const asn = String(cf.asn || cf.AS || "");
		const org = String(cf.asOrganization || cf.organization || "").toLowerCase();

		const asnMap = {
			"197207": "همراه اول",
			"44244": "ایرانسل",
			"58224": "ایرانسل",
			"57218": "رایتل",
			"49100": "رایتل",
			"12880": "مخابرات",
			"49666": "مخابرات",
			"50810": "شاتل",
			"43754": "آسیاتک",
			"56402": "های‌وب",
			"31549": "پارس‌آنلاین",
			"39501": "مبین‌نت",
			"25124": "فن‌آوا"
		};
		if (asn && asnMap[asn]) return asnMap[asn];

		if (/mci|mobile communication company of iran|hamrah|tci-mci/.test(org)) return "همراه اول";
		if (/mtn|irancell|iran.?cell/.test(org)) return "ایرانسل";
		if (/rightel|raitel/.test(org)) return "رایتل";
		if (/telecommunication company of iran|\btci\b|iran telecom/.test(org)) return "مخابرات";
		if (/shatel/.test(org)) return "شاتل";
		if (/asiatech/.test(org)) return "آسیاتک";
		if (/hiweb|highweb/.test(org)) return "های‌وب";
		if (/pars.?online/.test(org)) return "پارس‌آنلاین";
		if (/mobinnet/.test(org)) return "مبین‌نت";

		const byIp = detectOperatorByIp(clientIP);
		if (byIp) return byIp;

		// قبلاً اینجا نام خام ASN (مثلاً بریده‌ای از asOrganization) برگردانده می‌شد
		// که باعث ثبت نام‌های نامفهوم/بی‌ربط (مثل رشته‌های انگلیسی بریده‌شده) در
		// لیست اپراتورهای متصل کاربر می‌شد. چون این مقدار یک اپراتور واقعی و
		// شناخته‌شده نیست، دیگر آن را برنمی‌گردانیم تا لیست کاربر تمیز بماند.
		return null;
	} catch (e) {}
	return null;
}

// هر ورودی به صورت {name, ts} ذخیره می‌شود تا بشود اپراتورهای قدیمی/اشتباه را
// بعد از مدتی (توسط چک دوره‌ای هر ۳ ساعته) از لیست حذف کرد و لیست همیشه
// نشان‌دهنده‌ی وضعیت واقعی و اخیر باشد، نه هر تشخیص اشتباه یک‌باره‌ای که قبلاً
// برای همیشه در لیست می‌ماند.
const OPERATOR_HISTORY_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 ساعت
async function recordUserOperator(env, username, operator) {
	if (!username || !operator) return;
	try {
		const row = await env.DB.prepare("SELECT connected_operators FROM users WHERE username = ?").bind(username).first();
		let ops = normalizeOperatorHistory(row && row.connected_operators);
		const now = Date.now();
		const existing = ops.find(o => o.name === operator);
		if (existing) {
			existing.ts = now;
		} else {
			ops.push({ name: operator, ts: now });
		}
		ops = ops.filter(o => now - o.ts <= OPERATOR_HISTORY_MAX_AGE_MS);
		if (ops.length > 20) ops = ops.slice(-20);
		await env.DB.prepare("UPDATE users SET connected_operators = ? WHERE username = ?").bind(JSON.stringify(ops), username).run();
	} catch (e) {}
}
// یک لیست connected_operators (چه فرمت قدیمی رشته‌ای، چه فرمت جدید {name, ts}) را
// همیشه به فرمت جدید {name, ts} تبدیل می‌کند.
function normalizeOperatorHistory(raw) {
	let ops = [];
	try { ops = JSON.parse(raw || "[]"); } catch (e) { ops = []; }
	if (!Array.isArray(ops)) return [];
	const now = Date.now();
	return ops.map(o => {
		if (o && typeof o === "object" && o.name) return { name: String(o.name), ts: Number(o.ts) || now };
		if (typeof o === "string") return { name: o, ts: now };
		return null;
	}).filter(Boolean);
}
// هر ۳ ساعت (توسط اجرای Cron) برای همه‌ی کاربران صدا زده می‌شود:
// ۱) اپراتورهای منقضی (قدیمی‌تر از OPERATOR_HISTORY_MAX_AGE_MS) را حذف می‌کند
// ۲) اپراتور فعلیِ IPهای هم‌اکنون متصل (active_ips) را دوباره تشخیص/تازه می‌کند
async function refreshAllUsersOperators(env) {
	try {
		const { results } = await env.DB.prepare("SELECT username, connected_operators, active_ips FROM users WHERE active_ips IS NOT NULL AND active_ips != '' AND active_ips != '{}'").all();
		if (!results || !results.length) return;
		const now = Date.now();
		for (const row of results) {
			try {
				let ops = normalizeOperatorHistory(row.connected_operators);
				let activeIps = {};
				try { activeIps = JSON.parse(row.active_ips || "{}"); } catch (e) { activeIps = {}; }
				let changed = false;
				for (const ip of Object.keys(activeIps)) {
					const entry = activeIps[ip];
					const op = entry && typeof entry === "object" ? entry.operator : null;
					if (!op) continue;
					const existing = ops.find(o => o.name === op);
					if (existing) { existing.ts = now; } else { ops.push({ name: op, ts: now }); changed = true; }
				}
				const before = ops.length;
				ops = ops.filter(o => now - o.ts <= OPERATOR_HISTORY_MAX_AGE_MS);
				if (ops.length !== before) changed = true;
				if (ops.length > 20) { ops = ops.slice(-20); changed = true; }
				if (changed) {
					await env.DB.prepare("UPDATE users SET connected_operators = ? WHERE username = ?").bind(JSON.stringify(ops), row.username).run();
				}
			} catch (e) {}
		}
	} catch (e) {}
}

function parseOsLabel(ua) {
	try {
		const s = String(ua || "");
		if (/android/i.test(s)) return "Android";
		if (/iphone|ipad|ipod/i.test(s)) return "iOS";
		if (/windows nt/i.test(s)) return "Windows";
		if (/mac os x|macintosh/i.test(s)) return "macOS";
		if (/cros/i.test(s)) return "ChromeOS";
		if (/linux/i.test(s)) return "Linux";
		return "Unknown";
	} catch (e) { return "Unknown"; }
}
function generateSessionToken() {
	const arr = new Uint8Array(24);
	crypto.getRandomValues(arr);
	return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function getSessionTokenFromRequest(request) {
	try {
		const cookies = request.headers.get("Cookie") || "";
		const c = cookies.split(";").find((x) => x.trim().startsWith("panel_session="));
		if (!c) return null;
		return c.split("=").slice(1).join("=").trim() || null;
	} catch (e) { return null; }
}
async function ensureSessionTables(env) {
	try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS panel_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, ip TEXT, user_agent TEXT, os_label TEXT, role TEXT DEFAULT 'owner', created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL)").run(); } catch (e) {}
	try { await env.DB.prepare("ALTER TABLE panel_sessions ADD COLUMN role TEXT DEFAULT 'owner'").run(); } catch (e) {}
	try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS panel_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, block_type TEXT NOT NULL, block_value TEXT NOT NULL, label TEXT, created_at INTEGER NOT NULL)").run(); } catch (e) {}
	try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS failed_logins (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user_agent TEXT, os_label TEXT, created_at INTEGER NOT NULL)").run(); } catch (e) {}
}
async function cleanupFailedLogins(env) {
	try {
		const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
		await env.DB.prepare("DELETE FROM failed_logins WHERE created_at < ?").bind(cutoff).run();
	} catch (e) { }
}
async function recordFailedLogin(env, ip, ua, osLabel) {
	try {
		await ensureSessionTables(env);
		await env.DB.prepare("INSERT INTO failed_logins (ip, user_agent, os_label, created_at) VALUES (?, ?, ?, ?)").bind(String(ip || "unknown"), String(ua || "").slice(0, 300), String(osLabel || "Unknown"), Date.now()).run();
		if (Math.random() < 0.1) await cleanupFailedLogins(env);
	} catch (e) { }
}
async function getManagerPasswordHash(env) {
	try {
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'manager_password'").first();
		return row && row.value ? row.value : null;
	} catch (e) { return null; }
}
async function getSessionRole(env, request) {
	try {
		const token = getSessionTokenFromRequest(request);
		if (!token) return null;
		const ownerHash = await DbService.getPanelPassword(env.DB);
		if (ownerHash && token === ownerHash) return "owner";
		await ensureSessionTables(env);
		const row = await env.DB.prepare("SELECT role FROM panel_sessions WHERE token = ? LIMIT 1").bind(token).first();
		if (row && row.role === "manager") return "manager";
		if (row) return "owner";
		return null;
	} catch (e) { return null; }
}
function isOwnerOnlyApi(pathname, method) {
	const p = pathname || "";
	// فقط این بخش‌ها برای رمز مدیریت مسدود است:
	// تنظیمات، دفترچه ورود، افراد داخل پنل، بازنشانی کامل، اطلاعات ورود، ورودهای ناموفق
	if (p === "/api/access-logs") return true;
	if (p === "/api/failed-logins" || p.startsWith("/api/failed-logins/")) return true;
	if (p.startsWith("/api/panel-sessions")) return true;
	if (p.startsWith("/api/panel-blocks")) return true;
	if (p.includes("factory-reset") || p.includes("factory_reset")) return true;
	if (p === "/api/settings" && method !== "GET") return true;
	// امنیت: تغییر رمز مالک و رمز مدیریت فقط برای مالک
	if (p === "/api/change-password") return true;
	if (p === "/api/manager-password") return true;
	return false;
}
async function isPanelBlocked(env, ip, osLabel) {
	try {
		await ensureSessionTables(env);
		if (ip) {
			const r = await env.DB.prepare("SELECT id FROM panel_blocks WHERE block_type = ? AND block_value = ? LIMIT 1").bind("ip", String(ip)).first();
			if (r) return true;
		}
		if (osLabel) {
			const r = await env.DB.prepare("SELECT id FROM panel_blocks WHERE block_type = ? AND block_value = ? LIMIT 1").bind("os", String(osLabel)).first();
			if (r) return true;
		}
	} catch (e) {}
	return false;
}
async function createPanelSession(env, request, role) {
	try {
		await ensureSessionTables(env);
		const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
		const ua = (request.headers.get("User-Agent") || "").slice(0, 400);
		const osLabel = parseOsLabel(ua);
		if (await isPanelBlocked(env, ip, osLabel)) {
			return { error: "دسترسی مسدود شده است" };
		}
		const token = generateSessionToken();
		const now = Date.now();
		const r = (role === "manager") ? "manager" : "owner";
		try {
			await env.DB.prepare("INSERT INTO panel_sessions (token, ip, user_agent, os_label, role, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(token, String(ip).split(",")[0].trim(), ua, osLabel, r, now, now).run();
		} catch (e) {
			await env.DB.prepare("INSERT INTO panel_sessions (token, ip, user_agent, os_label, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)").bind(token, String(ip).split(",")[0].trim(), ua, osLabel, now, now).run();
		}
		return { token, ip: String(ip).split(",")[0].trim(), osLabel, role: r };
	} catch (e) {
		return { error: "خطا در نشست" };
	}
}
/** Ensure current request has a tracked panel session. Returns { token } if cookie must be updated. */
async function touchOrMigrateSession(env, request, storedPasswordHash) {
	try {
		await ensureSessionTables(env);
		const ip = (request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown").split(",")[0].trim();
		const ua = (request.headers.get("User-Agent") || "").slice(0, 400);
		const osLabel = parseOsLabel(ua);
		if (await isPanelBlocked(env, ip, osLabel)) {
			return { blocked: true };
		}
		const current = getSessionTokenFromRequest(request);
		const now = Date.now();
		if (current && storedPasswordHash && current !== storedPasswordHash) {
			const row = await env.DB.prepare("SELECT id FROM panel_sessions WHERE token = ? LIMIT 1").bind(current).first();
			if (row) {
				try {
					await env.DB.prepare("UPDATE panel_sessions SET last_seen = ?, ip = ?, user_agent = ?, os_label = ? WHERE id = ?").bind(now, ip, ua, osLabel, row.id).run();
				} catch (e) {}
				return { token: null, ok: true };
			}
			// token invalid
			return { invalid: true };
		}
		// legacy password-hash cookie OR missing session row → create real session
		const token = generateSessionToken();
		await env.DB.prepare("INSERT INTO panel_sessions (token, ip, user_agent, os_label, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)").bind(token, ip, ua, osLabel, now, now).run();
		return { token: token, ok: true };
	} catch (e) {
		return { ok: true, token: null };
	}
}

/* ---------------- پیام‌رسانی کاربر <-> مالک پنل ---------------- */
const MSG_MAX_LEN = 1000;
const MSG_THREAD_KEEP = 200;
const MSG_MIN_INTERVAL_MS = 5000;
const MSG_MAX_PENDING = 40;
async function ensureUserMessagesTable(env) {
	try {
		await env.DB.prepare("CREATE TABLE IF NOT EXISTS user_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, sender TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, read_by_owner INTEGER DEFAULT 0, read_by_user INTEGER DEFAULT 0)").run();
	} catch (e) { }
	try {
		await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_user_messages_username ON user_messages (username, id)").run();
	} catch (e) { }
}
function sanitizeMessageBody(raw) {
	let t = String(raw === null || raw === undefined ? "" : raw);
	t = t.replace(/\r/g, "").trim();
	if (t.length > MSG_MAX_LEN) t = t.slice(0, MSG_MAX_LEN);
	return t;
}
function msgJson(obj, status) {
	return new Response(JSON.stringify(obj), {
		status: status || 200,
		headers: { "Content-Type": "application/json; charset=utf-8" },
	});
}
async function findMessageUser(env, username, uuid) {
	const uname = String(username || "").trim();
	const uid = String(uuid || "").trim();
	if (!uname || !uid) return null;
	try {
		const user = await env.DB.prepare("SELECT username, uuid FROM users WHERE (username = ? COLLATE NOCASE OR uuid = ?) AND uuid = ? LIMIT 1").bind(uname, uname, uid).first();
		return user || null;
	} catch (e) { return null; }
}
async function trimMessageThread(env, username) {
	try {
		await env.DB.prepare("DELETE FROM user_messages WHERE username = ? AND id NOT IN (SELECT id FROM user_messages WHERE username = ? ORDER BY id DESC LIMIT ?)").bind(username, username, MSG_THREAD_KEEP).run();
	} catch (e) { }
}
async function ensureDonationsTable(env) {
	try {
		await env.DB.prepare("CREATE TABLE IF NOT EXISTS donations (id INTEGER PRIMARY KEY AUTOINCREMENT, from_username TEXT NOT NULL, to_username TEXT NOT NULL, gb REAL NOT NULL, created_at INTEGER NOT NULL, seen INTEGER DEFAULT 0)").run();
	} catch (e) { }
}
async function handleDonateConfig(request, url, env) {
	await ensureDonationsTable(env);
	const body = await readJsonBody(request);
	const donor = await findMessageUser(env, body.username, body.uuid);
	if (!donor) return msgJson({ error: "Unauthorized" }, 401);
	const gb = parseFloat(body.gb);
	if (!gb || isNaN(gb) || gb <= 0) {
		return msgJson({ error: "حجم انتخابی نامعتبر است" }, 400);
	}
	let donorFull;
	try {
		donorFull = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(donor.username).first();
	} catch (e) {
		return msgJson({ error: "خطا در دریافت اطلاعات کاربر" }, 500);
	}
	if (!donorFull) return msgJson({ error: "Unauthorized" }, 401);
	if (!donorFull.limit_gb || donorFull.limit_gb <= 0) {
		return msgJson({ error: "این بخش برای کاربران با حجم نامحدود غیرفعال است" }, 400);
	}
	const usedGb = getEffectiveTrafficGb((donorFull.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(donorFull.username) || 0) / (1024 * 1024 * 1024)), donorFull.traffic_multiplier);
	const remainingGb = donorFull.limit_gb - usedGb;
	if (gb > remainingGb) {
		return msgJson({ error: "حجم انتخابی بیشتر از حجم باقیمانده شما است" }, 400);
	}
	let newUsername = "";
	let attempts = 0;
	while (attempts < 8) {
		const suffix = Array.from(crypto.getRandomValues(new Uint8Array(3))).map((b) => b.toString(16).padStart(2, "0")).join("");
		const candidate = (donorFull.username + "-gift-" + suffix).slice(0, 32);
		const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(candidate).first();
		if (!existing) { newUsername = candidate; break; }
		attempts++;
	}
	if (!newUsername) return msgJson({ error: "خطا در ساخت نام کاربری، دوباره تلاش کنید" }, 500);
	const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(6))).map((b) => b.toString(16).padStart(2, "0")).join("");
	const newUuid = `50414e45-4c5f-5a45-5553-${randomHex}`;
	const trojanHash = sha224Pure(newUuid);
	const nowTime = Date.now();
	const todayUtc = Math.floor(nowTime / 86400000) * 86400000;
	try {
		await env.DB.prepare(
			"INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, last_reset_vol_time, last_reset_req_time, ip_operator, ip_count, last_rotate_time, enable_direct, trojan_hash, is_gift, gifted_from) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)"
		)
			.bind(
				newUsername, newUuid, gb, donorFull.expiry_days || null, donorFull.ips || null, donorFull.connection_type || "vless", donorFull.tls, donorFull.port, donorFull.fingerprint || "chrome",
				donorFull.ip_limit || null, donorFull.ip_limit || null, new Date().toISOString(),
				donorFull.block_porn ? 1 : 0, donorFull.block_ads ? 1 : 0, donorFull.frag_len || "200-3000", donorFull.frag_int || "1-2", donorFull.advanced_frag || null,
				donorFull.cipher_suites || null, donorFull.tls_mask || null, donorFull.user_proxy_iata || null, donorFull.user_socks5 || null, donorFull.user_proxy_ip || null,
				todayUtc, todayUtc, donorFull.ip_operator || "all", donorFull.ip_count || 20, nowTime, donorFull.enable_direct !== 0 ? 1 : 0, trojanHash, donorFull.username
			)
			.run();
	} catch (e) {
		return msgJson({ error: "خطا در ساخت کانفیگ جدید: " + e.message }, 500);
	}
	try {
		await env.DB.prepare("UPDATE users SET limit_gb = limit_gb - ? WHERE username = ?").bind(gb, donorFull.username).run();
	} catch (e) { }
	try {
		await env.DB.prepare("INSERT INTO donations (from_username, to_username, gb, created_at, seen) VALUES (?, ?, ?, ?, 0)").bind(donorFull.username, newUsername, gb, nowTime).run();
	} catch (e) { }
	return msgJson({
		success: true,
		username: newUsername,
		uuid: newUuid,
		status_url: url.origin + "/status/" + encodeURIComponent(newUsername),
		sub_url: url.origin + "/sub/" + encodeURIComponent(newUsername),
	});
}
const Router = {
	isWebSocketUpgrade(request) {
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket";
	},
isSubscriptionPath(pathname) {
	return pathname.startsWith("/sub/") || 
	       pathname.startsWith("/feed/") || 
	       pathname.startsWith("/clash/") || 
	       pathname.startsWith("/yaml/");
},
	async handleWebSocket(request, env, ctx) {
		try {
			return handlevIees(env, null, ctx, request);
		} catch (e) {
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async handleSubscription(url, env) {
	const pathname = url.pathname;
	const isClash = pathname.startsWith("/clash/") || pathname.startsWith("/yaml/");
	const isSubPath = pathname.startsWith("/sub/");
	
	let offset = 5; // /sub/
	if (pathname.startsWith("/feed/")) offset = 6;
	else if (pathname.startsWith("/clash/")) offset = 7;
	else if (pathname.startsWith("/yaml/")) offset = 6;
	
	let subUser = safeDecodeURI(pathname.slice(offset));
	const host = url.hostname;
	try {
		const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(subUser, subUser).first();
		if (!user) {
			return new Response("Not Found", { status: 404 });
		}
		try {
			USER_REQ_CACHE.set(user.username, (USER_REQ_CACHE.get(user.username) || 0) + 1);
		} catch (e) { }
		
		if (isClash) {
			return await SubscriptionService.generateClash(user, host);
		}
		return await SubscriptionService.generateText(user, host);
	} catch (err) {
		return new Response("Error building config: " + err.message, { status: 500 });
	}
},
	async handlePanel(request, env) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		let gfxSetting = 'false';
			try {
				const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
				if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
			} catch (e) {}
		
		if (!hasPassword) {
			return new Response(HTML_TEMPLATES.setup.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(HTML_TEMPLATES.login.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const headers = {
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
			Pragma: "no-cache",
			Expires: "0",
		};
		try {
			const storedHash = await DbService.getPanelPassword(env.DB);
			const touch = await touchOrMigrateSession(env, request, storedHash);
			if (touch && touch.blocked) {
				return new Response(HTML_TEMPLATES.login.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
					headers: {
						"Content-Type": "text/html; charset=utf-8",
						"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
					},
				});
			}
			if (touch && touch.invalid) {
				return new Response(HTML_TEMPLATES.login.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
					headers: {
						"Content-Type": "text/html; charset=utf-8",
						"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
					},
				});
			}
			if (touch && touch.token) {
				headers["Set-Cookie"] = "panel_session=" + touch.token + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000";
			}
		} catch (e) { }
		try { await recordAccessLog(env, request); } catch (e) { }
		let panelRole = "owner";
		try {
			const r = await getSessionRole(env, request);
			if (r === "manager") panelRole = "manager";
		} catch (e) {}
		let panelHtml = HTML_TEMPLATES.panel.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting);
		panelHtml = panelHtml.replace(/\/\*\{\{PANEL_ROLE\}\}\*\//g, panelRole);
		return new Response(panelHtml, {
			headers: headers,
		});
	},
	async handleUserStatus(request, url, env) {
		const username = safeDecodeURI(url.pathname.slice(8));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const subResponse = await SubscriptionService.generateText(user, url.hostname);
			const subBase64 = await subResponse.text();
			let plainLinks = "";
			try {
				plainLinks = decodeURIComponent(escape(atob(subBase64)));
			} catch (e) {
				plainLinks = atob(subBase64);
			}
			if (user.auto_rotate_ip === 1) {
				const cachedIpsData = await getCachedIps();
				const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
				if (randomIps.length > 0) user.ips = randomIps.join("\n");
			}
			const userIpsMap = GLOBAL_ACTIVE_IPS.get(user.username);
			const liveIpCount = userIpsMap ? userIpsMap.size : 0;
			const userJson = JSON.stringify({
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: getEffectiveTrafficGb((user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)), user.traffic_multiplier),
				limit_req: user.limit_req,
				used_req: (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0),
				is_active: user.is_active,
				online_count: Math.max(liveIpCount, getActiveIpCount(user.active_ips)),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
				connection_type: user.connection_type || "vless",
				user_proxy_iata: user.user_proxy_iata,
				user_socks5: user.user_socks5,
				user_proxy_ip: user.user_proxy_ip,
				start_on_first_connect: user.start_on_first_connect,
				first_connection_time: user.first_connection_time,
				enable_direct: user.enable_direct !== 0 ? 1 : 0,
				daily_limit_gb: user.daily_limit_gb,
				daily_used_gb: getEffectiveTrafficGb((user.daily_used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)), user.traffic_multiplier),
				daily_reset_hour: DAILY_RESET_HOUR,
				daily_reset_minute: DAILY_RESET_MINUTE,
				daily_lock_until: user.daily_lock_until || 0,
				daily_lock_step: user.daily_lock_step || 0,
				announce_enabled: user.announce_enabled === 1 ? 1 : 0,
				announce_text: user.announce_enabled === 1 ? (user.announce_text || "") : "",
			});
			const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson};`);
			const finalHtml = html + "\n<!-- HIDDEN_CONFIGS -->\n<div style='display:none; white-space:pre-wrap;'>\n" + plainLinks + "\n</div>";
			let gfxSetting = 'false';
			try {
				const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
				if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
			} catch (e) {}
			const replacedHtml = finalHtml.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting);
			try {
				const ua = (request.headers.get("User-Agent") || "").toLowerCase();
				if (!ua.includes("mozilla") && !ua.includes("chrome") && !ua.includes("safari")) {
					USER_REQ_CACHE.set(user.username, (USER_REQ_CACHE.get(user.username) || 0) + 1);
				}
			} catch (e) { }
			return new Response(replacedHtml, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			return new Response("Error: " + err.message, { status: 500 });
		}
	},
	async handleApi(request, url, env, ctx) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (url.pathname === "/api/setup-password" && request.method === "POST") {
			if (hasPassword) {
				return new Response(JSON.stringify({ error: "رمز عبور از قبل تعریف شده است" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await readJsonBody(request);
			const cleanPassword = (password || "").trim();
			if (!cleanPassword || cleanPassword.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(cleanPassword);
			await DbService.setPanelPassword(env.DB, hashed);
			LOGIN_ATTEMPTS.clear();
			let setupCookie = hashed;
			try {
				const ss = await createPanelSession(env, request);
				if (ss && ss.token) setupCookie = ss.token;
			} catch (e) {}
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + setupCookie + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
			const clientUA = request.headers.get("User-Agent") || "";
			const clientOsLabel = parseOsLabel(clientUA);
			if (await isPanelBlocked(env, clientIP, clientOsLabel)) {
				return new Response(JSON.stringify({ error: "دسترسی شما مسدود شده است" }), {
					status: 403,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const now = Date.now();
			if (LOGIN_ATTEMPTS.size > 256) {
				for (const [ip, rec] of LOGIN_ATTEMPTS) {
					if (now - rec.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
				}
			}
			const attemptRecord = LOGIN_ATTEMPTS.get(clientIP) || { count: 0, lastAttempt: 0 };
			if (attemptRecord.count >= 15 && now - attemptRecord.lastAttempt < 900000) {
				const remaining = Math.ceil((900000 - (now - attemptRecord.lastAttempt)) / 60000);
				return new Response(JSON.stringify({ error: `دسترسی شما مسدود شد. لطفاً ${remaining} دقیقه دیگر تلاش کنید.` }), {
					status: 429,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await readJsonBody(request);
			const cleanPassword = (password || "").trim();
			const hashedInput = await DbService.sha256(cleanPassword);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			const managerHash = await getManagerPasswordHash(env);
			let isValid = false;
			let loginRole = "owner";
			if (storedHash === hashedInput) {
				isValid = true;
				loginRole = "owner";
			} else if (managerHash && managerHash === hashedInput) {
				isValid = true;
				loginRole = "manager";
			} else {
				const oldHashedInput = await DbService.oldSha256(cleanPassword);
				if (storedHash === oldHashedInput) {
					isValid = true;
					loginRole = "owner";
					await DbService.setPanelPassword(env.DB, hashedInput);
				}
			}
			if (isValid) {
				LOGIN_ATTEMPTS.delete(clientIP);
				let cookieVal = hashedInput;
				try {
					const sess = await createPanelSession(env, request, loginRole);
					if (sess && sess.error) {
						return new Response(JSON.stringify({ error: sess.error }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					if (sess && sess.token) cookieVal = sess.token;
				} catch (e) {}
				try { await recordAccessLog(env, request); } catch (e) { }
				return new Response(JSON.stringify({ success: true }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + cookieVal + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			} else {
				attemptRecord.count = now - attemptRecord.lastAttempt > 900000 ? 1 : attemptRecord.count + 1;
				attemptRecord.lastAttempt = now;
				LOGIN_ATTEMPTS.set(clientIP, attemptRecord);
				try { if (ctx) ctx.waitUntil(recordFailedLogin(env, clientIP, clientUA, clientOsLabel)); else await recordFailedLogin(env, clientIP, clientUA, clientOsLabel); } catch (e) { }
				return new Response(JSON.stringify({ error: `رمز عبور اشتباه است (تلاش‌های باقی‌مانده: ${15 - attemptRecord.count})` }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/logout" && request.method === "POST") {
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
				},
			});
		}
		if (url.pathname === "/api/recover" && request.method === "POST") {
			const { api_token } = await readJsonBody(request);
			if (!api_token) {
				return new Response(JSON.stringify({ error: "Token is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			try {
				const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
					headers: { Authorization: "Bearer " + api_token },
				});
				const cfData = await cfRes.json();
				if (!cfRes.ok || !cfData.success) {
					return new Response(JSON.stringify({ error: "Invalid or expired Cloudflare token" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const host = url.hostname;
				let isAuthorized = false;
				if (host.endsWith(".workers.dev")) {
					const parts = host.split(".");
					const targetSubdomain = parts[parts.length - 3];
					const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const accountsData = await accountsRes.json();
					if (accountsData.success && accountsData.result) {
						for (const acc of accountsData.result) {
							const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, {
								headers: { Authorization: "Bearer " + api_token },
							});
							const subData = await subRes.json();
							if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) {
								isAuthorized = true;
								break;
							}
						}
					}
				} else {
					const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const zonesData = await zonesRes.json();
					if (zonesData.success && zonesData.result) {
						for (const zone of zonesData.result) {
							if (host === zone.name || host.endsWith("." + zone.name)) {
								isAuthorized = true;
								break;
							}
						}
					}
				}
				if (!isAuthorized) {
					return new Response(JSON.stringify({ error: "این توکن متعلق به صاحب پـنـل نیست (ای کــثـــکـــش)" }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
				cachedPanelPassword = null;
				LOGIN_ATTEMPTS.clear();
				return new Response(JSON.stringify({ success: true }), {
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Cloudflare API connection error" }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/sub-messages") {
			await ensureUserMessagesTable(env);
			if (request.method === "GET") {
				const uname = safeDecodeURI(url.searchParams.get("username") || "");
				const uuid = url.searchParams.get("uuid") || "";
				const user = await findMessageUser(env, uname, uuid);
				if (!user) return msgJson({ error: "Unauthorized" }, 401);
				let rows = [];
				try {
					const r = await env.DB.prepare("SELECT id, sender, body, created_at FROM user_messages WHERE username = ? ORDER BY id ASC LIMIT ?").bind(user.username, MSG_THREAD_KEEP).all();
					rows = r.results || [];
				} catch (e) { rows = []; }
				try {
					await env.DB.prepare("UPDATE user_messages SET read_by_user = 1 WHERE username = ? AND sender = 'owner' AND read_by_user = 0").bind(user.username).run();
				} catch (e) { }
				return msgJson({ messages: rows });
			}
			if (request.method === "POST") {
				const body = await readJsonBody(request);
				const user = await findMessageUser(env, body.username, body.uuid);
				if (!user) return msgJson({ error: "Unauthorized" }, 401);
				const text = sanitizeMessageBody(body.text);
				if (!text) return msgJson({ error: "متن پیام خالی است" }, 400);
				const now = Date.now();
				try {
					const last = await env.DB.prepare("SELECT created_at FROM user_messages WHERE username = ? AND sender = 'user' ORDER BY id DESC LIMIT 1").bind(user.username).first();
					if (last && now - (last.created_at || 0) < MSG_MIN_INTERVAL_MS) {
						return msgJson({ error: "چند لحظه صبر کنید و دوباره ارسال کنید" }, 429);
					}
					const pending = await env.DB.prepare("SELECT COUNT(*) AS c FROM user_messages WHERE username = ? AND sender = 'user' AND read_by_owner = 0").bind(user.username).first();
					if (pending && (pending.c || 0) >= MSG_MAX_PENDING) {
						return msgJson({ error: "پیام‌های خوانده‌نشده شما زیاد است؛ لطفاً منتظر پاسخ بمانید" }, 429);
					}
				} catch (e) { }
				try {
					await env.DB.prepare("INSERT INTO user_messages (username, sender, body, created_at, read_by_owner, read_by_user) VALUES (?, 'user', ?, ?, 0, 1)").bind(user.username, text, now).run();
				} catch (e) {
					return msgJson({ error: "خطا در ثبت پیام" }, 500);
				}
				await trimMessageThread(env, user.username);
				return msgJson({ success: true });
			}
			if (request.method === "PUT") {
				const body = await readJsonBody(request);
				const user = await findMessageUser(env, body.username, body.uuid);
				if (!user) return msgJson({ error: "Unauthorized" }, 401);
				const id = parseInt(body.id, 10);
				const text = sanitizeMessageBody(body.text);
				if (!id || isNaN(id)) return msgJson({ error: "شناسه پیام نامعتبر است" }, 400);
				if (!text) return msgJson({ error: "متن پیام خالی است" }, 400);
				try {
					const row = await env.DB.prepare("SELECT id, sender, username FROM user_messages WHERE id = ? LIMIT 1").bind(id).first();
					if (!row) return msgJson({ error: "پیام یافت نشد" }, 404);
					if (row.sender !== "user" || row.username !== user.username) {
						return msgJson({ error: "فقط می‌توانید پیام خودتان را ویرایش کنید" }, 403);
					}
					await env.DB.prepare("UPDATE user_messages SET body = ? WHERE id = ?").bind(text, id).run();
					return msgJson({ success: true });
				} catch (e) {
					return msgJson({ error: "خطا در ویرایش پیام" }, 500);
				}
			}
			if (request.method === "DELETE") {
				const body = await readJsonBody(request);
				const user = await findMessageUser(env, body.username, body.uuid);
				if (!user) return msgJson({ error: "Unauthorized" }, 401);
				const id = parseInt(body.id || url.searchParams.get("id") || "0", 10);
				if (!id || isNaN(id)) return msgJson({ error: "شناسه پیام نامعتبر است" }, 400);
				try {
					const row = await env.DB.prepare("SELECT id, sender, username FROM user_messages WHERE id = ? LIMIT 1").bind(id).first();
					if (!row) return msgJson({ error: "پیام یافت نشد" }, 404);
					if (row.sender !== "user" || row.username !== user.username) {
						return msgJson({ error: "فقط می‌توانید پیام خودتان را حذف کنید" }, 403);
					}
					await env.DB.prepare("DELETE FROM user_messages WHERE id = ?").bind(id).run();
					return msgJson({ success: true });
				} catch (e) {
					return msgJson({ error: "خطا در حذف پیام" }, 500);
				}
			}
			return msgJson({ error: "Method Not Allowed" }, 405);
		}
		if (url.pathname === "/api/donate-config" && request.method === "POST") {
			return await handleDonateConfig(request, url, env);
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized && url.pathname !== "/api/test-proxy") {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (authorized && isOwnerOnlyApi(url.pathname, request.method)) {
			const role = await getSessionRole(env, request);
			if (role === "manager") {
				return new Response(JSON.stringify({ error: "این بخش فقط برای مالک پنل در دسترس است" }), {
					status: 403,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/donation-notifications" && request.method === "GET") {
			await ensureDonationsTable(env);
			try {
				const unseenRow = await env.DB.prepare("SELECT COUNT(*) AS c FROM donations WHERE seen = 0").first();
				const { results } = await env.DB.prepare("SELECT id, from_username, to_username, gb, created_at, seen FROM donations ORDER BY id DESC LIMIT 50").all();
				return msgJson({ donations: results || [], unseen: (unseenRow && unseenRow.c) || 0 });
			} catch (e) {
				return msgJson({ donations: [], unseen: 0 });
			}
		}
		if (url.pathname === "/api/donation-notifications/ack" && request.method === "POST") {
			await ensureDonationsTable(env);
			try {
				await env.DB.prepare("UPDATE donations SET seen = 1 WHERE seen = 0").run();
				return msgJson({ success: true });
			} catch (e) {
				return msgJson({ error: "خطا در بروزرسانی" }, 500);
			}
		}
		if (url.pathname === "/api/donation-notifications/clear" && request.method === "POST") {
			await ensureDonationsTable(env);
			try {
				await env.DB.prepare("DELETE FROM donations").run();
				return msgJson({ success: true });
			} catch (e) {
				return msgJson({ error: "خطا در پاک کردن لیست" }, 500);
			}
		}
		if (url.pathname === "/api/messages/unread" && request.method === "GET") {
			await ensureUserMessagesTable(env);
			try {
				const row = await env.DB.prepare("SELECT COUNT(*) AS c FROM user_messages WHERE sender = 'user' AND read_by_owner = 0").first();
				return msgJson({ unread: (row && row.c) || 0 });
			} catch (e) { return msgJson({ unread: 0 }); }
		}
		if (url.pathname === "/api/messages/threads" && request.method === "GET") {
			await ensureUserMessagesTable(env);
			try {
				const lastRes = await env.DB.prepare("SELECT m.username AS username, m.sender AS sender, m.body AS body, m.created_at AS created_at FROM user_messages m INNER JOIN (SELECT username, MAX(id) AS mid FROM user_messages GROUP BY username) t ON m.id = t.mid ORDER BY m.id DESC LIMIT 100").all();
				const unreadRes = await env.DB.prepare("SELECT username, COUNT(*) AS c FROM user_messages WHERE sender = 'user' AND read_by_owner = 0 GROUP BY username").all();
				const unreadMap = {};
				for (const r of (unreadRes.results || [])) unreadMap[r.username] = r.c || 0;
				const threads = (lastRes.results || []).map(function (r) {
					return {
						username: r.username,
						last_body: r.body,
						last_sender: r.sender,
						last_at: r.created_at,
						unread: unreadMap[r.username] || 0,
					};
				});
				let total = 0;
				for (const k in unreadMap) total += unreadMap[k];
				return msgJson({ threads: threads, unread: total });
			} catch (e) {
				return msgJson({ threads: [], unread: 0 });
			}
		}
		if (url.pathname === "/api/messages/thread" && request.method === "GET") {
			await ensureUserMessagesTable(env);
			const uname = safeDecodeURI(url.searchParams.get("username") || "");
			if (!uname) return msgJson({ error: "نام کاربری لازم است" }, 400);
			let rows = [];
			try {
				const r = await env.DB.prepare("SELECT id, sender, body, created_at FROM user_messages WHERE username = ? ORDER BY id ASC LIMIT ?").bind(uname, MSG_THREAD_KEEP).all();
				rows = r.results || [];
			} catch (e) { rows = []; }
			try {
				await env.DB.prepare("UPDATE user_messages SET read_by_owner = 1 WHERE username = ? AND sender = 'user' AND read_by_owner = 0").bind(uname).run();
			} catch (e) { }
			return msgJson({ username: uname, messages: rows });
		}
		if (url.pathname === "/api/messages/thread" && request.method === "DELETE") {
			await ensureUserMessagesTable(env);
			const uname = safeDecodeURI(url.searchParams.get("username") || "");
			if (!uname) return msgJson({ error: "نام کاربری لازم است" }, 400);
			try {
				await env.DB.prepare("DELETE FROM user_messages WHERE username = ?").bind(uname).run();
				return msgJson({ success: true });
			} catch (e) { return msgJson({ error: "خطا در حذف گفتگو" }, 500); }
		}
		if (url.pathname === "/api/messages/reply" && request.method === "POST") {
			await ensureUserMessagesTable(env);
			const body = await readJsonBody(request);
			const uname = String(body.username || "").trim();
			const text = sanitizeMessageBody(body.text);
			if (!uname) return msgJson({ error: "نام کاربری لازم است" }, 400);
			if (!text) return msgJson({ error: "متن پاسخ خالی است" }, 400);
			let realName = uname;
			try {
				const u = await env.DB.prepare("SELECT username FROM users WHERE username = ? COLLATE NOCASE LIMIT 1").bind(uname).first();
				if (u && u.username) realName = u.username;
			} catch (e) { }
			try {
				await env.DB.prepare("INSERT INTO user_messages (username, sender, body, created_at, read_by_owner, read_by_user) VALUES (?, 'owner', ?, ?, 1, 0)").bind(realName, text, Date.now()).run();
				await env.DB.prepare("UPDATE user_messages SET read_by_owner = 1 WHERE username = ? AND sender = 'user' AND read_by_owner = 0").bind(realName).run();
			} catch (e) {
				return msgJson({ error: "خطا در ارسال پاسخ" }, 500);
			}
			await trimMessageThread(env, realName);
			return msgJson({ success: true });
		}

		if (url.pathname === "/api/messages/message" && request.method === "PUT") {
			await ensureUserMessagesTable(env);
			const body = await readJsonBody(request);
			const id = parseInt(body.id, 10);
			const text = sanitizeMessageBody(body.text);
			if (!id || isNaN(id)) return msgJson({ error: "شناسه پیام نامعتبر است" }, 400);
			if (!text) return msgJson({ error: "متن پیام خالی است" }, 400);
			try {
				const row = await env.DB.prepare("SELECT id FROM user_messages WHERE id = ? LIMIT 1").bind(id).first();
				if (!row) return msgJson({ error: "پیام یافت نشد" }, 404);
				await env.DB.prepare("UPDATE user_messages SET body = ? WHERE id = ?").bind(text, id).run();
				return msgJson({ success: true });
			} catch (e) {
				return msgJson({ error: "خطا در ویرایش پیام" }, 500);
			}
		}
		if (url.pathname === "/api/messages/message" && request.method === "DELETE") {
			await ensureUserMessagesTable(env);
			const id = parseInt(url.searchParams.get("id") || "0", 10);
			if (!id || isNaN(id)) return msgJson({ error: "شناسه پیام نامعتبر است" }, 400);
			try {
				const row = await env.DB.prepare("SELECT id FROM user_messages WHERE id = ? LIMIT 1").bind(id).first();
				if (!row) return msgJson({ error: "پیام یافت نشد" }, 404);
				await env.DB.prepare("DELETE FROM user_messages WHERE id = ?").bind(id).run();
				return msgJson({ success: true });
			} catch (e) {
				return msgJson({ error: "خطا در حذف پیام" }, 500);
			}
		}
		if (url.pathname === "/api/auto-update-setup" && request.method === "POST") {
			const body = await readJsonBody(request);
			if (body.action === "check") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				const hasToken = !!env.CF_API_TOKEN || !!(dbTokenRow && dbTokenRow.value);
				const isAutoUpdateEnabled = false; /* auto-update removed */
				return new Response(JSON.stringify({ has_token: hasToken, auto_update: isAutoUpdateEnabled }), { headers: { "Content-Type": "application/json" } });
			}
			if (body.action === "enable") {
				return new Response(JSON.stringify({ error: "AUTO_UPDATE_REMOVED" }), { status: 410, headers: { "Content-Type": "application/json" } });
			}
			if (body.action === "disable") {
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '0')").run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			try {
				GLOBAL_TRAFFIC_CACHE.clear();
				GLOBAL_USER_MULTIPLIER.clear();
				ACTIVE_CONNECTIONS_COUNT.clear();
				GLOBAL_ACTIVE_IPS.clear();
				GLOBAL_LAST_ACTIVE_WRITE.clear();
				GLOBAL_LAST_DB_WRITE.clear();
				GLOBAL_WRITE_LOCK.clear();
				DNS_CACHE.clear();
				USER_REQ_CACHE.clear();
				LOGIN_ATTEMPTS.clear();
				GLOBAL_REQ_COUNT = 0;
				GLOBAL_LAST_REQ_WRITE = 0;
				GLOBAL_IPS_CACHE = {};
				GLOBAL_IPS_LAST_FETCH = 0;
				cachedVipCountries = [];
				lastVipCountriesFetch = 0;
				CF_USAGE_CACHE = null;
				CF_USAGE_LAST_FETCH = 0;
				CF_USAGE_CACHE_DATE = "";
				localLastAutoResetCheck = 0;
				cachedPanelPassword = null;
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/factory-reset" && request.method === "POST") {
    const body = await readJsonBody(request);
    if (body.confirm !== "RESET-ALL") {
        return new Response(JSON.stringify({ error: "عبارت تأیید اشتباه است" }), {
            status: 400,
            headers: { "Content-Type": "application/json; charset=utf-8" },
        });
    }
    try {
        // 1. پاک کردن تمام کاربران
        await env.DB.prepare("DELETE FROM users").run();
        
        // 2. پاک کردن تمام تنظیمات (شامل رمز پنل، توکن، gfx و ...)
        await env.DB.prepare("DELETE FROM settings").run();
        
        // 3. پاک کردن جداول اضافی (اگر وجود دارند)
        try { await env.DB.prepare("DELETE FROM logs").run(); } catch (e) {}
        
        // 4. پاک کردن کش‌های سراسری
        GLOBAL_TRAFFIC_CACHE.clear();
        ACTIVE_CONNECTIONS_COUNT.clear();
        GLOBAL_ACTIVE_IPS.clear();
        GLOBAL_LAST_ACTIVE_WRITE.clear();
        GLOBAL_LAST_DB_WRITE.clear();
        GLOBAL_WRITE_LOCK.clear();
        DNS_CACHE.clear();
        USER_REQ_CACHE.clear();
        LOGIN_ATTEMPTS.clear();
        GLOBAL_REQ_COUNT = 0;
        GLOBAL_LAST_REQ_WRITE = 0;
        GLOBAL_IPS_CACHE = {};
        GLOBAL_IPS_LAST_FETCH = 0;
        cachedVipCountries = [];
        lastVipCountriesFetch = 0;
        CF_USAGE_CACHE = null;
        CF_USAGE_LAST_FETCH = 0;
        CF_USAGE_CACHE_DATE = "";
        localLastAutoResetCheck = 0;
        cachedPanelPassword = null;
        
        // 5. پاک کردن کوکی نشست کاربر
        return new Response(JSON.stringify({ success: true }), {
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
            },
        });
    } catch (err) {
        return new Response(JSON.stringify({ error: "خطا در بازنشانی: " + err.message }), {
            status: 500,
            headers: { "Content-Type": "application/json; charset=utf-8" },
        });
    }
}
		if (url.pathname === "/api/check-update" && request.method === "GET") {
			try {
				const githubRes = await fetchUpdateSource("Caspian.js?t=" + Date.now(), {
					headers: {
						"User-Agent": "Mozilla/5.0",
						"Cache-Control": "no-cache",
					},
				});
				if (!githubRes.ok) {
					return new Response(JSON.stringify({
						error: "خطا در دریافت سورس از گیت‌هاب (وضعیت: " + githubRes.status + ")",
						local_version: PANEL_VERSION
					}), { status: 502, headers: { "Content-Type": "application/json; charset=utf-8" } });
				}
				const srcText = await githubRes.text();
				const match = srcText.match(/CURRENT_VERSION\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]/i)
					|| srcText.match(/PANEL_VERSION\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]/i);
				const latestVersion = match ? match[1] : null;
				const localVersion = PANEL_VERSION;
				let updateAvailable = false;
				if (latestVersion && latestVersion !== localVersion) {
					const l = latestVersion.split(".").map(Number);
					const c = localVersion.split(".").map(Number);
					for (let i = 0; i < Math.max(l.length, c.length); i++) {
						if ((l[i] || 0) > (c[i] || 0)) { updateAvailable = true; break; }
						if ((l[i] || 0) < (c[i] || 0)) break;
					}
				}
				return new Response(JSON.stringify({
					success: true,
					local_version: localVersion,
					latest_version: latestVersion,
					update_available: updateAvailable
				}), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (err) {
				return new Response(JSON.stringify({
					error: "خطا در بررسی آپدیت: " + (err.message || "unknown"),
					local_version: PANEL_VERSION
				}), { status: 500, headers: { "Content-Type": "application/json; charset=utf-8" } });
			}
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
			let currentToken = env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null) || body.cf_token || null;
			let currentAccountId = env.CF_ACCOUNT_ID;
			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
			try {
				if (body.cf_token) {
					try {
						await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_token', ?)").bind(String(body.cf_token)).run();
					} catch (e) {}
				}
				const cfHeaders = {
					Authorization: "Bearer " + currentToken,
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CaspianPanel/1.0",
				};
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: cfHeaders });
					if (!accRes.ok) throw new Error("کلودفلر درخواست اکانت را رد کرد (وضعیت: " + accRes.status + "). توکن را بررسی کنید.");
					const accData = await accRes.json().catch(() => ({}));
					if (!accData.success || !accData.result || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}
				const githubRes = await fetchUpdateSource("Caspian.js?t=" + Date.now(), {
					headers: {
						"User-Agent": "Mozilla/5.0",
						"Cache-Control": "no-cache",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب (وضعیت: " + githubRes.status + ")");
				const newCode = await githubRes.text();
				if (!newCode || newCode.length < 1000) throw new Error("سورس دریافت‌شده از گیت‌هاب خالی یا ناقص است.");

				let scriptName = env.WORKER_NAME || "";
				if (!scriptName) {
					const host = url.hostname || "";
					if (host.endsWith(".workers.dev")) {
						scriptName = host.split(".")[0];
					} else {
						scriptName = host.split(".")[0];
					}
				}

				// try resolve real script name from account scripts list if direct bindings fail
				let bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, {
					headers: cfHeaders,
				});
				if (!bindingsRes.ok) {
					const listRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts`, { headers: cfHeaders });
					const listData = await listRes.json().catch(() => ({}));
					if (listData.success && Array.isArray(listData.result)) {
						const hostHint = (url.hostname || "").split(".")[0].toLowerCase();
						const found = listData.result.find((s) => s.id === scriptName)
							|| listData.result.find((s) => String(s.id || "").toLowerCase() === hostHint)
							|| listData.result.find((s) => String(s.id || "").toLowerCase().includes(hostHint));
						if (found && found.id) {
							scriptName = found.id;
							bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${encodeURIComponent(scriptName)}/bindings`, {
								headers: cfHeaders,
							});
						}
					}
				}
				if (!bindingsRes.ok) {
					const errT = await bindingsRes.text().catch(() => "");
					throw new Error("عدم دسترسی به ورکر «" + scriptName + "» (وضعیت: " + bindingsRes.status + "). نام ورکر یا دسترسی توکن را بررسی کنید. " + errT.substring(0, 80));
				}
				const bindingsData = await bindingsRes.json().catch(() => ({}));
				if (!bindingsData.success) throw new Error("توکن فاقد دسترسی Workers Scripts:Edit است.");

				const newBindings = [];
				for (const b of bindingsData.result || []) {
					if (b.name === "CF_API_TOKEN" || b.name === "CF_ACCOUNT_ID") continue;
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.type === "kv_namespace") {
						newBindings.push({ type: "kv_namespace", name: b.name, namespace_id: b.namespace_id || b.id });
					} else if (b.type === "plain_text") {
						newBindings.push({ type: "plain_text", name: b.name, text: b.text || "" });
					} else if (b.type === "secret_text") {
						// keep name-only secret refs so CF does not wipe existing secrets
						newBindings.push({ type: "secret_text", name: b.name });
					} else if (b.type !== "secret_text") {
						newBindings.push(b);
					}
				}
				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });

				let mainModule = "caspian.js";
				let compatDate = "2024-09-23";
				let compatFlags = ["nodejs_compat"];
				try {
					const settingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`, {
						headers: cfHeaders,
					});
					if (settingsRes.ok) {
						const settingsData = await settingsRes.json().catch(() => ({}));
						const st = settingsData.result || {};
						if (st.compatibility_date) compatDate = st.compatibility_date;
						if (Array.isArray(st.compatibility_flags) && st.compatibility_flags.length) compatFlags = st.compatibility_flags;
					}
				} catch (e) {}

				const metadata = {
					main_module: mainModule,
					compatibility_date: compatDate,
					compatibility_flags: compatFlags,
					bindings: newBindings,
				};
				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
				formData.append(mainModule, new Blob([newCode], { type: "application/javascript+module" }), mainModule);
				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${encodeURIComponent(scriptName)}`, {
					method: "PUT",
					headers: cfHeaders,
					body: formData,
				});
				const deployText = await deployRes.text().catch(() => "");
				let deployData = {};
				try { deployData = JSON.parse(deployText); } catch (e) {}
				if (!deployRes.ok || !deployData.success) {
					const cfError = (deployData.errors && deployData.errors[0] && deployData.errors[0].message)
						|| deployText.substring(0, 200)
						|| ("خطای کلودفلر هنگام دیپلوی (" + deployRes.status + ")");
					throw new Error(cfError);
				}
				return new Response(JSON.stringify({ success: true, script: scriptName }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message || String(err) }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password } = await readJsonBody(request);
			const cleanCurrent = (current_password || "").trim();
			const cleanNew = (new_password || "").trim();
			if (!cleanCurrent || !cleanNew) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی و جدید الزامی هستند" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const currentHash = await DbService.sha256(cleanCurrent);
			const oldCurrentHash = await DbService.oldSha256(cleanCurrent);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			if (storedHash && storedHash !== currentHash && storedHash !== oldCurrentHash) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (cleanNew.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(cleanNew);
			await DbService.setPanelPassword(env.DB, newHash);
			try { await ensureSessionTables(env); await env.DB.prepare("DELETE FROM panel_sessions").run(); } catch (e) {}
			let cpCookie = newHash;
			try {
				const ss = await createPanelSession(env, request);
				if (ss && ss.token) cpCookie = ss.token;
			} catch (e) {}
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + cpCookie + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach((r) => {
							if (r.key !== "cf_token" && r.key !== "panel_password") settingsObj[r.key] = r.value;
						});
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
			}
			if (request.method === "POST") {
				const body = await readJsonBody(request);
				if (body.settings && typeof body.settings === "object") {
					for (const [k, v] of Object.entries(body.settings)) {
						await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
					}
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/proxy-ip") {
			if (request.method === "POST") {
				const { proxy_ip, iata, socks5 } = await readJsonBody(request);
				if (proxy_ip) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
				if (iata !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
				if (socks5 !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5', ?)").bind(socks5).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
			if (request.method === "GET") {
				const rowIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				const rowIata = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
				const rowSocks = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				return new Response(
					JSON.stringify({
						proxy_ip: rowIp ? rowIp.value : "",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : "",
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const { proxy, skip_country, username, replace_on_fail } = await readJsonBody(request);
			if (!proxy) return new Response(JSON.stringify({ error: "پـروکـسـی وارد نشده است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			
			if (proxy === "direct") {
				const startT = Date.now();
				try {
					const controller = new AbortController();
					const tid = setTimeout(() => controller.abort(), 3000);
					await fetch("https://cp.cloudflare.com/generate_204", { method: "HEAD", signal: controller.signal });
					clearTimeout(tid);
					return new Response(JSON.stringify({ success: true, ping: (Date.now() - startT), country: "UN" }), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: "نت آزاد قطع است" }), { status: 200, headers: { "Content-Type": "application/json" } });
				}
			}
			try {
				let ip = "";
				let workingProxy = proxy;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = proxy.match(/server=([^&]+)/)?.[1] || "";
				} else {
					let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
				}
				let country = "UN";
				const startTime = Date.now();
				let targetHost = skip_country ? "1.1.1.1" : "ip-api.com";
				let reqPath = skip_country ? "/" : "/json/?fields=countryCode";
				const payload = new TextEncoder().encode("GET " + reqPath + " HTTP/1.1\r\nHost: " + targetHost + "\r\nConnection: close\r\n\r\n");
				
				const s = await connectProxy(proxy, targetHost, 80, payload);
				
				const reader = s.readable.getReader();
				let resStr = "";
				const dec = new TextDecoder();
				const timeoutId = setTimeout(() => {
					try {
						s.close();
					} catch (e) { }
				}, 7000);
				try {
					while (true) {
						const res = await reader.read();
						if (res.done || !res.value) break;
						resStr += dec.decode(res.value, { stream: true });
						if (skip_country) {
							if (resStr.includes("HTTP/1.")) break;
						} else {
							if (resStr.includes("countryCode")) break;
						}
					}
				} finally {
					clearTimeout(timeoutId);
					try {
						s.close();
					} catch (e) { }
				}
				if (!resStr) {
					throw new Error("تایم‌اوت در دریافت دیتا");
				}
				const ping = Date.now() - startTime;
				if (!skip_country) {
					try {
						const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
						if (jsonMatch && jsonMatch[1]) country = jsonMatch[1];
					} catch (e) { }
					if (country === "UN" && ip) {
						try {
							const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
							const geoData = await geoRes.json();
							if (geoData && geoData.countryCode) country = geoData.countryCode;
						} catch (e) { }
					}
				}
				return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				if (username && replace_on_fail) {
					const replaceTask = replaceBrokenProxy(username, env, proxy);
					if (ctx) ctx.waitUntil(replaceTask);
					else replaceTask.catch(() => { });
				}
				let msg = e.message;
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "ارتباط با سرور قطع شد (احتمالاً پـروکـسـی مسدود یا خاموش است)";
				else if (msg.includes("timeout") || msg.includes("timed out") || msg.includes("تایم‌اوت")) msg = "تایم‌اوت در اتصال (پـروکـسـی در دسترس نیست)";
				else if (msg.includes("Invalid URL") || msg.includes("Invalid format")) msg = "فرمت وارد شده برای پـروکـسـی اشتباه است";
				else if (msg === "err") msg = "خطای نامشخص (ارتباط برقرار نشد)";
				return new Response(JSON.stringify({ error: msg }), { status: 200, headers: { "Content-Type": "application/json" } });
			}
		}

		if (url.pathname === "/api/panel-sessions" && request.method === "GET") {
			try {
				await ensureSessionTables(env);
				const currentTok = getSessionTokenFromRequest(request);
				const { results } = await env.DB.prepare("SELECT id, token, ip, user_agent, os_label, created_at, last_seen FROM panel_sessions ORDER BY last_seen DESC LIMIT 100").all();
				const sessions = (results || []).map((r) => ({
					id: r.id,
					ip: r.ip,
					user_agent: r.user_agent,
					os_label: r.os_label,
					created_at: r.created_at,
					last_seen: r.last_seen,
					is_me: r.token === currentTok
				}));
				const { results: blocks } = await env.DB.prepare("SELECT id, block_type, block_value, label, created_at FROM panel_blocks ORDER BY created_at DESC LIMIT 50").all();
				return new Response(JSON.stringify({ sessions: sessions, blocks: blocks || [] }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
			} catch (e) {
				return new Response(JSON.stringify({ sessions: [], blocks: [] }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname.startsWith("/api/panel-sessions/") && request.method === "DELETE") {
			try {
				await ensureSessionTables(env);
				const id = parseInt(url.pathname.split("/").pop(), 10);
				if (!id) return new Response(JSON.stringify({ error: "invalid" }), { status: 400, headers: { "Content-Type": "application/json" } });
				await env.DB.prepare("DELETE FROM panel_sessions WHERE id = ?").bind(id).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: String(e.message || e) }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/panel-blocks" && request.method === "POST") {
			try {
				await ensureSessionTables(env);
				const body = await readJsonBody(request);
				const blockType = (body.block_type === "os") ? "os" : "ip";
				const blockValue = String(body.block_value || "").trim();
				if (!blockValue) return new Response(JSON.stringify({ error: "empty" }), { status: 400, headers: { "Content-Type": "application/json" } });
				await env.DB.prepare("INSERT INTO panel_blocks (block_type, block_value, label, created_at) VALUES (?, ?, ?, ?)").bind(blockType, blockValue, String(body.label || blockValue), Date.now()).run();
				if (blockType === "ip") {
					await env.DB.prepare("DELETE FROM panel_sessions WHERE ip = ?").bind(blockValue).run();
				} else {
					await env.DB.prepare("DELETE FROM panel_sessions WHERE os_label = ?").bind(blockValue).run();
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: String(e.message || e) }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname.startsWith("/api/panel-blocks/") && request.method === "DELETE") {
			try {
				await ensureSessionTables(env);
				const id = parseInt(url.pathname.split("/").pop(), 10);
				if (!id) return new Response(JSON.stringify({ error: "invalid" }), { status: 400, headers: { "Content-Type": "application/json" } });
				await env.DB.prepare("DELETE FROM panel_blocks WHERE id = ?").bind(id).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: String(e.message || e) }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}


		if (url.pathname === "/api/manager-password" && request.method === "GET") {
			try {
				const h = await getManagerPasswordHash(env);
				return new Response(JSON.stringify({ has_manager: !!h }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ has_manager: false }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/manager-password" && request.method === "POST") {
			try {
				const body = await readJsonBody(request);
				const action = body.action || "set";
				if (action === "delete") {
					await env.DB.prepare("DELETE FROM settings WHERE key = 'manager_password'").run();
					try { await env.DB.prepare("DELETE FROM panel_sessions WHERE role = 'manager'").run(); } catch (e) {}
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
				const pwd = String(body.password || "").trim();
				if (!pwd || pwd.length < 4) {
					return new Response(JSON.stringify({ error: "رمز مالکیت باید حداقل ۴ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
				}
				const ownerHash = await DbService.getPanelPassword(env.DB, true);
				const hashed = await DbService.sha256(pwd);
				if (ownerHash && hashed === ownerHash) {
					return new Response(JSON.stringify({ error: "رمز مالکیت نباید با رمز مالک یکی باشد" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
				}
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('manager_password', ?)").bind(hashed).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: String(e.message || e) }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/access-logs" && request.method === "GET") {
			try {
				await cleanupAccessLogs(env);
				const { results } = await env.DB.prepare("SELECT id, ip, user_agent, created_at FROM access_logs WHERE created_at >= ? ORDER BY created_at DESC LIMIT 200").bind(Date.now() - 86400000).all();
				return new Response(JSON.stringify({ logs: results || [] }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
			} catch (e) {
				return new Response(JSON.stringify({ logs: [], error: e.message }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/access-logs" && request.method === "DELETE") {
			try {
				await env.DB.prepare("DELETE FROM access_logs").run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/failed-logins" && request.method === "GET") {
			try {
				await ensureSessionTables(env);
				await cleanupFailedLogins(env);
				const { results } = await env.DB.prepare("SELECT id, ip, user_agent, os_label, created_at FROM failed_logins ORDER BY created_at DESC LIMIT 200").all();
				const { results: blocks } = await env.DB.prepare("SELECT id, block_type, block_value, label, created_at FROM panel_blocks ORDER BY created_at DESC LIMIT 50").all();
				return new Response(JSON.stringify({ logins: results || [], blocks: blocks || [] }), { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
			} catch (e) {
				return new Response(JSON.stringify({ logins: [], blocks: [], error: e.message }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/failed-logins" && request.method === "DELETE") {
			try {
				await ensureSessionTables(env);
				await env.DB.prepare("DELETE FROM failed_logins").run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/traffic-chart" && request.method === "GET") {
			try {
				await ensureTrafficDailyTable(env);
				const days = Math.min(parseInt(url.searchParams.get("days") || "30", 10) || 30, 90);
				let results = [];
				try {
					const q = await env.DB.prepare("SELECT day_key, total_gb FROM traffic_daily ORDER BY day_key DESC LIMIT ?").bind(days).all();
					results = q.results || [];
				} catch (e) { results = []; }
				const map = {};
				for (const r of results) map[r.day_key] = Number(r.total_gb) || 0;
				const out = [];
				const now = Date.now();
				for (let i = days - 1; i >= 0; i--) {
					const key = getTehranDayKey(now - i * 86400000);
					out.push({ day_key: key, total_gb: map[key] || 0 });
				}
				// live cache not yet flushed
				let liveExtra = 0;
				for (const v of GLOBAL_TRAFFIC_CACHE.values()) liveExtra += (v || 0);
				const liveGb = liveExtra / (1024 * 1024 * 1024);
				// bootstrap today from users.daily_used_gb if history empty/today zero
				let todayBootstrap = 0;
				try {
					const sumRow = await env.DB.prepare("SELECT COALESCE(SUM(daily_used_gb), 0) AS s FROM users").first();
					todayBootstrap = Number(sumRow && sumRow.s) || 0;
				} catch (e) { todayBootstrap = 0; }
				if (out.length) {
					const last = out[out.length - 1];
					const fromHistory = last.total_gb || 0;
					if (fromHistory > 0) {
						last.total_gb = fromHistory + liveGb;
					} else {
						// no recorded history yet: seed from sum of users.daily_used_gb + live cache
						last.total_gb = Math.max(todayBootstrap, 0) + liveGb;
						if (last.total_gb > 0) {
							try {
								await env.DB.prepare("INSERT INTO traffic_daily (day_key, total_gb, updated_at) VALUES (?, ?, ?)").bind(last.day_key, last.total_gb, now).run();
							} catch (e) {
								try {
									await env.DB.prepare("UPDATE traffic_daily SET total_gb = ?, updated_at = ? WHERE day_key = ?").bind(last.total_gb, now, last.day_key).run();
								} catch (e2) {}
							}
						}
					}
				}
				return new Response(JSON.stringify({ days: out }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message || "خطا", days: [] }), { status: 500, headers: { "Content-Type": "application/json; charset=utf-8" } });
			}
		}
		if (url.pathname.startsWith("/api/users")) {
			const pathParts = url.pathname.split("/");
			const isUserAction = pathParts.length > 3;
			if (isUserAction) {
				const username = safeDecodeURI(pathParts.pop());
				if (request.method === "PUT") {
					const body = await readJsonBody(request);
					if (Object.keys(body).length === 0) {
						return new Response(JSON.stringify({ error: "Invalid request body" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (body.toggle_only !== undefined) {
						await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else if (body.reset_action !== undefined) {
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0, is_active = 1 WHERE username = ?").bind(username).run();
							GLOBAL_TRAFFIC_CACHE.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0, is_active = 1 WHERE username = ?").bind(username).run();
							USER_REQ_CACHE.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP, first_connection_time = NULL, is_active = 1 WHERE username = ?").bind(username).run();
							for (const [lockK] of GLOBAL_WRITE_LOCK.entries()) { if (lockK.endsWith("_first_conn")) GLOBAL_WRITE_LOCK.delete(lockK); }
						} else if (body.reset_action === "daily") {
							const cachedBytes = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
							if (cachedBytes > 0) {
								const deltaGb = cachedBytes / (1024 * 1024 * 1024);
								try {
									await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, Date.now(), username).run();
								} catch (e) {}
								GLOBAL_TRAFFIC_CACHE.set(username, 0);
							}
							await env.DB.prepare("UPDATE users SET daily_used_gb = 0, daily_lock_until = 0, daily_lock_step = 0, is_active = 1 WHERE username = ?").bind(username).run();
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols, daily_limit_gb, traffic_multiplier, announce_enabled, announce_text } = body;
						if (new_username && new_username !== username) {
							if (!/^[a-zA-Z0-9_-]+$/.test(new_username)) {
								return new Response(JSON.stringify({ error: "نام کاربری جدید غیرمجاز است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(new_username).first();
							if (existing) {
								return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							if (GLOBAL_TRAFFIC_CACHE.has(username)) {
								GLOBAL_TRAFFIC_CACHE.set(new_username, GLOBAL_TRAFFIC_CACHE.get(username));
								GLOBAL_TRAFFIC_CACHE.delete(username);
							}
							if (USER_REQ_CACHE.has(username)) {
								USER_REQ_CACHE.set(new_username, USER_REQ_CACHE.get(username));
								USER_REQ_CACHE.delete(username);
							}
							if (ACTIVE_CONNECTIONS_COUNT.has(username)) {
								ACTIVE_CONNECTIONS_COUNT.set(new_username, ACTIVE_CONNECTIONS_COUNT.get(username));
								ACTIVE_CONNECTIONS_COUNT.delete(username);
							}
							if (GLOBAL_LAST_ACTIVE_WRITE.has(username)) {
								GLOBAL_LAST_ACTIVE_WRITE.set(new_username, GLOBAL_LAST_ACTIVE_WRITE.get(username));
								GLOBAL_LAST_ACTIVE_WRITE.delete(username);
							}
						}
						let finalConnType = undefined;
						if (protocols && Array.isArray(protocols) && protocols.length > 0) {
							finalConnType = protocols.join(",");
						} else if (connection_type) {
							finalConnType = connection_type;
						}
						const existingUser = await env.DB.prepare("SELECT uuid FROM users WHERE username = ?").bind(username).first();
						const trojanHash = existingUser && existingUser.uuid ? sha224Pure(existingUser.uuid) : null;
						const annEnabledVal = announce_enabled !== undefined ? (announce_enabled ? 1 : 0) : null;
						const annTextVal = announce_text !== undefined ? String(announce_text || "").trim().slice(0, 200) : null;
						await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, advanced_frag = ?, cipher_suites = ?, tls_mask = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ?, auto_reset_vol_days = ?, auto_reset_req_days = ?, auto_rotate_ip = ?, rotate_time = ?, ip_operator = ?, ip_count = ?, auto_rotate_user_proxy = ?, start_on_first_connect = ?, enable_direct = ?, daily_limit_gb = ?, traffic_multiplier = ?, daily_lock_until = 0, daily_lock_step = 0, announce_enabled = COALESCE(?, announce_enabled), announce_text = COALESCE(?, announce_text), connection_type = CASE WHEN ? IS NOT NULL THEN ? ELSE connection_type END, trojan_hash = COALESCE(trojan_hash, ?) WHERE username = ?")
							.bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20, auto_rotate_user_proxy ? 1 : 0, start_on_first_connect ? 1 : 0, enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1, daily_limit_gb ? parseFloat(daily_limit_gb) : null, parseTrafficMultiplier(traffic_multiplier), annEnabledVal, annTextVal, finalConnType !== undefined ? finalConnType : null, finalConnType !== undefined ? finalConnType : null, trojanHash, username)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					try {
						const userToDelete = await env.DB.prepare("SELECT lifetime_used_gb, used_gb FROM users WHERE username = ?").bind(username).first();
						if (userToDelete) {
							const gbToKeep = userToDelete.lifetime_used_gb || userToDelete.used_gb || 0;
							if (gbToKeep > 0) {
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('deleted_users_gb', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS REAL) + ?").bind(String(gbToKeep), String(gbToKeep)).run();
							}
						}
					} catch(e) {}
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) { }
					try {
						const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
						const now = Date.now();
						const cachedIpsData = await getCachedIps();
						const enrichedUsers = (results || []).map((user) => {
							let finalIps = user.ips;
							if (user.auto_rotate_ip === 1) {
								const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
								if (randomIps.length > 0) finalIps = randomIps.join("\n");
							}
							const userIpsMap = GLOBAL_ACTIVE_IPS.get(user.username);
							const liveIpCount = userIpsMap ? userIpsMap.size : 0;
							const currentOnlineCount = Math.max(liveIpCount, getActiveIpCount(user.active_ips));
							const realUsed = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
							const realDaily = (user.daily_used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
							const mult = parseTrafficMultiplier(user.traffic_multiplier);
							return {
								...user,
								ips: finalIps,
								used_gb: realUsed * mult,
								used_req: (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0),
								daily_used_gb: realDaily * mult,
								traffic_multiplier: mult,
								is_online: currentOnlineCount > 0 ? 1 : 0,
								online_count: currentOnlineCount,
							};
						});
						let cfReqs = { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
						try {
							const liveCf = await getCfUsage(env);
							const todayStr = new Date().toISOString().split("T")[0];
							const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
							const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
							let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
							let dbToday = 0;
							if (dateRow && dateRow.value === todayStr) {
								const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first();
								dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0;
							}
							if (liveCf.today > dbToday) {
								dbToday = liveCf.today;
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run();
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run();
							}
							if (liveCf.total > dbTotal) {
								dbTotal = liveCf.total;
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run();
							}
							cfReqs.today = dbToday + GLOBAL_REQ_COUNT;
							cfReqs.total = dbTotal + GLOBAL_REQ_COUNT;
							cfReqs.d1Reads = liveCf.d1Reads;
							cfReqs.d1Writes = liveCf.d1Writes;
						} catch (e) { }
						let deletedGb = 0;
						try {
							const delRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'deleted_users_gb'").first();
							if (delRow) deletedGb = parseFloat(delRow.value) || 0;
						} catch (e) {}
						return new Response(
							JSON.stringify({
								users: enrichedUsers,
								serverTime: now,
								cfRequestsToday: cfReqs.today,
								cfRequestsTotal: cfReqs.total,
								d1Reads: cfReqs.d1Reads,
								d1Writes: cfReqs.d1Writes,
								deletedGb: deletedGb,
							}),
							{
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					} catch (dbErr) {
						return new Response(
							JSON.stringify({
								users: [],
								serverTime: Date.now(),
								cfRequestsToday: 0,
								cfRequestsTotal: 0,
								error: dbErr.message,
							}),
							{
								status: 200,
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					}
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols, daily_limit_gb, traffic_multiplier, announce_enabled, announce_text } = await readJsonBody(request);
					if (!username) {
						return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 32) {
						return new Response(JSON.stringify({ error: "نام کاربری نمی‌تواند بیشتر از ۳۲ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
						return new Response(JSON.stringify({ error: "نام کاربری غیرمجاز است (فقط حروف، اعداد، خط تیره و آندرلاین)" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					let finalUuid = uuid;
					if (!finalUuid) {
						const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(6)))
							.map((b) => b.toString(16).padStart(2, "0"))
							.join("");
						finalUuid = `50414e45-4c5f-5a45-5553-${randomHex}`;
					}
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					const existingUser = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
					if (existingUser) {
						return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					try {
						const todayUtc = Math.floor(Date.now() / 86400000) * 86400000;
						const nowTime = Date.now();
						let finalConnType = "vless";
						if (protocols && Array.isArray(protocols) && protocols.length > 0) {
							finalConnType = protocols.join(",");
						} else if (connection_type) {
							finalConnType = connection_type;
						}
						const trojanHash = sha224Pure(finalUuid);
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, last_reset_vol_time, last_reset_req_time, auto_rotate_ip, rotate_time, ip_operator, ip_count, last_rotate_time, auto_rotate_user_proxy, start_on_first_connect, first_connection_time, trojan_hash, enable_direct, daily_limit_gb, traffic_multiplier, announce_enabled, announce_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, finalConnType, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, todayUtc, todayUtc, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20, nowTime, auto_rotate_user_proxy ? 1 : 0, start_on_first_connect ? 1 : 0, null, trojanHash, enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1, daily_limit_gb ? parseFloat(daily_limit_gb) : null, parseTrafficMultiplier(traffic_multiplier), announce_enabled ? 1 : 0, String(announce_text || "").trim().slice(0, 200) || null)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} catch (err) {
						return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
					}
				}
			}
		}
		return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
	},
};
let schemaEnsured = false;
let schemaPromise = null;
let cachedPanelPassword = null;
const DbService = {
	async ensureSchema(db) {
if (schemaEnsured) return;
		if (schemaPromise) {
			await schemaPromise;
			return;
		}
		schemaPromise = (async () => {
			try {
				await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, uuid TEXT, limit_gb REAL, expiry_days INTEGER, ips TEXT, connection_type TEXT, tls TEXT, port INTEGER, used_gb REAL DEFAULT 0, is_active INTEGER DEFAULT 1, last_active INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`).run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user_agent TEXT, created_at INTEGER NOT NULL)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS panel_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, ip TEXT, user_agent TEXT, os_label TEXT, role TEXT DEFAULT 'owner', created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS panel_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, block_type TEXT NOT NULL, block_value TEXT NOT NULL, label TEXT, created_at INTEGER NOT NULL)").run();
			await db.prepare("CREATE TABLE IF NOT EXISTS failed_logins (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user_agent TEXT, os_label TEXT, created_at INTEGER NOT NULL)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS traffic_daily (day_key TEXT PRIMARY KEY, total_gb REAL DEFAULT 0, updated_at INTEGER DEFAULT 0)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS user_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, sender TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, read_by_owner INTEGER DEFAULT 0, read_by_user INTEGER DEFAULT 0)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE INDEX IF NOT EXISTS idx_user_messages_username ON user_messages (username, id)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS donations (id INTEGER PRIMARY KEY AUTOINCREMENT, from_username TEXT NOT NULL, to_username TEXT NOT NULL, gb REAL NOT NULL, created_at INTEGER NOT NULL, seen INTEGER DEFAULT 0)").run();
			} catch (e) { }
			try {
				await db.prepare("CREATE INDEX IF NOT EXISTS idx_donations_seen ON donations (seen, id)").run();
			} catch (e) { }
			try {
				const { results } = await db.prepare("PRAGMA table_info(users)").all();
				const existingCols = new Set((results || []).map((r) => r.name));
				const colsToAdd = [
					{ name: "advanced_frag", def: "TEXT DEFAULT NULL" },
					{ name: "cipher_suites", def: "TEXT DEFAULT NULL" },
					{ name: "tls_mask", def: "TEXT DEFAULT NULL" },
					{ name: "is_active", def: "INTEGER DEFAULT 1" },
					{ name: "last_active", def: "INTEGER" },
					{ name: "fingerprint", def: "TEXT DEFAULT 'chrome'" },
					{ name: "max_connections", def: "INTEGER" },
					{ name: "limit_req", def: "INTEGER" },
					{ name: "used_req", def: "INTEGER DEFAULT 0" },
					{ name: "ip_limit", def: "INTEGER DEFAULT NULL" },
					{ name: "active_ips", def: "TEXT DEFAULT NULL" },
					{ name: "block_porn", def: "INTEGER DEFAULT 0" },
					{ name: "block_ads", def: "INTEGER DEFAULT 0" },
					{ name: "frag_len", def: "TEXT DEFAULT '200-3000'" },
					{ name: "frag_int", def: "TEXT DEFAULT '1-2'" },
					{ name: "lifetime_used_gb", def: "REAL DEFAULT 0" },
					{ name: "user_proxy_ip", def: "TEXT DEFAULT NULL" },
					{ name: "user_proxy_iata", def: "TEXT DEFAULT NULL" },
					{ name: "user_socks5", def: "TEXT DEFAULT NULL" },
					{ name: "auto_reset_vol_days", def: "INTEGER DEFAULT 0" },
					{ name: "auto_reset_req_days", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_vol_time", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_req_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_ip", def: "INTEGER DEFAULT 1" },
					{ name: "rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "ip_operator", def: "TEXT DEFAULT 'all'" },
					{ name: "ip_count", def: "INTEGER DEFAULT 15" },
					{ name: "last_rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_user_proxy", def: "INTEGER DEFAULT 0" },
					{ name: "start_on_first_connect", def: "INTEGER DEFAULT 0" },
					{ name: "first_connection_time", def: "INTEGER DEFAULT NULL" },
					{ name: "trojan_hash", def: "TEXT DEFAULT NULL" },
					{ name: "enable_direct", def: "INTEGER DEFAULT 1" },
					{ name: "connected_operators", def: "TEXT DEFAULT '[]'" },
					{ name: "daily_limit_gb", def: "REAL DEFAULT NULL" },
					{ name: "daily_used_gb", def: "REAL DEFAULT 0" },
					{ name: "daily_lock_until", def: "INTEGER DEFAULT 0" },
					{ name: "daily_lock_step", def: "REAL DEFAULT 0" },
					{ name: "announce_enabled", def: "INTEGER DEFAULT 0" },
					{ name: "announce_text", def: "TEXT DEFAULT NULL" },
					{ name: "is_gift", def: "INTEGER DEFAULT 0" },
					{ name: "gifted_from", def: "TEXT DEFAULT NULL" },
					{ name: "traffic_multiplier", def: "REAL DEFAULT 1" },
				];
				const stmts = [];
				for (const col of colsToAdd) {
					if (!existingCols.has(col.name)) {
						stmts.push(db.prepare(`ALTER TABLE users ADD COLUMN ${col.name} ${col.def}`));
					}
				}
				if (stmts.length > 0) {
					await db.batch(stmts);
				}
			} catch (e) { }
			try {
				await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
			} catch (e) { }
			try {
				await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
			} catch (e) { }
		})();
		await schemaPromise;
		schemaEnsured = true;
	},
	async getPanelPassword(db, forceRefresh = true) {
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row && row.value ? row.value : null;
			return cachedPanelPassword;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async verifyApiAuth(request, env) {
		try {
			const storedPasswordHash = await this.getPanelPassword(env.DB);
			if (!storedPasswordHash) return true;
			const sessionToken = getSessionTokenFromRequest(request);
			if (!sessionToken) return false;
			const ip = (request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown").split(",")[0].trim();
			const osLabel = parseOsLabel(request.headers.get("User-Agent") || "");
			if (await isPanelBlocked(env, ip, osLabel)) return false;
			if (sessionToken === storedPasswordHash) return true;
			try {
				await ensureSessionTables(env);
				const row = await env.DB.prepare("SELECT id, ip, os_label FROM panel_sessions WHERE token = ? LIMIT 1").bind(sessionToken).first();
				if (!row) return false;
				if (await isPanelBlocked(env, row.ip, row.os_label)) return false;
				try { await env.DB.prepare("UPDATE panel_sessions SET last_seen = ? WHERE id = ?").bind(Date.now(), row.id).run(); } catch (e) {}
				return true;
			} catch (e) {
				return false;
			}
		} catch (e) {
			return false;
		}
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
	async oldSha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
};
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 180000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
// ---- Announcement header (shown by client apps that support the "announce" header) ----
function buildAnnounceHeaders(user) {
	try {
		if (!user || Number(user.announce_enabled) !== 1) return {};
		const text = String(user.announce_text || "").trim().slice(0, 200);
		if (!text) return {};
		const bytes = TEXT_ENCODER.encode(text);
		let bin = "";
		for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
		return { "announce": "base64:" + btoa(bin) };
	} catch (e) {
		return {};
	}
}
const SubscriptionService = {
	async generateText(user, host) {
		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await getCachedIps();
			const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const dynPath = encodeURIComponent("/stream/PANEL_CASPIAN/" + ((user.uuid || "").split("-")[4] || "default"));
		const links = [];
		let remVol = "Unlimited";
		if (user.limit_gb) {
			let liveUsedGb = getEffectiveTrafficGb((user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)), user.traffic_multiplier);
			let rem = user.limit_gb - liveUsedGb;
			remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
		}
		let remTime = "Unlimited";
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					const expiryDate = new Date(user.first_connection_time + user.expiry_days * 86400000);
					const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
					remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
				} else {
					remTime = user.expiry_days + "Days (Not Started)";
				}
			} else if (user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 86400000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
		}
		let remReq = "Unlimited";
		if (user.limit_req) {
			let liveUsedReq = (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0);
			let rem = user.limit_req - liveUsedReq;
			remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
		}
		const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
links.push("vl" + "e" + "ss://" + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=" + dynPath + "#" + encodeURIComponent(infoRemark));
		const rawPath = "/stream/PANEL_CASPIAN/" + ((user.uuid || "").split("-")[4] || "default");
		let proxyList = [];
		try {
			if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
			} else if (user.user_socks5 || user.user_proxy_ip) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			} else {
				proxyList = [null];
			}
		} catch (e) {
			proxyList = [user.user_socks5 || user.user_proxy_ip];
		}
		if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
		const allowDirect = user.enable_direct !== 0;
		if (allowDirect) {
			let hasDirect = proxyList.some(p => p === null || p === "");
			if (!hasDirect) proxyList.push(null);
		} else {
			proxyList = proxyList.filter(p => p !== null && p !== "");
		}
		if (proxyList.length === 0) proxyList = [null];
		let resolvedProxies = [];
		for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
			let proxyItem = proxyList[locIdx];
			let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
			let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : user.user_proxy_iata || "";
			if (!countryCode && proxyStr) {
				try {
					const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
					const s = await connectProxy(proxyStr, "ip-api.com", 80, payload);
					const reader = s.readable.getReader();
					let resStr = "";
					const dec = new TextDecoder();
					const timeoutId = setTimeout(() => {
						try {
							s.close();
						} catch (e) { }
					}, 2000);
					try {
						while (true) {
							const res = await reader.read();
							if (res.done || !res.value) break;
							resStr += dec.decode(res.value, { stream: true });
							if (resStr.includes("countryCode")) break;
						}
					} finally {
						clearTimeout(timeoutId);
						try {
							s.close();
						} catch (e) { }
					}
					const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
					if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
				} catch (e) { }
				if (!countryCode) {
					let ip = "";
					let cleanProxy = proxyStr.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
					if (ip) {
						try {
							const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
							const geoData = await geoRes.json();
							if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
						} catch (e) { }
					}
				}
			}
			let flagEmoji = "🌐";
			if (countryCode) {
				const codePoints = countryCode
					.toUpperCase()
					.split("")
					.map((char) => 127397 + char.charCodeAt(0));
				try {
					flagEmoji = String.fromCodePoint(...codePoints);
				} catch (e) { }
			}
			const currentDynPath = encodeURIComponent(rawPath + (proxyItem !== null && proxyItem !== "" ? `/loc-${locIdx}` : ""));
			resolvedProxies.push({ flagEmoji, currentDynPath });
		}
		const connType = String(user.connection_type || "vless").toLowerCase();
		const enableVless = connType.includes("vless") || connType === "vl" + "e" + "ss" || (!connType.includes("trojan") && !connType.includes("shadowsocks"));
		const enableTrojan = connType.includes("trojan");
		const enableSS = connType.includes("shadowsocks");
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				resolvedProxies.forEach((proxy) => {
					const isTlsPort = TLS_PORTS.has(portStr);
					const tlsVal = isTlsPort ? "tls" : "none";
					let userFrag = "";
					if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
					if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
					if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
					if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
						
					const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

					if (enableVless) {
						const remark = "CASPIAN | " + proxy.flagEmoji + " | " + user.username;
						links.push("vl" + "e" + "ss://" + user.uuid + "@" + ip + ":" + portStr + "?path=" + proxy.currentDynPath + "&security=" + tlsVal + "&encryption=none&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(remark));
					}
					if (enableTrojan) {
						const trojanRemark = "CASPIAN | " + proxy.flagEmoji + " | " + user.username;
						links.push("trojan://" + user.uuid + "@" + ip + ":" + portStr + "?path=" + proxy.currentDynPath + "&security=" + tlsVal + "&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(trojanRemark));
					}
					if (enableSS) {
						const ssRemark = "CASPIAN | " + proxy.flagEmoji + " | " + user.username;
						const methodPass = btoa("aes-256-gcm:" + user.uuid);
						let pluginOpts = "v2ray-plugin;mode=websocket;host=" + host + ";path=" + decodeURIComponent(proxy.currentDynPath) + (isTlsPort ? ";tls" : "");
						let pluginStr = encodeURIComponent(pluginOpts);
						links.push("ss://" + methodPass + "@" + ip + ":" + portStr + "/?plugin=" + pluginStr + "#" + encodeURIComponent(ssRemark));
					}
				});
			});
		});
		const noise = ["# System Update Feed: OK", "# Sync Code: " + Math.random().toString(36).slice(2, 10), "# Version: 2.10.1", "# Description: Secure Node Configurations", ""].join("\n");
		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));
		const downloadBytes = Math.floor(getEffectiveTrafficGb((user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)), user.traffic_multiplier) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					expireTimestamp = Math.floor((user.first_connection_time + user.expiry_days * 86400000) / 1000);
				} else {
					expireTimestamp = Math.floor((Date.now() + user.expiry_days * 86400000) / 1000);
				}
			} else if (user.created_at) {
				expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
			}
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
				...buildAnnounceHeaders(user),
			},
		});
		},
			async generateClash(user, host) {
		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await getCachedIps();
			const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips) {
			const parsedIps = user.ips.split("\n").map((ip) => ip.trim()).filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}

		const ports = String(user.port || "443").split(",").map((p) => p.trim()).filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const rawPath = "/stream/PANEL_CASPIAN/" + ((user.uuid || "").split("-")[4] || "default");

		let proxyList = [];
		try {
			if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
			} else if (user.user_socks5 || user.user_proxy_ip) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			} else {
				proxyList = [null];
			}
		} catch (e) {
			proxyList = [user.user_socks5 || user.user_proxy_ip];
		}
		if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];

		const allowDirect = user.enable_direct !== 0;
		if (allowDirect) {
			let hasDirect = proxyList.some((p) => p === null || p === "");
			if (!hasDirect) proxyList.push(null);
		} else {
			proxyList = proxyList.filter((p) => p !== null && p !== "");
		}
		if (proxyList.length === 0) proxyList = [null];

		const userConnType = String(user.connection_type || "vless").toLowerCase();
		const enableVless = userConnType.includes("vless") || userConnType === "vl" + "e" + "ss" || (!userConnType.includes("trojan") && !userConnType.includes("shadowsocks"));
		const enableTrojan = userConnType.includes("trojan");
		const enableSS = userConnType.includes("shadowsocks");

		const proxies = [];
		const proxyNames = [];

		for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
			const proxyItem = proxyList[locIdx];
			const countryCode = typeof proxyItem === "object" && proxyItem !== null ? (proxyItem.country || "") : (user.user_proxy_iata || "");
			let flagEmoji = "🌐";
			if (countryCode && countryCode.length === 2) {
				try {
					flagEmoji = String.fromCodePoint(...countryCode.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0)));
				} catch (e) {}
			}

			const currentPath = rawPath + ((proxyItem !== null && proxyItem !== "") ? "/loc-" + locIdx : "");

			for (const ip of ips) {
				for (const portStr of ports) {
					const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
					const portNum = parseInt(portStr) || 443;

					if (enableVless) {
						const name = `CASPIAN | ${flagEmoji} | ${user.username} | ${ip}:${portStr}`;
						const proxy = {
							name: name,
							type: "vless",
							server: ip,
							port: portNum,
							uuid: user.uuid,
							network: "ws",
							tls: isTlsPort,
							udp: true,
							"client-fingerprint": fp,
							"ws-opts": {
								path: currentPath,
								headers: { Host: host }
							}
						};
						if (isTlsPort) {
							proxy.servername = host;
							proxy["skip-cert-verify"] = false;
						}
						if (user.frag_len && user.frag_int) {
							// Clash Meta از reality/fragment مستقیم پشتیبانی محدود دارد
						}
						proxies.push(proxy);
						proxyNames.push(name);
					}

					if (enableTrojan) {
						const name = `CASPIAN | ${flagEmoji} | ${user.username} | Trojan | ${ip}:${portStr}`;
						const proxy = {
							name: name,
							type: "trojan",
							server: ip,
							port: portNum,
							password: user.uuid,
							network: "ws",
							tls: isTlsPort,
							udp: true,
							"client-fingerprint": fp,
							"ws-opts": {
								path: currentPath,
								headers: { Host: host }
							}
						};
						if (isTlsPort) {
							proxy.sni = host;
							proxy["skip-cert-verify"] = false;
						}
						proxies.push(proxy);
						proxyNames.push(name);
					}

					if (enableSS) {
						const name = `CASPIAN | ${flagEmoji} | ${user.username} | SS | ${ip}:${portStr}`;
						const proxy = {
							name: name,
							type: "ss",
							server: ip,
							port: portNum,
							cipher: "aes-256-gcm",
							password: user.uuid,
							plugin: "v2ray-plugin",
							"plugin-opts": {
								mode: "websocket",
								host: host,
								path: currentPath,
								tls: isTlsPort,
								mux: true
							}
						};
						proxies.push(proxy);
						proxyNames.push(name);
					}
				}
			}
		}

		if (proxies.length === 0) {
			return new Response("No proxies available", { status: 400 });
		}

		// ساخت YAML
		let yaml = `mixed-port: 7890
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090
unified-delay: true
tcp-concurrent: true

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
  fallback:
    - 8.8.4.4
    - tls://dns.google

proxies:
`;

		for (const p of proxies) {
			yaml += `  - name: "${p.name}"\n`;
			yaml += `    type: ${p.type}\n`;
			yaml += `    server: ${p.server}\n`;
			yaml += `    port: ${p.port}\n`;

			if (p.type === "vless") {
				yaml += `    uuid: ${p.uuid}\n`;
				yaml += `    network: ws\n`;
				yaml += `    tls: ${p.tls}\n`;
				yaml += `    udp: true\n`;
				yaml += `    client-fingerprint: ${p["client-fingerprint"]}\n`;
				if (p.servername) yaml += `    servername: ${p.servername}\n`;
				if (p["skip-cert-verify"] !== undefined) yaml += `    skip-cert-verify: ${p["skip-cert-verify"]}\n`;
				yaml += `    ws-opts:\n`;
				yaml += `      path: ${p["ws-opts"].path}\n`;
				yaml += `      headers:\n`;
				yaml += `        Host: ${p["ws-opts"].headers.Host}\n`;
			} else if (p.type === "trojan") {
				yaml += `    password: ${p.password}\n`;
				yaml += `    network: ws\n`;
				yaml += `    tls: ${p.tls}\n`;
				yaml += `    udp: true\n`;
				yaml += `    client-fingerprint: ${p["client-fingerprint"]}\n`;
				if (p.sni) yaml += `    sni: ${p.sni}\n`;
				if (p["skip-cert-verify"] !== undefined) yaml += `    skip-cert-verify: ${p["skip-cert-verify"]}\n`;
				yaml += `    ws-opts:\n`;
				yaml += `      path: ${p["ws-opts"].path}\n`;
				yaml += `      headers:\n`;
				yaml += `        Host: ${p["ws-opts"].headers.Host}\n`;
			} else if (p.type === "ss") {
				yaml += `    cipher: ${p.cipher}\n`;
				yaml += `    password: ${p.password}\n`;
				yaml += `    plugin: v2ray-plugin\n`;
				yaml += `    plugin-opts:\n`;
				yaml += `      mode: websocket\n`;
				yaml += `      host: ${p["plugin-opts"].host}\n`;
				yaml += `      path: ${p["plugin-opts"].path}\n`;
				yaml += `      tls: ${p["plugin-opts"].tls}\n`;
				yaml += `      mux: true\n`;
			}
			yaml += `\n`;
		}

		yaml += `proxy-groups:
  - name: 🚀 Proxy
    type: select
    proxies:
`;
		for (const n of proxyNames) {
			yaml += `      - "${n}"\n`;
		}
		yaml += `      - DIRECT\n`;

		yaml += `
  - name: ♻️ Auto
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
`;
		for (const n of proxyNames) {
			yaml += `      - "${n}"\n`;
		}

		yaml += `
rules:
  - GEOIP,IR,DIRECT
  - DOMAIN-SUFFIX,ir,DIRECT
  - DOMAIN-KEYWORD,iran,DIRECT
  - MATCH,🚀 Proxy
`;

		// اطلاعات حجم و انقضا
		const downloadBytes = Math.floor(getEffectiveTrafficGb((user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)), user.traffic_multiplier) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					expireTimestamp = Math.floor((user.first_connection_time + user.expiry_days * 86400000) / 1000);
				} else {
					expireTimestamp = Math.floor((Date.now() + user.expiry_days * 86400000) / 1000);
				}
			} else if (user.created_at) {
				expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
			}
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;

		return new Response(yaml, {
			headers: {
				"Content-Type": "text/yaml; charset=utf-8",
				"Content-Disposition": `attachment; filename="${user.username}-clash.yaml"`,
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
				...buildAnnounceHeaders(user),
			},
		});
	}
}
async function flushExpiredTraffic(env) {
	const now = Date.now();
	for (const [key, val] of DNS_CACHE.entries()) {
		if (now > val.expires) DNS_CACHE.delete(key);
	}
	for (const [ip, record] of LOGIN_ATTEMPTS.entries()) {
		if (now - record.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
	}
	const allUsers = new Set([...GLOBAL_TRAFFIC_CACHE.keys(), ...USER_REQ_CACHE.keys()]);
	for (const uname of allUsers) {
		const cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
		const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
		const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) {
			GLOBAL_TRAFFIC_CACHE.delete(uname);
			USER_REQ_CACHE.delete(uname);
			if (activeCount <= 0) {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
			}
			continue;
		}
		if (GLOBAL_WRITE_LOCK.get(uname)) continue;
		const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 60000) {
			GLOBAL_WRITE_LOCK.set(uname, true);
			GLOBAL_TRAFFIC_CACHE.set(uname, 0);
			USER_REQ_CACHE.set(uname, 0);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, daily_used_gb = daily_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, deltaGb, cachedReqs, now, uname).run();
				await recordPanelDailyTraffic(env, deltaGb);
			} catch (e) {
				console.error(e.message);
			} finally {
				GLOBAL_WRITE_LOCK.delete(uname);
				if (activeCount <= 0) {
					GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
				}
			}
		}
	}
}
function getSelectedUserProxy(userSocks5, request) {
	if (!userSocks5) return "";
	let proxyList = [];
	try {
		if (userSocks5.trim().startsWith("[")) {
			proxyList = JSON.parse(userSocks5);
		} else {
			proxyList = [userSocks5];
		}
	} catch (e) {
		proxyList = [userSocks5];
	}
	if (!Array.isArray(proxyList) || proxyList.length === 0) return "";
	let idx = -1;
	if (request) {
		try {
			const url = new URL(request.url);
			const pathMatch = url.pathname.match(/\/loc-(\d+)/);
			if (pathMatch) {
				idx = parseInt(pathMatch[1], 10);
			} else {
				const locParam = url.searchParams.get("loc");
				if (locParam !== null && !isNaN(Number(locParam))) {
					idx = parseInt(locParam, 10);
				}
			}
		} catch (e) { }
	}
	if (idx === -1) return "";
	const selected = proxyList[idx] || proxyList[0];
	return typeof selected === "object" ? selected.proxy || "" : String(selected || "");
}
async function handlevIees(env, storedData = null, ctx = null, request = null) {
	let rawClientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	let clientIP = rawClientIP;
	if (rawClientIP !== "unknown") {
		if (rawClientIP.includes(":")) {
			const parts = rawClientIP.split(":");
			if (parts.length >= 4) {
				clientIP = parts.slice(0, 4).join(":") + "::/64";
			}
		} else if (rawClientIP.includes(".")) {
			const parts = rawClientIP.split(".");
			if (parts.length === 4) {
				clientIP = parts.slice(0, 3).join(".") + ".0/24";
			}
		}
	}
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	let username = null;
	let validUUID = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	let sessionTrafficMultiplier = 1;
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
		GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
		GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
		if (GLOBAL_WRITE_LOCK.get(username)) return;
		let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 500 * 1024 * 1024;
		if ((current >= thresholdBytes && now - lastDbWrite > 180000) || (current > 0 && now - lastDbWrite > 900000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) - toCommit);
			USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) - toCommitReq);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, daily_used_gb = daily_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, deltaGb, toCommitReq, now, username).run();
					await recordPanelDailyTraffic(env, deltaGb);
				} catch (e) {
					console.error(e.message);
					GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) + toCommit);
					USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) + toCommitReq);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	let hasCountedAsActive = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (hasCountedAsActive) {
			activeCount = Math.max(0, activeCount - 1);
			let userIps = GLOBAL_ACTIVE_IPS.get(uname);
			if (userIps) {
				let ipConns = userIps.get(clientIP) || 0;
				if (ipConns <= 1) {
					userIps.delete(clientIP);
					if (userIps.size === 0) GLOBAL_ACTIVE_IPS.delete(uname);
				} else {
					userIps.set(clientIP, ipConns - 1);
				}
			}
		}
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			GLOBAL_ACTIVE_IPS.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			let nowOff = Date.now();
			let lastWrite = GLOBAL_LAST_DB_WRITE.get(uname) || 0;
			let shouldCommit = (cachedBytes >= 20 * 1024 * 1024) || (nowOff - lastWrite > 600000) || (cachedReqs >= 20);
			if (shouldCommit && (cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				GLOBAL_LAST_DB_WRITE.set(uname, nowOff);
				GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) - cachedBytes);
				USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) - cachedReqs);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, daily_used_gb = daily_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, deltaGb, cachedReqs, nowOff, uname).run();
						const _mOff = GLOBAL_USER_MULTIPLIER.get(uname) || 1;
						await recordPanelDailyTraffic(env, _mOff > 0 ? deltaGb / _mOff : deltaGb);
					} catch (e) {
						console.error(e.message);
						GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) + cachedBytes);
						USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) + cachedReqs);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	let heartbeat;
	const runHeartbeat = async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID || !username) {
					heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
					return;
				}
				const nowTime = Date.now();
				const lastCheck = GLOBAL_LAST_ACTIVE_WRITE.get(username + "_hb") || 0;
				if (nowTime - lastCheck >= 180000) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username + "_hb", nowTime);
					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips, daily_limit_gb, daily_used_gb, daily_lock_until, daily_lock_step, traffic_multiplier FROM users WHERE uuid = ?").bind(validUUID).first();
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						const liveGbRealHb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
						const liveGb = getEffectiveTrafficGb(liveGbRealHb, user.traffic_multiplier);
						if (user.limit_gb && liveGb >= user.limit_gb) isExpired = true;
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) isExpired = true;
						const liveDailyGbRealHb = (user.daily_used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
						const liveDailyGbHb = getEffectiveTrafficGb(liveDailyGbRealHb, user.traffic_multiplier);
						if (await evaluateDailyLock(env, user, username, liveDailyGbHb, ctx)) isExpired = true;
						if (user.expiry_days) {
							if (user.start_on_first_connect === 1) {
								if (user.first_connection_time) {
									const expiryDate = new Date(user.first_connection_time + user.expiry_days * 86400000);
									if (nowTime > expiryDate.getTime()) isExpired = true;
								}
							} else if (user.created_at) {
								const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000);
								if (nowTime > expiryDate.getTime()) isExpired = true;
							}
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try {
								activeIps = JSON.parse(user.active_ips || "{}");
							} catch (e) { }
							let hasChanges = false;
							let needsDbUpdateForTimestamp = false;
							
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 180000 && ip !== clientIP) {
									delete activeIps[ip];
									hasChanges = true;
								}
							}
							if (!activeIps[clientIP]) {
								activeIps[clientIP] = { timestamp: nowTime, count: 1 };
								hasChanges = true;
							} else {
								const currentData = activeIps[clientIP];
								const lastSeen = typeof currentData === "object" ? currentData.timestamp : currentData;
								if (nowTime - lastSeen > 150000) {
									if (typeof activeIps[clientIP] === "object") {
										activeIps[clientIP].timestamp = nowTime;
									} else {
										activeIps[clientIP] = { timestamp: nowTime, count: 1 };
									}
									needsDbUpdateForTimestamp = true;
								}
							}
							const sortedIps = Object.keys(activeIps).sort((a, b) => {
								const tA = typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
								const tB = typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
								return tB - tA;
							});
							/* Bypassed: if (user.ip_limit && user.ip_limit > 0 && sortedIps.indexOf(clientIP) >= user.ip_limit) isIpLimitExpired = true; */
							if (hasChanges || needsDbUpdateForTimestamp || isIpLimitExpired) updatedActiveIps = JSON.stringify(activeIps);
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						/* Bypassed: clearTimeout(heartbeat); closeSocketQuietly(serverSock); return; */
					}
					if (updatedActiveIps !== null) {
						GLOBAL_LAST_DB_WRITE.set(username, nowTime);
						await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(nowTime, updatedActiveIps, username).run();
						try {
							const op = detectOperatorFromRequest(request, clientIP);
							if (op) {
								// attach operator on this IP entry
								try {
									const parsed = JSON.parse(updatedActiveIps || "{}");
									if (parsed[clientIP] && typeof parsed[clientIP] === "object") {
										parsed[clientIP].operator = op;
										updatedActiveIps = JSON.stringify(parsed);
										await env.DB.prepare("UPDATE users SET active_ips = ? WHERE username = ?").bind(updatedActiveIps, username).run();
									}
								} catch (e2) {}
								await recordUserOperator(env, username, op);
							}
						} catch (e) {}
					} else if (nowTime - (GLOBAL_LAST_DB_WRITE.get(username) || 0) >= 900000) {
						GLOBAL_LAST_DB_WRITE.set(username, nowTime);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(nowTime, username).run();
					}
				}
			} catch (e) { }
			heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
		} else {
			clearTimeout(heartbeat);
		}
	};
	heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let isTrojanProto = false;
	let isShadowsocksProto = false;
	let ssUpAeadCtx = null;
	let ssUpExpectedPayloadLen = null;
	let ssUpBuffer = new Uint8Array(0);
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) { }
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) { }
			closeSocketQuietly(serverSock);
		},
		name: "vIeesWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		addBytes(bytes);
		if (isDnsQuery) {
			if (isTrojanProto) {
				await forwardTrojanUDP(chunk, serverSock, addBytes, targetDns);
			} else {
				await forwardvIeesUDP(chunk, serverSock, null, addBytes, targetDns);
			}
			return;
		}
		if (isHeaderParsed) {
			if (remoteConnWrapper.connectingPromise) {
				await remoteConnWrapper.connectingPromise;
			}
			if (isShadowsocksProto && ssUpAeadCtx) {
				ssUpBuffer = concatBytes(ssUpBuffer, chunk);
				while (true) {
					if (ssUpExpectedPayloadLen === null) {
						if (ssUpBuffer.byteLength < 18) break;
						const encLen = ssUpBuffer.slice(0, 18);
						const decLen = await SSCrypto.decryptChunk(ssUpAeadCtx.key, ssUpAeadCtx.nonce, encLen);
						if (!decLen) { serverSock.close(); return; }
						ssUpExpectedPayloadLen = (decLen[0] << 8) | decLen[1];
						ssUpBuffer = ssUpBuffer.slice(18);
					}
					if (ssUpExpectedPayloadLen !== null) {
						if (ssUpBuffer.byteLength < ssUpExpectedPayloadLen + 16) break;
						const encPayload = ssUpBuffer.slice(0, ssUpExpectedPayloadLen + 16);
						const decPayload = await SSCrypto.decryptChunk(ssUpAeadCtx.key, ssUpAeadCtx.nonce, encPayload);
						if (!decPayload) { serverSock.close(); return; }
						await writeToRemote(decPayload);
						ssUpBuffer = ssUpBuffer.slice(ssUpExpectedPayloadLen + 16);
						ssUpExpectedPayloadLen = null;
					}
				}
			} else {
				await writeToRemote(chunk);
			}
			return;
		}
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			
			let isTrojan = false;
			let isShadowsocks = false;
			if (chunkBuffer.byteLength >= 58 && chunkBuffer[56] === 0x0D && chunkBuffer[57] === 0x0A) {
				const checkHex = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
				if (/^[0-9a-f]{56}$/.test(checkHex)) {
					isTrojan = true;
				}
			} else if (chunkBuffer.byteLength > 0 && chunkBuffer[0] !== 0x00 && chunkBuffer[0] !== 0x01 && chunkBuffer[0] !== 0x02 && chunkBuffer[0] !== 0x03) {
				isShadowsocks = true;
			}
			
			let cmd = 0;
			let port = 0;
			let addrType = 0;
			let addr = "";
			let rawData = null;
			let respHeader = null;
			let userLookupKey = null;
			let user = null;

			if (isHeaderParsing) return;
			isHeaderParsing = true;
			isTrojanProto = isTrojan;

			try {
				if (isShadowsocks) {
					if (chunkBuffer.byteLength < 50) { isHeaderParsing = false; return; }
					if (request) {
						const reqUrl = new URL(request.url);
						const pathParts = reqUrl.pathname.split("/");
						if (pathParts.length >= 4) userLookupKey = pathParts[3];
					}
					if (userLookupKey) {
						user = await env.DB.prepare("SELECT * FROM users WHERE uuid LIKE ? AND is_active = 1").bind('%' + userLookupKey).first();
					}
					if (!user || !String(user.connection_type).includes("shadowsocks")) {
						serverSock.close();
						return;
					}
					
					isShadowsocksProto = true;
					const salt = chunkBuffer.slice(0, 32);
					const key = await SSCrypto.deriveSubkey(user.uuid, salt);
					const nonce = new Uint8Array(12);
					ssUpAeadCtx = { key, nonce };
					const encLen = chunkBuffer.slice(32, 32 + 18);
					const decLenBuf = await SSCrypto.decryptChunk(key, nonce, encLen);
					if (!decLenBuf) { serverSock.close(); return; }
					const payloadLen = (decLenBuf[0] << 8) | decLenBuf[1];
					if (chunkBuffer.byteLength < 50 + payloadLen + 16) return;
					const encPayload = chunkBuffer.slice(50, 50 + payloadLen + 16);
					const decryptedPayload = await SSCrypto.decryptChunk(key, nonce, encPayload);
					if (!decryptedPayload) { serverSock.close(); return; }
					
					let offset = 0;
					addrType = decryptedPayload[offset++];
					if (addrType === 1) {
						addr = `${decryptedPayload[offset++]}.${decryptedPayload[offset++]}.${decryptedPayload[offset++]}.${decryptedPayload[offset++]}`;
					} else if (addrType === 3) {
						const domainLen = decryptedPayload[offset++];
						addr = TEXT_DECODER.decode(decryptedPayload.slice(offset, offset + domainLen));
						offset += domainLen;
					} else if (addrType === 4) {
						const v6 = [];
						for (let i = 0; i < 8; i++) v6.push(((decryptedPayload[offset++] << 8) | decryptedPayload[offset++]).toString(16));
						addr = v6.join(":");
					} else {
						serverSock.close();
						return;
					}
					port = (decryptedPayload[offset++] << 8) | decryptedPayload[offset++];
					cmd = 1;
					rawData = decryptedPayload.slice(offset);
					
					let bufOffset = 50 + payloadLen + 16;
					ssUpBuffer = chunkBuffer.slice(bufOffset);
					while (true) {
						if (ssUpExpectedPayloadLen === null) {
							if (ssUpBuffer.byteLength < 18) break;
							const encL = ssUpBuffer.slice(0, 18);
							const decL = await SSCrypto.decryptChunk(key, nonce, encL);
							if (!decL) { serverSock.close(); return; }
							ssUpExpectedPayloadLen = (decL[0] << 8) | decL[1];
							ssUpBuffer = ssUpBuffer.slice(18);
						}
						if (ssUpExpectedPayloadLen !== null) {
							if (ssUpBuffer.byteLength < ssUpExpectedPayloadLen + 16) break;
							const encP = ssUpBuffer.slice(0, ssUpExpectedPayloadLen + 16);
							const decP = await SSCrypto.decryptChunk(key, nonce, encP);
							if (!decP) { serverSock.close(); return; }
							rawData = concatBytes(rawData, decP);
							ssUpBuffer = ssUpBuffer.slice(ssUpExpectedPayloadLen + 16);
							ssUpExpectedPayloadLen = null;
						}
					}
					
					respHeader = null;
					
				} else if (isTrojan) {
					const hexHash = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
					userLookupKey = hexHash;
					let offset = 58;
					cmd = chunkBuffer[offset++];
					addrType = chunkBuffer[offset++];
					if (addrType === 1) {
						if (chunkBuffer.byteLength < offset + 4 + 2 + 2) { isHeaderParsing = false; return; }
						addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
					} else if (addrType === 3) {
						if (chunkBuffer.byteLength < offset + 1) { isHeaderParsing = false; return; }
						const domainLen = chunkBuffer[offset++];
						if (chunkBuffer.byteLength < offset + domainLen + 2 + 2) { isHeaderParsing = false; return; }
						addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
						offset += domainLen;
					} else if (addrType === 4) {
						if (chunkBuffer.byteLength < offset + 16 + 2 + 2) { isHeaderParsing = false; return; }
						const v6 = [];
						for (let i = 0; i < 8; i++) {
							v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
						}
						addr = v6.join(":");
					} else {
						serverSock.close();
						return;
					}
					port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
					if (chunkBuffer[offset] !== 0x0D || chunkBuffer[offset + 1] !== 0x0A) {
						serverSock.close();
						return;
					}
					offset += 2;
					rawData = chunkBuffer.slice(offset);
					respHeader = null;
					
					user = await env.DB.prepare("SELECT * FROM users WHERE trojan_hash = ? OR uuid = ?").bind(userLookupKey, userLookupKey).first();
					if (!user) {
						const { results } = await env.DB.prepare("SELECT * FROM users WHERE is_active = 1").all();
						if (results) {
							user = results.find(u => u.uuid && sha224Pure(u.uuid) === userLookupKey);
							if (user) {
								const updateHashTask = async () => {
									try { await env.DB.prepare("UPDATE users SET trojan_hash = ? WHERE id = ?").bind(userLookupKey, user.id).run(); } catch (err) {}
								};
								if (ctx) ctx.waitUntil(updateHashTask());
								else updateHashTask();
							}
						}
					}
				} else {
					if (chunkBuffer.byteLength < 24) { isHeaderParsing = false; return; }
					let optLen = chunkBuffer[17];
					let requiredLen = 18 + optLen + 4;
					if (chunkBuffer.byteLength < requiredLen) { isHeaderParsing = false; return; }
					addrType = chunkBuffer[18 + optLen + 3];
					if (addrType === 1) requiredLen += 4;
					else if (addrType === 2) {
						requiredLen += 1;
						if (chunkBuffer.byteLength < requiredLen) { isHeaderParsing = false; return; }
						requiredLen += chunkBuffer[18 + optLen + 4];
					} else if (addrType === 3) requiredLen += 16;
					else { serverSock.close(); return; }
					if (chunkBuffer.byteLength < requiredLen) { isHeaderParsing = false; return; }
					reqUUID = extractUUIDFromvIees(chunkBuffer);
					if (!reqUUID) { serverSock.close(); return; }
					userLookupKey = reqUUID;
					let offset = 17;
					optLen = chunkBuffer[offset++];
					offset += optLen;
					cmd = chunkBuffer[offset++];
					port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
					addrType = chunkBuffer[offset++];
					if (addrType === 1) {
						addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
					} else if (addrType === 2) {
						const domainLen = chunkBuffer[offset++];
						addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
						offset += domainLen;
					} else if (addrType === 3) {
						const v6 = [];
						for (let i = 0; i < 8; i++) v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
						addr = v6.join(":");
					}
					rawData = chunkBuffer.slice(offset);
					respHeader = new Uint8Array([chunkBuffer[0], 0]);
					user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(userLookupKey).first();
				}
			} catch (e) { }
			if (!user) {
				serverSock.close();
				return;
			}
			const userConn = String(user.connection_type || "vless").toLowerCase();
			if (isTrojan) {
				if (!userConn.includes("trojan")) {
					serverSock.close();
					return;
				}
			} else if (isShadowsocks) {
				if (!userConn.includes("shadowsocks")) {
					serverSock.close();
					return;
				}
			} else {
				if (!userConn.includes("vless") && userConn !== "vl" + "e" + "ss") {
					serverSock.close();
					return;
				}
			}
			reqUUID = user.uuid;
			if (request) {
				const reqUrl = new URL(request.url);
				const expectedPath = "/stream/PANEL_CASPIAN/" + ((user.uuid || "").split("-")[4] || "default");
				if (!reqUrl.pathname.startsWith(expectedPath)) {
					serverSock.close();
					return;
				}
			}
			username = user.username;
			validUUID = reqUUID;
			sessionTrafficMultiplier = parseTrafficMultiplier(user.traffic_multiplier);
			GLOBAL_USER_MULTIPLIER.set(username, sessionTrafficMultiplier);
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			if (!GLOBAL_TRAFFIC_CACHE.has(username)) {
				GLOBAL_TRAFFIC_CACHE.set(username, 0);
			}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (user.is_active === 0) {
				serverSock.close();
				return;
			}
			const liveGbReal = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
			const liveGb = getEffectiveTrafficGb(liveGbReal, user.traffic_multiplier);
			if (user.limit_gb && liveGb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) > user.limit_req) {
				serverSock.close();
				return;
			}
			const liveDailyGbReal = (user.daily_used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
			const liveDailyGb = getEffectiveTrafficGb(liveDailyGbReal, user.traffic_multiplier);
			if (await evaluateDailyLock(env, user, username, liveDailyGb, ctx)) {
				serverSock.close();
				return;
			}
			if (user.start_on_first_connect === 1 && !user.first_connection_time && !GLOBAL_WRITE_LOCK.get(reqUUID + "_first_conn")) {
				GLOBAL_WRITE_LOCK.set(reqUUID + "_first_conn", true);
				const firstConnectNow = Date.now();
				user.first_connection_time = firstConnectNow;
				const updateFirstTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET first_connection_time = ? WHERE uuid = ?").bind(firstConnectNow, reqUUID).run();
					} catch (e) {
						GLOBAL_WRITE_LOCK.delete(reqUUID + "_first_conn");
					}
				};
				if (ctx) ctx.waitUntil(updateFirstTask());
				else updateFirstTask();
			}
			if (user.expiry_days) {
				let isTimeExpired = false;
				if (user.start_on_first_connect === 1) {
					if (user.first_connection_time) {
						const expiryDate = new Date(user.first_connection_time + user.expiry_days * 24 * 60 * 60 * 1000);
						if (new Date() > expiryDate) isTimeExpired = true;
					}
				} else if (user.created_at) {
					const created = new Date(user.created_at);
					const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
					if (new Date() > expiryDate) isTimeExpired = true;
				}
				if (isTimeExpired) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) { }
					serverSock.close();
					return;
				}
			}
			if (user.block_porn === 1 && user.block_ads === 1) {
				targetDns = "94.140.14.15";
				targetDoh = "https://family.adguard-dns.com/dns-query";
			} else if (user.block_porn === 1) {
				targetDns = "1.1.1.3";
				targetDoh = "https://family.cloudflare-dns.com/dns-query";
			} else if (user.block_ads === 1) {
				targetDns = "94.140.14.14";
				targetDoh = "https://dns.adguard-dns.com/dns-query";
			}
			if (clientIP && clientIP !== "unknown") {
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) { }
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 180000) delete activeIps[ip];
				}
				let isNewIp = false;
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps);
					/* Bypassed: if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) { serverSock.close(); return; } */
					activeIps[clientIP] = { timestamp: now, count: 1 };
					isNewIp = true;
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
				}
				try {
					const opNow = detectOperatorFromRequest(request, clientIP);
					if (opNow && typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].operator = opNow;
						if (ctx) ctx.waitUntil(recordUserOperator(env, username, opNow));
						else recordUserOperator(env, username, opNow);
					}
				} catch (eOp) {}
				let lastDbW = GLOBAL_LAST_DB_WRITE.get(username) || 0;
				let needIpWrite = isNewIp;
				let needTimeWrite = (now - lastDbW > 900000);
				if (needIpWrite || needTimeWrite || (activeIps[clientIP] && activeIps[clientIP].operator)) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
					GLOBAL_LAST_DB_WRITE.set(username, now);
					const updateTask = async () => {
						try {
							await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
						} catch (e) { }
					};
					if (ctx) ctx.waitUntil(updateTask());
					else updateTask();
				}
			}
			isHeaderParsed = true;
			chunkBuffer = new Uint8Array(0);
			let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
			ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
			let userIps = GLOBAL_ACTIVE_IPS.get(username);
			if (!userIps) { userIps = new Map(); GLOBAL_ACTIVE_IPS.set(username, userIps); }
			userIps.set(clientIP, (userIps.get(clientIP) || 0) + 1);
			hasCountedAsActive = true;
			try {
				let isDomainAddress = (isTrojanProto && addrType === 3) || (!isTrojanProto && addrType === 2);
				let isIpAddress = (isTrojanProto && (addrType === 1 || addrType === 4)) || (!isTrojanProto && (addrType === 1 || addrType === 3));
				let sniffedDomain = null;
				if (isIpAddress && port === 443 && rawData && rawData.byteLength > 43) {
					try {
						let pos = 43;
						if (rawData[0] === 0x16 && rawData[5] === 0x01) {
							const sessionIdLen = rawData[pos];
							pos += 1 + sessionIdLen;
							const cipherSuitesLen = (rawData[pos] << 8) | rawData[pos + 1];
							pos += 2 + cipherSuitesLen;
							const compMethodsLen = rawData[pos];
							pos += 1 + compMethodsLen;
							const extensionsLen = (rawData[pos] << 8) | rawData[pos + 1];
							pos += 2;
							const endPos = Math.min(pos + extensionsLen, rawData.byteLength);
							while (pos + 4 <= endPos) {
								const extType = (rawData[pos] << 8) | rawData[pos + 1];
								const extLen = (rawData[pos + 2] << 8) | rawData[pos + 3];
								pos += 4;
								if (extType === 0x0000) {
									let sniListLen = (rawData[pos] << 8) | rawData[pos + 1];
									let sniPos = pos + 2;
									if (rawData[sniPos] === 0x00) {
										let sniLen = (rawData[sniPos + 1] << 8) | rawData[sniPos + 2];
										sniffedDomain = new TextDecoder().decode(rawData.slice(sniPos + 3, sniPos + 3 + sniLen));
										break;
									}
								}
								pos += extLen;
							}
						}
					} catch (e) {}
				}
				if (user.block_porn === 1 || user.block_ads === 1) {
					const dohIps = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001"];
					if (port === 443 && isIpAddress && dohIps.includes(addr)) {
						serverSock.close();
						return;
					}
				}
				let checkDomain = isDomainAddress ? addr : sniffedDomain;
				if ((user.block_ads === 1 || user.block_porn === 1) && checkDomain && port !== 53) {
					try {
						const dnsCheck = await dohQuery(checkDomain, "A", targetDoh);
						const isBlocked = dnsCheck.some((r) => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
						if (isBlocked) {
							serverSock.close();
							return;
						}
						if (user.block_porn === 1 && dnsCheck.length > 0) {
							const isSearchEngine = /(google\.|bing\.com|yandex\.|yahoo\.|duckduckgo\.com|youtube\.)/i.test(checkDomain);
							if (isSearchEngine) {
								const validIpRecord = dnsCheck.find(r => r.type === 1 || r.type === 28);
								if (validIpRecord) {
									const safeIp = validIpRecord.data;
									if (safeIp && safeIp !== "0.0.0.0" && safeIp !== "::") {
										addr = safeIp;
									}
								}
							}
						}
					} catch (e) { }
				}
				if ((isTrojanProto && cmd === 3) || (!isTrojanProto && cmd === 2)) {
					if (port === 53) {
						isDnsQuery = true;
						if (isTrojanProto) {
							await forwardTrojanUDP(rawData, serverSock, addBytes, targetDns);
						} else {
							await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
						}
						return;
					}
					serverSock.close();
					return;
				}
				if (port === 25 || /^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|localhost$|::1|::ffff:|fd[0-9a-f]{2}:|fe80:)/i.test(addr)) {
					serverSock.close();
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
						let socks5 = getSelectedUserProxy(user?.user_socks5, request);
						
						const panelHost = request ? new URL(request.url).hostname : null;
						let loopBypassProxies = [];
						
						if (!socks5 && panelHost && (addr === panelHost || addr.endsWith('.workers.dev') || addr.endsWith('.pages.dev'))) {
							if (!GLOBAL_IPS_CACHE.loop_bypass || Date.now() - (GLOBAL_IPS_CACHE.loop_last_fetch || 0) > 3600000) {
								GLOBAL_IPS_CACHE.loop_bypass = [];
								let targetCountries = ["DE", "US", "GB", "NL", "FR"];
								
								try {
									const vipRes = await fetchWithFallback("vip-list");
									if (vipRes.ok) {
										const files = await vipRes.json();
										const fetchedVips = files.filter(f => f.name.endsWith(".txt")).map(f => f.name.replace(".txt", "").toUpperCase());
										if (fetchedVips.length > 0) targetCountries = fetchedVips;
									}
								} catch(e) {}
								
								targetCountries = targetCountries.sort(() => 0.5 - Math.random()).slice(0, 3);
								
								for (const fc of targetCountries) {
									try {
										const res = await fetchWithFallback("proxy_vip/" + fc + ".txt");
										if (res.ok) {
											const text = await res.text();
											const lines = text.split("\n").map(l => l.trim()).filter(l => l.length > 5);
											if (lines.length > 0) {
												GLOBAL_IPS_CACHE.loop_bypass = GLOBAL_IPS_CACHE.loop_bypass.concat(lines);
											}
										}
									} catch(e) {}
								}
								if (GLOBAL_IPS_CACHE.loop_bypass.length > 0) {
									GLOBAL_IPS_CACHE.loop_last_fetch = Date.now();
								}
							}
							
							if (GLOBAL_IPS_CACHE.loop_bypass && GLOBAL_IPS_CACHE.loop_bypass.length > 0) {
								const shuffled = [...GLOBAL_IPS_CACHE.loop_bypass].sort(() => 0.5 - Math.random());
								loopBypassProxies = shuffled.slice(0, 4);
							}
						}

						if (loopBypassProxies.length > 0) {
							const ac = new AbortController();
							try {
								s = await Promise.any(
									loopBypassProxies.map(p => 
										connectProxy(p, addr, port, dataPayload).then(sock => {
											if (ac.signal.aborted) {
												try { sock.close(); } catch(e) {}
												throw new Error("Cancelled");
											}
											ac.abort();
											return sock;
										})
									)
								);
							} catch (e) {
								throw new Error("Loop bypass proxies failed");
							}
						} else if (socks5) {
							try {
								s = await connectProxy(socks5, addr, port, dataPayload);
							} catch (proxyErr) {
								if (user.auto_rotate_user_proxy === 1) {
									const replaceTask = replaceBrokenProxy(user.username, env, socks5);
									if (ctx) ctx.waitUntil(replaceTask);
									else replaceTask.catch(() => { });
								}
								throw proxyErr;
							}
						} else {
							try {
								s = await connectDirect(addr, port, dataPayload, targetDoh);
							} catch (directErr) {
								if (useFallback) {
									const IATA_LIST = ["FRA", "AMS", "LHR", "CDG", "VIE", "HEL", "CPH", "MAD", "BCN", "MXP", "FCO", "ZRH", "WAW", "PRG", "DUB", "SNN", "MAN", "GVA", "BRU", "LIS", "ATH", "SOF", "OTP", "TLL", "RIX", "VNO", "BUD", "BEG", "ZAG", "MUC", "HAM", "SIN", "NRT", "HKG", "TPE", "ICN", "DXB", "BOM", "DEL", "YYZ", "YUL", "YVR", "JFK", "EWR", "LAX", "SFO", "ORD", "MIA", "DFW", "SEA", "IAD", "ATL"];
									let fallbackSuccess = false;
									const shuffledIatas = IATA_LIST.slice().sort(() => 0.5 - Math.random());
									const maxAttempts = 3;
									for (let i = 0; i < maxAttempts && i < shuffledIatas.length; i++) {
										const fallbackHost = shuffledIatas[i].toLowerCase() + ".proxyip.cmliussss.net";
										try {
											s = await connectDirect(fallbackHost, port, dataPayload, targetDoh);
											fallbackSuccess = true;
											break;
										} catch (fallbackErr) { }
									}
									if (!fallbackSuccess) throw directErr;
								} else {
							throw directErr;
						}
					}
				}
				remoteConnWrapper.socket = s;
				let aeadCtx = null;
				if (isShadowsocksProto && validUUID) {
					const downSalt = crypto.getRandomValues(new Uint8Array(32));
					const downKey = await SSCrypto.deriveSubkey(validUUID, downSalt);
					aeadCtx = { key: downKey, nonce: new Uint8Array(12), salt: downSalt };
				}
				connectStreams(s, serverSock, respHeader, null, addBytes, aeadCtx).finally(() => closeSocketQuietly(serverSock));
			})();
			remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		clearTimeout(heartbeat);
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		if (typeof event.data === "string") return;
		const size = event.data.byteLength || 0;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(event.data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearTimeout(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	return new Response(null, { status: 101, webSocket: clientSock });
}
let CF_USAGE_CACHE = null;
let CF_USAGE_LAST_FETCH = 0;
let CF_USAGE_CACHE_DATE = ""; 

async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
	const nowTime = Date.now();
	const todayStr = new Date().toISOString().split("T")[0];
	
	if (CF_USAGE_CACHE && (nowTime - CF_USAGE_LAST_FETCH < 15000) && CF_USAGE_CACHE_DATE === todayStr) {
		return CF_USAGE_CACHE;
	}
	try {
		const now = new Date();
		const startOfDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
		const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const q = `query {
	  viewer {
		accounts(filter: {accountTag: "${env.CF_ACCOUNT_ID}"}) {
		  today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
			sum { requests }
		  }
		  total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
			sum { requests }
		  }
		  d1: d1AnalyticsAdaptiveGroups(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
			sum { rowsRead rowsWritten }
		  }
		}
	  }
	}`;
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
			cache: "no-store" 
		});
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		const d1Reads = acc?.d1?.[0]?.sum?.rowsRead || 0;
		const d1Writes = acc?.d1?.[0]?.sum?.rowsWritten || 0;
		
		CF_USAGE_CACHE = { today: todayReqs, total: totalReqs, d1Reads, d1Writes };
		CF_USAGE_LAST_FETCH = nowTime;
		CF_USAGE_CACHE_DATE = todayStr;
		return CF_USAGE_CACHE;
	} catch (e) {
		return CF_USAGE_CACHE || { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatBytes(...chunkList) {
	if (chunkList.length === 2) {
		const a = convertToUint8Array(chunkList[0]);
		const b = convertToUint8Array(chunkList[1]);
		if (!a.byteLength) return b;
		if (!b.byteLength) return a;
		const merged = new Uint8Array(a.byteLength + b.byteLength);
		merged.set(a, 0);
		merged.set(b, a.byteLength);
		return merged;
	}
	const chunks = chunkList.map(convertToUint8Array);
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) { }
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (DNS_CACHE.has(cacheKey)) {
		const cached = DNS_CACHE.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		DNS_CACHE.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = TEXT_ENCODER.encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(TEXT_DECODER.decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		if (DNS_CACHE.size >= DNS_CACHE_MAX_ENTRIES) {
			const oldestKey = DNS_CACHE.keys().next().value;
			if (oldestKey !== undefined) DNS_CACHE.delete(oldestKey);
		}
		DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;
	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			let batchCount = 0;
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
				batchCount++;
				if (batchCount >= 16) {
					await Promise.resolve();
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) { }
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const MAX_CAP = 256 * 1024;
	const MIN_CAP = 16 * 1024;
	let currentPacketCap = 128 * 1024;
	const tailBytes = 512;
	let header = headerData;
	let pendingBuffer = null;
	let pendingBytes = 0;
	let flushPromise = null;
	let microtaskQueued = false;
	const adjustSmartBuffer = () => {
		const buffered = webSocket.bufferedAmount || 0;
		if (buffered > 256 * 1024) {
			currentPacketCap = Math.max(MIN_CAP, Math.floor(currentPacketCap / 2));
		} else if (buffered < 32 * 1024) {
			currentPacketCap = Math.min(MAX_CAP, currentPacketCap * 2);
		}
	};
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== 1) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
		if (typeof webSocket.bufferedAmount === "number") {
			while (webSocket.bufferedAmount > 1024 * 1024) {
				if (webSocket.readyState !== 1) break;
				await new Promise(r => setTimeout(r, 20));
			}
		}
	};
	const attachResponseHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};
	const flush = async () => {
		microtaskQueued = false;
		while (flushPromise) await flushPromise;
		if (!pendingBytes) return;
		const output = pendingBuffer.slice(0, pendingBytes);
		adjustSmartBuffer();
		pendingBytes = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= currentPacketCap) {
					const sendBytes = Math.min(currentPacketCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					adjustSmartBuffer();
					continue;
				}
				const copyBytes = Math.min(currentPacketCap - pendingBytes, totalBytes - offset);
				if (!pendingBuffer) pendingBuffer = new Uint8Array(MAX_CAP);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				if (pendingBytes >= currentPacketCap || currentPacketCap - pendingBytes < tailBytes) {
					await flush();
				} else if (!microtaskQueued) {
					microtaskQueued = true;
					queueMicrotask(() => {
						if (pendingBytes) flush().catch(() => closeSocketQuietly(webSocket));
					});
				}
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		while (ws.bufferedAmount > 1024 * 1024) {
			if (ws.readyState !== 1) break;
			await new Promise((r) => setTimeout(r, 20));
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes, aeadCtx = null) {
	let header = headerData,
		hasData = false;
	if (aeadCtx) {
		header = header ? concatBytes(aeadCtx.salt, header) : aeadCtx.salt;
	}
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		let reader = remoteSocket.readable.getReader({ mode: "byob" });
		let useBYOB = true;
		reader.releaseLock();
		if (useBYOB) {
			const transformStream = new TransformStream({
				async transform(chunk, controller) {
					hasData = true;
					if (typeof onBytes === "function") onBytes(chunk.byteLength);
					if (aeadCtx) {
						let offset = 0;
						while (offset < chunk.byteLength) {
							const sliceLen = Math.min(chunk.byteLength - offset, 16383);
							const slice = chunk.subarray(offset, offset + sliceLen);
							const lenBuf = new Uint8Array([(sliceLen >> 8) & 0xff, sliceLen & 0xff]);
							const encLen = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, lenBuf);
							const encPayload = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, slice);
							if (encLen && encPayload) controller.enqueue(concatBytes(encLen, encPayload));
							offset += sliceLen;
						}
					} else {
						controller.enqueue(chunk);
					}
				}
			});
			const writePromise = transformStream.readable.pipeTo(new WritableStream({
				async write(chunk) {
					await downstreamSender.send(chunk);
				}
			}));
			await remoteSocket.readable.pipeTo(transformStream.writable);
			await writePromise;
		}
	} catch (e) {
		let reader = remoteSocket.readable.getReader();
		try {
			while (true) {
				if (webSocket.bufferedAmount > 1024 * 1024) await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				
				if (aeadCtx) {
					let offset = 0;
					while (offset < value.byteLength) {
						const sliceLen = Math.min(value.byteLength - offset, 16383);
						const slice = value.subarray(offset, offset + sliceLen);
						const lenBuf = new Uint8Array([(sliceLen >> 8) & 0xff, sliceLen & 0xff]);
						const encLen = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, lenBuf);
						const encPayload = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, slice);
						if (encLen && encPayload) await downstreamSender.send(concatBytes(encLen, encPayload));
						offset += sliceLen;
					}
				} else {
					await downstreamSender.send(value);
				}
			}
		} finally {
			try { reader.cancel(); } catch (err) {}
			try { reader.releaseLock(); } catch (err) {}
		}
	} finally {
		await downstreamSender.flush();
		closeSocketQuietly(webSocket);
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const socket = connect({ hostname: address, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	if (initialData && initialData.byteLength > 0) {
		const w = socket.writable.getWriter();
		await w.write(convertToUint8Array(initialData));
		w.releaseLock();
	}
	return socket;
}
function sha224Pure(message) {
	function rotateRight(n, x) { return (x >>> n) | (x << (32 - n)); }
	function choice(x, y, z) { return (x & y) ^ (~x & z); }
	function majority(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
	function sigma0(x) { return rotateRight(2, x) ^ rotateRight(13, x) ^ rotateRight(22, x); }
	function sigma1(x) { return rotateRight(6, x) ^ rotateRight(11, x) ^ rotateRight(25, x); }
	function gamma0(x) { return rotateRight(7, x) ^ rotateRight(18, x) ^ (x >>> 3); }
	function gamma1(x) { return rotateRight(17, x) ^ rotateRight(19, x) ^ (x >>> 10); }
	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];
	let H = [
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
		0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	];
	const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
	const bitLen = msgBytes.length * 8;
	const newLen = (((msgBytes.length + 8) >> 6) + 1) << 6;
	const padded = new Uint8Array(newLen);
	padded.set(msgBytes);
	padded[msgBytes.length] = 0x80;
	const view = new DataView(padded.buffer);
	view.setUint32(newLen - 4, bitLen, false);
	const W = new Uint32Array(64);
	for (let i = 0; i < newLen; i += 64) {
		for (let t = 0; t < 16; t++) {
			W[t] = view.getUint32(i + t * 4, false);
		}
		for (let t = 16; t < 64; t++) {
			W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
		}
		let [a, b, c, d, e, f, g, h] = H;
		for (let t = 0; t < 64; t++) {
			const T1 = (h + sigma1(e) + choice(e, f, g) + K[t] + W[t]) >>> 0;
			const T2 = (sigma0(a) + majority(a, b, c)) >>> 0;
			h = g;
			g = f;
			f = e;
			e = (d + T1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (T1 + T2) >>> 0;
		}
		H[0] = (H[0] + a) >>> 0;
		H[1] = (H[1] + b) >>> 0;
		H[2] = (H[2] + c) >>> 0;
		H[3] = (H[3] + d) >>> 0;
		H[4] = (H[4] + e) >>> 0;
		H[5] = (H[5] + f) >>> 0;
		H[6] = (H[6] + g) >>> 0;
		H[7] = (H[7] + h) >>> 0;
	}
	return H.slice(0, 7).map(w => w.toString(16).padStart(8, '0')).join('');
}
async function forwardTrojanUDP(udpChunk, webSocket, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 7) return;
		let offset = 0;
		const addrType = data[offset++];
		let headerAddrBytes = [];
		
		if (addrType === 1) {
			if (data.byteLength < offset + 4) return;
			headerAddrBytes = [addrType, data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
			offset += 4;
		} else if (addrType === 3) {
			if (data.byteLength < offset + 1) return;
			const domainLen = data[offset++];
			if (data.byteLength < offset + domainLen) return;
			headerAddrBytes = [addrType, domainLen, ...data.slice(offset, offset + domainLen)];
			offset += domainLen;
		} else if (addrType === 4) {
			if (data.byteLength < offset + 16) return;
			headerAddrBytes = [addrType, ...data.slice(offset, offset + 16)];
			offset += 16;
		} else {
			return;
		}
		
		if (data.byteLength < offset + 4) return;
		const port = (data[offset++] << 8) | data[offset++];
		const length = (data[offset++] << 8) | data[offset++];
		offset += 2; 
		if (data.byteLength < offset + length) return;
		
		const dnsPayload = data.slice(offset, offset + length);
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpHeader = new Uint8Array(headerAddrBytes.length + 2 + 2 + 2);
		let hOff = 0;
		for (let b of headerAddrBytes) udpHeader[hOff++] = b;
		udpHeader[hOff++] = (port >> 8) & 0xff;
		udpHeader[hOff++] = port & 0xff;
		udpHeader[hOff++] = (resLen >> 8) & 0xff;
		udpHeader[hOff++] = resLen & 0xff;
		udpHeader[hOff++] = 0x0D;
		udpHeader[hOff++] = 0x0A;
		const merged = new Uint8Array(udpHeader.length + resLen);
		merged.set(udpHeader, 0);
		merged.set(rawResponse, udpHeader.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
async function forwardvIeesUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 2) return;
		const length = (data[0] << 8) | data[1];
		if (data.byteLength < 2 + length) return;
		
		const dnsPayload = data.slice(2, 2 + length);
		
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpPacket = new Uint8Array(2 + resLen);
		udpPacket[0] = (resLen >> 8) & 0xff;
		udpPacket[1] = resLen & 0xff;
		udpPacket.set(rawResponse, 2);
		const header = respHeader || new Uint8Array([0, 0]);
		const merged = new Uint8Array(header.length + udpPacket.byteLength);
		merged.set(header, 0);
		merged.set(udpPacket, header.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
function extractUUIDFromvIees(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function trackRequest(env, ctx) {
	GLOBAL_REQ_COUNT++;
	const now = Date.now();
	if ((now - GLOBAL_LAST_REQ_WRITE > 900000 || GLOBAL_REQ_COUNT > 5000) && GLOBAL_REQ_COUNT > 0) {
		GLOBAL_LAST_REQ_WRITE = now;
		const countToSave = GLOBAL_REQ_COUNT;
		GLOBAL_REQ_COUNT = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
			} catch (e) { }
		};
		if (ctx) ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}
	const hasProtocol = /^(socks4|socks5|socks|http|https):\/\//i.test(normalized);
	const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
	const isSocks4 = normalized.toLowerCase().startsWith("socks4://");
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	if (isSocks4) {
		return await connectSocks4(cleanStr, destAddr, destPort, initialData);
	}
	if (hasProtocol) {
		return await connectSocks5(cleanStr, destAddr, destPort, initialData);
	}
	return await Promise.any([
		connectSocks5(cleanStr, destAddr, destPort, initialData),
		connectHttp(cleanStr, destAddr, destPort, initialData)
	]);
}
async function connectSocks4(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 1080);
	const socket = connect({ hostname: host, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		const portHigh = (destPort >> 8) & 0xff;
		const portLow = destPort & 0xff;
		let req;
		if (isIPv4(destAddr)) {
			const ipBytes = destAddr.split(".").map(Number);
			req = new Uint8Array([0x04, 0x01, portHigh, portLow, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00]);
		} else {
			const hostBytes = new TextEncoder().encode(destAddr);
			req = new Uint8Array(9 + hostBytes.length + 1);
			req[0] = 0x04;
			req[1] = 0x01;
			req[2] = portHigh;
			req[3] = portLow;
			req[4] = 0x00;
			req[5] = 0x00;
			req[6] = 0x00;
			req[7] = 0x01;
			req[8] = 0x00;
			req.set(hostBytes, 9);
			req[9 + hostBytes.length] = 0x00;
		}
		await writer.write(req);
		let res = await readWithTimeout(reader, 4000);
		if (res.done || !res.value || res.value[0] !== 0x00 || res.value[1] !== 0x5a) {
			throw new Error("پـروکـسـی SOCKS4 وصل نشد یا اتصال را رد کرد");
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
function parseProxyConfig(proxyStr, defaultPort) {
	let user = "",
		pass = "",
		host = "",
		port = defaultPort;
	let auth = false,
		remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || defaultPort;
		} else {
			host = remain;
		}
	}
	return { user, pass, host, port, auth };
}
async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
	const socket = connect({ hostname: host, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}
		let res = await readWithTimeout(reader, 4000);
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پـروکـسـی SOCKS5 نیست یا خاموش است)");
		const method = res.value[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);
			await writer.write(authReq);
			let authRes = await readWithTimeout(reader, 4000);
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پـروکـسـی اشتباه است");
		}
		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split(".").map(Number));
		} else if (destAddr.includes(":")) {
			addrType = 0x04;
			addrBytes = new Uint8Array(16);
			const blocks = destAddr.split(":");
			for (let i = 0; i < 8; i++) {
				const val = parseInt(blocks[i] || "0", 16);
				addrBytes[i * 2] = (val >> 8) & 0xff;
				addrBytes[i * 2 + 1] = val & 0xff;
			}
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05;
		req[1] = 0x01;
		req[2] = 0x00;
		req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xff;
		req[portOffset + 1] = destPort & 0xff;
		await writer.write(req);
		let connRes = await readWithTimeout(reader, 4000);
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("پـروکـسـی وصل شد اما دسترسی به اینترنت آزاد ندارد");
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
	const socket = connect({ hostname: host, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
		let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";
		await writer.write(new TextEncoder().encode(req));
		let resStr = "";
		const dec = new TextDecoder();
		while (true) {
			const res = await readWithTimeout(reader, 4000);
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += dec.decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
const COMMON_HEAD = `

	<script>
		window.GLOBAL_GFX = "/*{{GFX_SETTING}}*/";
		if (window.GLOBAL_GFX === 'false' || (window.GLOBAL_GFX.startsWith('/*') && localStorage.getItem('gfx-enabled') !== 'true')) {
			document.documentElement.classList.add('gfx-off');
		}
		if (localStorage.getItem('color-theme') === 'light' && window.location.pathname === '/panel') {
			document.documentElement.classList.remove('dark');
		} else {
			document.documentElement.classList.add('dark');
		}
		if (localStorage.getItem('grayscale-theme') === 'true') {
			document.documentElement.classList.add('grayscale-active');
		}
		if (localStorage.getItem('rgb-theme') === 'true') {
			document.documentElement.classList.add('rgb-active');
		}
		/* migrate settings saved under the old zeus_ names (moved once, nothing is lost) */
		try {
			['color_theme','stats_hidden','users_custom_order','login_time','refresh_rate','rate_migrated_to_5s'].forEach(function (k) {
				var o = localStorage.getItem('zeus_' + k);
				if (o !== null) {
					if (localStorage.getItem('caspian_' + k) === null) localStorage.setItem('caspian_' + k, o);
					localStorage.removeItem('zeus_' + k);
				}
			});
		} catch (e) {}
		try {
			var __zt = localStorage.getItem('caspian_color_theme');
			if (['blue','gold','emerald','rose','violet','cyan','orange','slate'].indexOf(__zt) !== -1) {
				document.documentElement.classList.add('theme-' + __zt);
			}
		} catch (e) {}
		/* usage-bar colour: green->red by percent normally, plain theme colour when a colour theme is active */
		window.__usageColor = function (hue) {
			return document.documentElement.className.indexOf('theme-') !== -1 ? 'var(--t600)' : 'hsl(' + hue + ', 80%, 45%)';
		};
		try { localStorage.removeItem('proxy_flag_cache'); } catch(e) {}
	</script>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js"></script>
	<link rel="manifest" href="/manifest.json">
	<link rel="icon" type="image/svg+xml" href="/icon.svg">
	<link rel="apple-touch-icon" href="/icon.svg">
	<meta name="theme-color" content="#000000">
	<meta name="mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
	<meta name="apple-mobile-web-app-title" content="CASPIAN Panel">
	<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css">
<script>
	/* Caspian: all accent hues (red, green, amber, blue, ...) are remapped to CSS variables.
	   With no theme selected the var() fallbacks are the ORIGINAL Tailwind colors, so nothing changes.
	   With a theme selected (html.theme-*) every hue becomes the theme colour, same shade. */
	var CASPIAN_KEEP_HUES = []; /* hues to keep untouched, e.g. ['red','green'] */
	var CASPIAN_PALETTE = {'red':'fef2f2fee2e2fecacafca5a5f87171ef4444dc2626b91c1c991b1b7f1d1d450a0a','orange':'fff7edffedd5fed7aafdba74fb923cf97316ea580cc2410c9a34127c2d12431407','amber':'fffbebfef3c7fde68afcd34dfbbf24f59e0bd97706b4530992400e78350f451a03','yellow':'fefce8fef9c3fef08afde047facc15eab308ca8a04a16207854d0e713f12422006','lime':'f7fee7ecfccbd9f99dbef264a3e63584cc1665a30d4d7c0f3f62123653141a2e05','green':'f0fdf4dcfce7bbf7d086efac4ade8022c55e16a34a15803d16653414532d052e16','emerald':'ecfdf5d1fae5a7f3d06ee7b734d39910b981059669047857065f46064e3b022c22','teal':'f0fdfaccfbf199f6e45eead42dd4bf14b8a60d94880f766e115e59134e4a042f2e','cyan':'ecfeffcffafea5f3fc67e8f922d3ee06b6d40891b20e7490155e75164e63083344','sky':'f0f9ffe0f2febae6fd7dd3fc38bdf80ea5e90284c70369a10759850c4a6e082f49','blue':'eff6ffdbeafebfdbfe93c5fd60a5fa3b82f62563eb1d4ed81e40af1e3a8a172554','indigo':'eef2ffe0e7ffc7d2fea5b4fc818cf86366f14f46e54338ca3730a3312e811e1b4b','violet':'f5f3ffede9feddd6fec4b5fda78bfa8b5cf67c3aed6d28d95b21b64c1d952e1065','purple':'faf5fff3e8ffe9d5ffd8b4fec084fca855f79333ea7e22ce6b21a8581c873b0764','fuchsia':'fdf4fffae8fff5d0fef0abfce879f9d946efc026d3a21caf86198f701a754a044e','pink':'fdf2f8fce7f3fbcfe8f9a8d4f472b6ec4899db2777be185d9d174d831843500724','rose':'fff1f2ffe4e6fecdd3fda4affb7185f43f5ee11d48be123c9f12398813374c0519'};
	var CASPIAN_SHADES = [50,100,200,300,400,500,600,700,800,900,950];
	var CASPIAN_ACCENT = {};
	Object.keys(CASPIAN_PALETTE).forEach(function (hue) {
		if (CASPIAN_KEEP_HUES.indexOf(hue) !== -1) return;
		var shades = {};
		CASPIAN_SHADES.forEach(function (s, i) {
			var h = CASPIAN_PALETTE[hue].substr(i * 6, 6);
			var rgb = parseInt(h.substr(0, 2), 16) + ' ' + parseInt(h.substr(2, 2), 16) + ' ' + parseInt(h.substr(4, 2), 16);
			shades[s] = 'rgb(var(--a' + s + ', ' + rgb + ') / <alpha-value>)';
		});
		CASPIAN_ACCENT[hue] = shades;
	});
	tailwind.config = {
		darkMode: 'class',
		theme: {
			extend: {
				fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
				colors: Object.assign({
					amoled: {
						bg: '#000105',
						card: 'rgb(var(--am-card, 4 9 20) / <alpha-value>)',
						input: 'rgb(var(--am-input, 8 18 36) / <alpha-value>)',
						border: 'rgb(var(--am-border, 16 32 64) / <alpha-value>)'
					},
					pattng: 'rgb(var(--a500, 51 251 31) / <alpha-value>)'
				}, CASPIAN_ACCENT)
			}
		}
	}
</script>
<style>
	.cursor-wrapper {
		pointer-events: none;
		position: fixed;
		top: 0;
		left: 0;
		z-index: 9999;
		display: none;
	}
	@media (pointer: fine) {
		html:not(.gfx-off) * {
			cursor: none !important;
		}
		html:not(.gfx-off) .cursor-wrapper {
			display: block;
		}
	}
	#cursor-dot {
		width: 6px;
		height: 6px;
		background-color: #2563eb;
		border-radius: 50%;
		box-shadow: 0 0 8px #2563eb, 0 0 16px #1d4ed8;
		transform: translate(-50%, -50%);
	}
	#cursor-ring-pos {
		width: 36px;
		height: 36px;
		transform: translate(-50%, -50%);
		transition: width 0.2s cubic-bezier(0.16, 1, 0.3, 1), height 0.2s cubic-bezier(0.16, 1, 0.3, 1);
	}
	#cursor-ring-visual {
		width: 100%;
		height: 100%;
		border: 1.5px dashed rgba(37, 99, 235, 0.9);
		border-radius: 50%;
		animation: spinRing 10s linear infinite;
		transition: border-color 0.2s, background-color 0.2s;
	}
	@keyframes spinRing {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}
	body.hover-active #cursor-ring-pos {
		width: 48px;
		height: 48px;
	}
	body.hover-active #cursor-ring-visual {
		border: 2px solid #2563eb;
		background-color: rgba(37, 99, 235, 0.2);
		animation: spinRingFast 3s linear infinite;
	}
	@keyframes spinRingFast {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}
	#cursor-glow-pos {
		width: 40px;
		height: 40px;
		transform: translate(-50%, -50%);
		transition: width 0.2s cubic-bezier(0.16, 1, 0.3, 1), height 0.2s cubic-bezier(0.16, 1, 0.3, 1);
	}
	body.hover-active #cursor-glow-pos {
		width: 54px;
		height: 54px;
	}
	#cursor-glow-visual {
		width: 100%;
		height: 100%;
		border-radius: 50%;
		background: radial-gradient(circle, rgba(37, 99, 235, 0.4) 0%, rgba(29, 78, 216, 0.1) 40%, transparent 70%);
	}
		:root {
			--bg-tint: rgba(59, 130, 246, 0.03);
			--plane-color: #93c5fd; 
			--plane-dark: #f9fafb;
			--plane-opacity: 0.20;
		}
		.dark {
			--bg-tint: rgba(16, 32, 64, 0.4); 
			--plane-color: #1d4ed8; 
			--plane-dark: #000105;
			--plane-opacity: 0.15;
		}
		.bg-canvas { position: fixed; inset: 0; z-index: 0; pointer-events: none; }
		#waves { position: fixed; inset: 0; width: 100%; height: 100%; display: block; }
		.vignette {
			position: fixed; inset: 0; z-index: 2; pointer-events: none;
			background: radial-gradient(ellipse at center, transparent 35%, rgba(255,255,255,0.5) 100%);
		}
		.dark .vignette {
			background: radial-gradient(ellipse at center, transparent 35%, rgba(0,1,5,0.85) 100%);
		}
		.ambient {
			position: fixed; inset: 0; z-index: 1; pointer-events: none;
			background:
				radial-gradient(700px 500px at 12% 20%, var(--bg-tint), transparent 60%),
				radial-gradient(800px 600px at 90% 90%, var(--bg-tint), transparent 60%);
		}

		/* === Caspian colour themes ===
		   --t*  : hex shades (cursor, background tint, waves)
		   --a*  : rgb triplets that replace EVERY Tailwind accent hue (red, green, blue, ...)
		   --am-*: dark-mode surfaces (card / input / border) tinted with the theme colour
		   Notifications (#toast-container) and the theme picker swatches are reset below and keep their own colours. === */
		html.theme-blue {
			--t50:#eff6ff;--t100:#dbeafe;--t200:#bfdbfe;--t300:#93c5fd;--t400:#60a5fa;--t500:#3b82f6;--t600:#2563eb;--t700:#1d4ed8;--t800:#1e40af;--t900:#1e3a8a;
			--a50:239 246 255;--a100:219 234 254;--a200:191 219 254;--a300:147 197 253;--a400:96 165 250;--a500:59 130 246;--a600:37 99 235;--a700:29 78 216;--a800:30 64 175;--a900:30 58 138;--a950:23 37 84;
			--am-card:4 8 19;--am-input:8 15 36;--am-border:16 32 76;--am-border-hover:24 46 110;
		}
		html.theme-gold {
			--t50:#fffbeb;--t100:#fef3c7;--t200:#fde68a;--t300:#fcd34d;--t400:#fbbf24;--t500:#f59e0b;--t600:#d97706;--t700:#b45309;--t800:#92400e;--t900:#78350f;
			--a50:255 251 235;--a100:254 243 199;--a200:253 230 138;--a300:252 211 77;--a400:251 191 36;--a500:245 158 11;--a600:217 119 6;--a700:180 83 9;--a800:146 64 14;--a900:120 53 15;--a950:69 26 3;
			--am-card:17 7 2;--am-input:31 14 4;--am-border:66 29 8;--am-border-hover:96 42 12;
		}
		html.theme-emerald {
			--t50:#ecfdf5;--t100:#d1fae5;--t200:#a7f3d0;--t300:#6ee7b7;--t400:#34d399;--t500:#10b981;--t600:#059669;--t700:#047857;--t800:#065f46;--t900:#064e3b;
			--a50:236 253 245;--a100:209 250 229;--a200:167 243 208;--a300:110 231 183;--a400:52 211 153;--a500:16 185 129;--a600:5 150 105;--a700:4 120 87;--a800:6 95 70;--a900:6 78 59;--a950:2 44 34;
			--am-card:1 11 8;--am-input:2 20 15;--am-border:3 43 32;--am-border-hover:5 62 47;
		}
		html.theme-rose {
			--t50:#fff1f2;--t100:#ffe4e6;--t200:#fecdd3;--t300:#fda4af;--t400:#fb7185;--t500:#f43f5e;--t600:#e11d48;--t700:#be123c;--t800:#9f1239;--t900:#881337;
			--a50:255 241 242;--a100:255 228 230;--a200:254 205 211;--a300:253 164 175;--a400:251 113 133;--a500:244 63 94;--a600:225 29 72;--a700:190 18 60;--a800:159 18 57;--a900:136 19 55;--a950:76 5 25;
			--am-card:19 3 8;--am-input:35 5 14;--am-border:75 10 30;--am-border-hover:109 15 44;
		}
		html.theme-violet {
			--t50:#f5f3ff;--t100:#ede9fe;--t200:#ddd6fe;--t300:#c4b5fd;--t400:#a78bfa;--t500:#8b5cf6;--t600:#7c3aed;--t700:#6d28d9;--t800:#5b21b6;--t900:#4c1d95;
			--a50:245 243 255;--a100:237 233 254;--a200:221 214 254;--a300:196 181 253;--a400:167 139 250;--a500:139 92 246;--a600:124 58 237;--a700:109 40 217;--a800:91 33 182;--a900:76 29 149;--a950:46 16 101;
			--am-card:11 4 21;--am-input:20 8 39;--am-border:42 16 82;--am-border-hover:61 23 119;
		}
		html.theme-cyan {
			--t50:#ecfeff;--t100:#cffafe;--t200:#a5f3fc;--t300:#67e8f9;--t400:#22d3ee;--t500:#06b6d4;--t600:#0891b2;--t700:#0e7490;--t800:#155e75;--t900:#164e63;
			--a50:236 254 255;--a100:207 250 254;--a200:165 243 252;--a300:103 232 249;--a400:34 211 238;--a500:6 182 212;--a600:8 145 178;--a700:14 116 144;--a800:21 94 117;--a900:22 78 99;--a950:8 51 68;
			--am-card:3 11 14;--am-input:6 20 26;--am-border:12 43 54;--am-border-hover:18 62 79;
		}
		html.theme-orange {
			--t50:#fff7ed;--t100:#ffedd5;--t200:#fed7aa;--t300:#fdba74;--t400:#fb923c;--t500:#f97316;--t600:#ea580c;--t700:#c2410c;--t800:#9a3412;--t900:#7c2d12;
			--a50:255 247 237;--a100:255 237 213;--a200:254 215 170;--a300:253 186 116;--a400:251 146 60;--a500:249 115 22;--a600:234 88 12;--a700:194 65 12;--a800:154 52 18;--a900:124 45 18;--a950:67 20 7;
			--am-card:17 6 3;--am-input:32 12 5;--am-border:68 25 10;--am-border-hover:99 36 14;
		}
		html.theme-slate {
			--t50:#f8fafc;--t100:#f1f5f9;--t200:#e2e8f0;--t300:#cbd5e1;--t400:#94a3b8;--t500:#64748b;--t600:#475569;--t700:#334155;--t800:#1e293b;--t900:#0f172a;
			--a50:248 250 252;--a100:241 245 249;--a200:226 232 240;--a300:203 213 225;--a400:148 163 184;--a500:100 116 139;--a600:71 85 105;--a700:51 65 85;--a800:30 41 59;--a900:15 23 42;--a950:2 6 23;
			--am-card:2 3 6;--am-input:4 6 11;--am-border:8 13 23;--am-border-hover:12 18 34;
		}


		/* progress bars & accent fills often inline hsl or blue */
		html[class*="theme-"] #cursor-dot { background-color: var(--t600) !important; box-shadow: 0 0 8px var(--t600), 0 0 16px var(--t700) !important; }
		html[class*="theme-"] #cursor-ring-visual { border-color: color-mix(in srgb, var(--t600) 90%, transparent) !important; }
		html[class*="theme-"] body.hover-active #cursor-ring-visual { border-color: var(--t600) !important; background-color: color-mix(in srgb, var(--t600) 20%, transparent) !important; }
		html[class*="theme-"] #cursor-glow-visual { background: radial-gradient(circle, color-mix(in srgb, var(--t600) 40%, transparent) 0%, color-mix(in srgb, var(--t700) 10%, transparent) 40%, transparent 70%) !important; }
		html[class*="theme-"] { --bg-tint: color-mix(in srgb, var(--t500) 8%, transparent); --plane-color: var(--t300); }
		html.dark[class*="theme-"] { --bg-tint: color-mix(in srgb, var(--t800) 35%, transparent); --plane-color: var(--t700); }

		/* Notifications + theme-picker swatches keep their ORIGINAL colours:
		   "initial" makes every var(--aN, fallback) inside them fall back to the stock Tailwind colour. */
		#toast-container, .theme-choice {
			--a50:initial;--a100:initial;--a200:initial;--a300:initial;--a400:initial;--a500:initial;--a600:initial;--a700:initial;--a800:initial;--a900:initial;--a950:initial;
			--am-card:initial;--am-input:initial;--am-border:initial;
		}

		/* dark scrollbars follow the theme (fallbacks = old navy colours) */
		.dark ::-webkit-scrollbar-thumb { background: rgb(var(--am-border, 16 32 64)) !important; }
		.dark ::-webkit-scrollbar-thumb:hover { background: rgb(var(--am-border-hover, 23 46 92)) !important; }
		html.dark, html.dark body, .dark .custom-scrollbar { scrollbar-color: rgb(var(--am-border, 16 32 64)) #000105 !important; }

</style>
<script>
	document.addEventListener('DOMContentLoaded', () => {
		if (window.matchMedia('(pointer: fine)').matches && localStorage.getItem('gfx-enabled') !== 'false') {
			const glowPos = document.createElement('div');
			glowPos.id = 'cursor-glow-pos';
			glowPos.className = 'cursor-wrapper';
			glowPos.innerHTML = '<div id="cursor-glow-visual"></div>';
			document.body.appendChild(glowPos);
			const ringPos = document.createElement('div');
			ringPos.id = 'cursor-ring-pos';
			ringPos.className = 'cursor-wrapper';
			ringPos.innerHTML = '<div id="cursor-ring-visual"></div>';
			document.body.appendChild(ringPos);
			const dot = document.createElement('div');
			dot.id = 'cursor-dot';
			dot.className = 'cursor-wrapper';
			document.body.appendChild(dot);
			let mouseX = window.innerWidth / 2;
			let mouseY = window.innerHeight / 2;
			let ringX = mouseX, ringY = mouseY;
			let glowX = mouseX, glowY = mouseY;
			let isMoving = false;
			window.addEventListener('mousemove', (e) => {
				mouseX = e.clientX;
				mouseY = e.clientY;
				dot.style.transform = 'translate3d(' + mouseX + 'px, ' + mouseY + 'px, 0) translate(-50%, -50%)';
				if (!isMoving) {
					isMoving = true;
					requestAnimationFrame(animatePhysics);
				}
			}, { passive: true });
			function animatePhysics() {
				ringX += (mouseX - ringX) * 0.45;
				ringY += (mouseY - ringY) * 0.45;
				ringPos.style.transform = 'translate3d(' + ringX + 'px, ' + ringY + 'px, 0) translate(-50%, -50%)';
				glowX += (mouseX - glowX) * 0.25;
				glowY += (mouseY - glowY) * 0.25;
				glowPos.style.transform = 'translate3d(' + glowX + 'px, ' + glowY + 'px, 0) translate(-50%, -50%)';
				if (Math.abs(mouseX - ringX) < 0.5 && Math.abs(mouseY - ringY) < 0.5) {
					isMoving = false;
				} else {
					requestAnimationFrame(animatePhysics);
				}
			}
			document.addEventListener('mouseover', (e) => {
				if (e.target.closest('a, button, input, select, label, [role="button"], textarea')) {
					document.body.classList.add('hover-active');
				}
			});
			document.addEventListener('mouseout', (e) => {
				if (e.target.closest('a, button, input, select, label, [role="button"], textarea')) {
					document.body.classList.remove('hover-active');
				}
			});
		}
	});
</script>`;
const COMMON_TOAST_HTML = `<div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>`;
const COMMON_WAVES_SCRIPT = `
	<canvas id="waves" class="bg-canvas"></canvas>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
	<script>
	  (function initWaves(){
		const canvas = document.getElementById('waves');
		if (!canvas) return;
		if (window.GLOBAL_GFX === 'false' || (window.GLOBAL_GFX.startsWith('/*') && localStorage.getItem('gfx-enabled') !== 'true')) {
			canvas.style.display = 'none';
			return;
		}
		const IS_MOBILE = window.innerWidth < 768;
		const renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: false, alpha: false, powerPreference: "default" });
		renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1));
		renderer.setSize(window.innerWidth, window.innerHeight);
		
		const isDarkInit = document.documentElement.classList.contains('dark');
		renderer.setClearColor(isDarkInit ? 0x000105 : 0xf9fafb, 1);
		const scene = new THREE.Scene();
		const camera = new THREE.PerspectiveCamera(60, window.innerWidth/window.innerHeight, 0.1, 200);
		camera.position.set(0, 0, IS_MOBILE ? 35 : 14);
		const segX = IS_MOBILE ? 80 : 80;
		const segY = IS_MOBILE ? 40 : 40;
		const geom = new THREE.PlaneGeometry(80, IS_MOBILE ? 90 : 40, segX, segY);
		const vertShader = "uniform float uTime; uniform float uStrength; varying float vElev; void main(){ vec3 p = position; float x = p.x * 0.2 + uTime * 0.3; float y = p.y * 0.2 + uTime * 0.25; float wave = sin(x)*cos(y)*1.6 + sin(x*2.1 + uTime)*0.7 + cos(y*1.7 - uTime*0.6)*0.7; wave *= uStrength * 1.5; p.z += wave; vElev = wave; gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0); }";
		const fragShader = "varying float vElev; uniform vec3 uHigh; uniform vec3 uLow; uniform float uFade; void main(){ float t = clamp((vElev + 2.0) / 4.0, 0.0, 1.0); vec3 col = mix(uLow, uHigh, t); gl_FragColor = vec4(col, uFade); }";
		function makePlane(px, py, pz, rx, ry, rz, high, low, fade){
		  const mat = new THREE.ShaderMaterial({
			wireframe: true, 
			transparent: true, 
			depthWrite: false,
			uniforms:{
			  uTime:{value:0}, 
			  uStrength:{value:1.1},
			  uHigh:{value:new THREE.Color(high)}, 
			  uLow:{value:new THREE.Color(low)},
			  uFade:{value:fade}
			},
			vertexShader: vertShader, 
			fragmentShader: fragShader
		  });
		  const m = new THREE.Mesh(geom, mat);
		  m.position.set(px, py, pz);
		  m.rotation.set(rx, ry, rz);
		  return m;
		}
		const cs = getComputedStyle(document.documentElement);
		const yOffset = IS_MOBILE ? 14 : 8;
		
		const topPlane = makePlane(0, yOffset, -5, -Math.PI/2.4, 0, 0, '#1e40af', '#040914', 0.35);
		const midPlane = makePlane(
		  0, 0, -25, 0, 0, 0, 
		  cs.getPropertyValue('--plane-color').trim() || '#1d4ed8', 
		  cs.getPropertyValue('--plane-dark').trim() || '#000105', 
		  (parseFloat(cs.getPropertyValue('--plane-opacity')) || 0.35) * 0.7
		);
		const botPlane = makePlane(
		  0, -yOffset, -5, Math.PI/2.4, 0, 0, 
		  cs.getPropertyValue('--plane-color').trim() || '#1d4ed8', 
		  cs.getPropertyValue('--plane-dark').trim() || '#000105', 
		  parseFloat(cs.getPropertyValue('--plane-opacity')) || 0.35
		);
		scene.add(topPlane);
		scene.add(midPlane);
		scene.add(botPlane);
		
		window.__dxTopPlane = topPlane;
		window.__dxMidPlane = midPlane;
		window.__dxBotPlane = botPlane;
		const clock = new THREE.Clock();
		let lastFrameTime = 0;
		function animate(timestamp) {
		  requestAnimationFrame(animate);
		  if (timestamp - lastFrameTime < 30) return;
		  lastFrameTime = timestamp;
		  
		  const t = clock.getElapsedTime();
		  topPlane.material.uniforms.uTime.value = t * 0.8; 
		  midPlane.material.uniforms.uTime.value = t * 0.6;
		  botPlane.material.uniforms.uTime.value = t * 0.8; 
		  renderer.render(scene, camera);
		}
		requestAnimationFrame(animate);
		window.addEventListener('resize', function(){
		  camera.aspect = window.innerWidth/window.innerHeight;
		  camera.updateProjectionMatrix();
		  renderer.setSize(window.innerWidth, window.innerHeight);
		});
		function retintScene(){
		  const isDark = document.documentElement.classList.contains('dark');
		  if (renderer) renderer.setClearColor(isDark ? 0x000105 : 0xf9fafb, 1);
		  const tv = function (n, fb) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim() || fb; };
		  const pColor = isDark ? tv('--t700', '#1d4ed8') : tv('--t300', '#93c5fd');
		  const pDark = isDark ? '#000105' : '#f9fafb';
		  const pOpacity = isDark ? 0.15 : 0.20;
		  if (botPlane) {
			botPlane.material.uniforms.uHigh.value.set(pColor);
			botPlane.material.uniforms.uLow.value.set(pDark);
			botPlane.material.uniforms.uFade.value = pOpacity;
		  }
		  if (midPlane) {
			midPlane.material.uniforms.uHigh.value.set(pColor);
			midPlane.material.uniforms.uLow.value.set(pDark);
			midPlane.material.uniforms.uFade.value = pOpacity * 0.7;
		  }
		  if (topPlane) {
			 if (!isDark) {
				topPlane.material.uniforms.uLow.value.set('#f9fafb');
				topPlane.material.uniforms.uHigh.value.set(tv('--t200', '#bfdbfe'));
			 } else {
				topPlane.material.uniforms.uLow.value.set('#040914');
				topPlane.material.uniforms.uHigh.value.set(tv('--t800', '#1e40af'));
			 }
		  }
		}
		
		const observer = new MutationObserver(function(mutations) {
			mutations.forEach(function(mutation) {
				if (mutation.attributeName === 'class') {
					retintScene();
				}
			});
		});
		observer.observe(document.documentElement, { attributes: true });
		retintScene();
	  })();
	</script>
`;
const COMMON_TOAST_JS = `
		function showToast(message, type = 'success') {
			const container = document.getElementById('toast-container');
			const toast = document.createElement('div');
			const colors = type === 'error' 
				? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
				: 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
			toast.className = 'px-4 py-3 border rounded-md shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
			toast.innerText = message;
			container.appendChild(toast);
			requestAnimationFrame(() => {
				toast.classList.remove('-translate-y-full', 'opacity-0');
			});
			setTimeout(() => {
				toast.classList.add('-translate-y-full', 'opacity-0');
				setTimeout(() => toast.remove(), 300);
			}, 3000);
		}
		window.alert = function(message) {
			let msgStr = message ? message.toString() : '';
			if (msgStr.toLowerCase().includes('d1') && (msgStr.toLowerCase().includes('limit') || msgStr.toLowerCase().includes('exceeded') || msgStr.toLowerCase().includes('daily row'))) {
				msgStr = '❌ سهمیه دیتابیس (D1) شما تمام شده و ساعت 3:30 درست میشه';
				if (typeof setNotifD1Warn === 'function') setNotifD1Warn(true);
			}
			if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
				showToast(msgStr, 'error');
			} else {
				showToast(msgStr, 'success');
			}
		};
`;
const HTML_TEMPLATES = {
	nginx: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval' blob:; style-src * 'unsafe-inline'; connect-src *;">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>دسترسی به پـنـل</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center justify-center p-4 gap-6">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl p-8 text-center flex flex-col items-center gap-4 relative z-10">
		<div class="p-4 bg-blue-50 dark:bg-blue-900/20 text-blue-500 rounded-full mb-2">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
		</div>
		<h2 class="text-xl font-bold text-gray-900 dark:text-white">ورود به پــنــل مالکیت</h2>
		<p class="text-sm text-gray-600 dark:text-gray-400 leading-relaxed mt-2">
			برای ورود به پـنـل، لطفاً عبارت 
			<span class="inline-block px-2 py-1 bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-zinc-800 rounded-md font-mono text-blue-500 font-bold mx-1 shadow-sm" dir="ltr">/panel</span> 
			را به انتهای آدرس مرورگر خود اضافه کنید یا روی دکمه زیر کلیک کنید.
		</p>
		<button onclick="window.location.href='/panel'" class="mt-4 w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition-colors duration-200 shadow-lg font-bold">
			ورود به پـنـل
		</button>
	</div>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	setup: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>تعریف رمز عبور پـنـل</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center justify-center p-4 gap-6">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl p-6 relative z-10">
		<h2 class="text-xl font-bold mb-2 text-center text-blue-600 dark:text-blue-400">تنظیم رمز عبور جدید</h2>
		<p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-6">این اولین ورود شما به پـنـل مالکیت است. لطفاً رمز عبور خود را تعیین کنید.</p>
		<form onsubmit="handleSetup(event)" class="space-y-4">
			<div>
				<label class="block text-sm font-medium mb-1.5">رمز عبور</label>
				<input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
			</div>
			<div>
				<label class="block text-sm font-medium mb-1.5">تکرار رمز عبور</label>
				<input type="password" id="confirm-password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
			</div>
			<button type="submit" id="submit-btn" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition font-bold">ثبت و ورود</button>
		</form>
	</div>
	${COMMON_TOAST_HTML}
	<script>
		${COMMON_TOAST_JS};
		async function handleSetup(event) {
			event.preventDefault();
			const password = document.getElementById('password').value.trim();
			const confirmPassword = document.getElementById('confirm-password').value.trim();
			const btn = document.getElementById('submit-btn');
			if (password !== confirmPassword) {
				alert('⚠️ رمز عبور و تکرار آن مطابقت ندارند!');
				return;
			}
			btn.disabled = true;
			btn.innerText = 'در حال ثبت...';
			try {
				const res = await fetch('/api/setup-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					alert('✅ رمز عبور با موفقیت تنظیم شد. در حال ورود...');
					setTimeout(() => {
						window.location.reload();
					}, 1500);
				} else {
					alert('خطا: ' + (data.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'ثبت و ورود';
			}
		}
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	login: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>ورود به پــنــل مالکیت</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center justify-center p-4 gap-6">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl p-6 relative z-10">
		<div id="login-section">
			<h2 class="text-xl font-bold mb-6 text-center text-blue-600 dark:text-blue-400">ورود به پـنـل مالکیت</h2>
			<form onsubmit="handleLogin(event)" class="space-y-4">
				<div>
					<label class="block text-sm font-medium mb-1.5">رمز عبور</label>
					<input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required>
				</div>
				<button type="submit" id="submit-btn" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition font-bold">ورود</button>
			</form>
			<div class="mt-4 text-center">
				<button onclick="toggleRecovery(true)" class="text-xs text-blue-500 hover:text-blue-600 transition font-medium">بازیابی رمز پـنـل</button>
			</div>
		</div>
		<div id="recovery-section" class="hidden">
			<h2 class="text-xl font-bold mb-4 text-center text-orange-600 dark:text-orange-400">بازیابی رمز پـنـل</h2>
			<div class="mb-5 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800/50 rounded-md text-xs leading-relaxed text-orange-800 dark:text-orange-300">
				برای احراز هویت و اثبات مالکیت پـنـل، از طریق دکمه زیر وارد کلودفلر شوید و توکن دریافتی را کپی کرده و در کادر زیر وارد کنید.
				<a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Caspian-Deployer-Token" target="_blank" class="mt-3 w-full flex items-center justify-center gap-2 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 rounded-md font-bold transition shadow-md">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
					دریافت توکن
				</a>
			</div>
			<form onsubmit="handleRecovery(event)" class="space-y-4">
				<div>
					<input type="password" id="api-token" placeholder="توکن را وارد کنید" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 text-xs text-center font-mono" required>
				</div>
				<div class="flex gap-2 pt-2">
					<button type="button" onclick="toggleRecovery(false)" class="w-1/3 py-2.5 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-sm transition shadow-sm">انصراف</button>
					<button type="submit" id="recover-btn" class="w-2/3 py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition font-bold">بازیابی رمز پـنـل</button>
				</div>
			</form>
		</div>
	</div>
	${COMMON_TOAST_HTML}
	<script>
		${COMMON_TOAST_JS}
		async function handleLogin(event) {
			event.preventDefault();
			const password = document.getElementById('password').value.trim();
			const btn = document.getElementById('submit-btn');
			btn.disabled = true;
			try {
				const res = await fetch('/api/login', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					window.location.reload();
				} else {
					alert(data.error || '❌ رمز عبور اشتباه است');
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
			}
		}
		function toggleRecovery(show) {
			document.getElementById('login-section').classList.toggle('hidden', show);
			document.getElementById('recovery-section').classList.toggle('hidden', !show);
		}
		async function handleRecovery(event) {
			event.preventDefault();
			const apiToken = document.getElementById('api-token').value;
			const btn = document.getElementById('recover-btn');
			btn.disabled = true;
			btn.innerText = 'در حال بررسی...';
			try {
				const res = await fetch('/api/recover', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ api_token: apiToken })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					alert('✅ رمز عبور با موفقیت حذف شد. در حال انتقال به صفحه تنظیمات اولیه...');
					setTimeout(() => {
						window.location.reload();
					}, 1500);
				} else {
					alert('❌ ' + (data.error || 'خطا در تایید اطلاعات'));
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'بازیابی رمز پـنـل';
			}
		}
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	panel: `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>CASPIAN</title>
	<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
	<script>
			const originalWarn = console.warn;
		console.warn = (...args) => {
			if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
			originalWarn(...args);
		};
	</script>
	${COMMON_HEAD}
	<style>
		body { font-family: 'Vazirmatn', sans-serif; }
		.caspian-flag {
			display: inline-block;
			width: 1.35em;
			height: 1em;
			vertical-align: -0.15em;
			border-radius: 2px;
			background-size: cover;
			background-position: 50%;
			background-repeat: no-repeat;
		}
		.caspian-flag-globe {
			font-size: 1.1em;
			line-height: 1;
			vertical-align: -0.05em;
		}
		html.grayscale-active {
			filter: grayscale(100%);
		}
		/* === RGB / Rainbow mode: accents + soft border wave === */
		html.rgb-active {
			--rgb-hue: 0;
		}
		html.rgb-active body {
			animation: rgb-border-wave 6s linear infinite;
		}
		@keyframes rgb-border-wave {
			0%   { box-shadow: inset 0 0 0 2px hsl(0, 90%, 55%), 0 0 24px hsl(0, 90%, 45%, 0.25); }
			16%  { box-shadow: inset 0 0 0 2px hsl(60, 90%, 55%), 0 0 24px hsl(60, 90%, 45%, 0.25); }
			33%  { box-shadow: inset 0 0 0 2px hsl(120, 90%, 50%), 0 0 24px hsl(120, 90%, 40%, 0.25); }
			50%  { box-shadow: inset 0 0 0 2px hsl(180, 90%, 50%), 0 0 24px hsl(180, 90%, 40%, 0.25); }
			66%  { box-shadow: inset 0 0 0 2px hsl(240, 90%, 60%), 0 0 24px hsl(240, 90%, 50%, 0.25); }
			83%  { box-shadow: inset 0 0 0 2px hsl(300, 90%, 55%), 0 0 24px hsl(300, 90%, 45%, 0.25); }
			100% { box-shadow: inset 0 0 0 2px hsl(360, 90%, 55%), 0 0 24px hsl(360, 90%, 45%, 0.25); }
		}
		html.rgb-active #rgb-toggle {
			background: linear-gradient(135deg, #ef4444, #eab308, #22c55e, #06b6d4, #3b82f6, #a855f7, #ef4444);
			background-size: 300% 300%;
			animation: rgb-btn-shift 3s linear infinite;
			color: #fff !important;
			border-color: transparent !important;
		}
		@keyframes rgb-btn-shift {
			0% { background-position: 0% 50%; }
			100% { background-position: 100% 50%; }
		}
		input[type="checkbox"] {
			accent-color: rgb(var(--a600, 22 163 74));
		}
		.dark input[type="checkbox"] {
			filter: none;
		}
		::-webkit-scrollbar {
			width: 6px;
			height: 6px;
		}
		::-webkit-scrollbar-track {
			background: #f3f4f6; 
			border-radius: 4px;
		}
		::-webkit-scrollbar-thumb {
			background: #d1d5db; 
			border-radius: 4px;
		}
		::-webkit-scrollbar-thumb:hover {
			background: #9ca3af;
		}
		html.dark::-webkit-scrollbar-track,
		.dark *::-webkit-scrollbar-track {
			background: #000105 !important;
		}
		html.dark::-webkit-scrollbar-thumb,
		.dark *::-webkit-scrollbar-thumb {
			background: #102040 !important;
		}
		html.dark::-webkit-scrollbar-thumb:hover,
		.dark *::-webkit-scrollbar-thumb:hover {
			background: #172e5c !important;
		}
		html, body, .custom-scrollbar {
			scrollbar-width: thin;
			scrollbar-color: #d1d5db #f3f4f6;
		}
		
		html.dark, html.dark body, .dark .custom-scrollbar {
			scrollbar-color: #102040 #000105 !important;
		}
		@media (min-width: 769px) {
			header, main { zoom: 1.25; }
		}
		@media (max-width: 768px) {
			header, main { zoom: 0.90; }
		}
		input[type="number"]::-webkit-outer-spin-button,
		input[type="number"]::-webkit-inner-spin-button {
			-webkit-appearance: none;
			margin: 0;
		}
		input[type="number"] {
			-moz-appearance: textfield;
		}
		:root {
			--bg-tint: rgba(59, 130, 246, 0.03);
			--plane-color: #93c5fd; 
			--plane-dark: #f9fafb;
			--plane-opacity: 0.20;
		}
		.dark {
			--bg-tint: rgba(16, 32, 64, 0.4); 
			--plane-color: #1d4ed8; 
			--plane-dark: #000105;
			--plane-opacity: 0.15;
		}
		.bg-canvas { position: fixed; inset: 0; z-index: 0; pointer-events: none; will-change: transform; transform: translateZ(0); }
		#waves { position: fixed; inset: 0; width: 100%; height: 100%; display: block; }
		.vignette {
			position: fixed; inset: 0; z-index: 2; pointer-events: none;
			background: radial-gradient(ellipse at center, transparent 35%, rgba(255,255,255,0.5) 100%);
		}
		.dark .vignette {
			background: radial-gradient(ellipse at center, transparent 35%, rgba(0,1,5,0.85) 100%);
		}
		.ambient {
			position: fixed; inset: 0; z-index: 1; pointer-events: none;
			background:
				radial-gradient(700px 500px at 12% 20%, var(--bg-tint), transparent 60%),
				radial-gradient(800px 600px at 90% 90%, var(--bg-tint), transparent 60%);
		}
		@keyframes violentShake {
			0%, 100% { transform: translateX(0); }
			10%, 30%, 50%, 70%, 90% { transform: translateX(-4px) rotate(-3deg); }
			20%, 40%, 60%, 80% { transform: translateX(4px) rotate(3deg); }
		}
		.animate-violent-shake {
			animation: violentShake 0.4s cubic-bezier(.36,.07,.19,.97) infinite;
		}
		@keyframes symBounce {
			0%, 100% { transform: translateY(-2px); }
			50% { transform: translateY(2px); }
		}
		.animate-sym-bounce {
			animation: symBounce 2s ease-in-out infinite;
		}
	</style>
</head>
<body class="bg-gray-100 dark:bg-amoled-bg text-gray-900 dark:text-zinc-100 min-h-screen transition-colors duration-200">
	<canvas id="waves" class="bg-canvas"></canvas>
	<header class="border-b border-gray-200 dark:border-amoled-border bg-gray-50/95 dark:bg-amoled-card/95 px-4 py-4 relative z-10">
<div class="w-full flex flex-col md:flex-row justify-between items-center gap-4">			<div class="flex flex-row flex-wrap justify-center items-center gap-3 w-full md:w-auto">
				<h1 class="text-lg font-bold flex items-center gap-2" dir="ltr">
					⚡️ CASPIAN
					<span id="panel-version" class="text-xs px-2 py-0.5 font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 rounded-full"></span>
				</h1>
				<div class="flex items-center gap-3 bg-gray-100 dark:bg-zinc-800/60 px-3 py-1.5 rounded-full border border-gray-200 dark:border-zinc-800/80 shadow-sm flex-shrink-0 w-fit">
					<a href="https://github.com/sepehr-gamer/Caspian-pannel" target="_blank" rel="noopener noreferrer" class="text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 transition-all transform hover:scale-125 duration-200 flex-shrink-0" title="GitHub">
						<svg class="w-[22px] h-[22px] flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
							<path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
						</svg>
					</a>
					<a href="https://t.me/PV_Golestaneh" target="_blank" rel="noopener noreferrer" class="text-sky-500 hover:text-sky-600 dark:hover:text-sky-400 transition-all transform hover:scale-125 duration-200 flex-shrink-0" title="Telegram">
						<svg class="w-[22px] h-[22px] flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
							<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/>
						</svg>
					</a>
					<button type="button" onclick="navigator.clipboard.writeText(window.location.origin + '/panel').then(() => showToast('✅ آدرس پنل با موفقیت کپی شد!'))" class="text-indigo-500 hover:text-indigo-600 dark:text-indigo-400 dark:hover:text-indigo-300 transition-all transform hover:scale-125 duration-200 flex-shrink-0 cursor-pointer" title="کپی آدرس پنل">
						<svg class="w-[22px] h-[22px] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
							<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
						</svg>
					</button>
				</div>
			</div>
			<div class="flex flex-wrap items-center justify-center gap-3 w-full max-w-[260px] mx-auto md:max-w-none md:mx-0 md:w-auto mt-3 md:mt-0">
				<button id="owner-chat-btn" type="button" onclick="if(typeof toggleOwnerChatModal==='function'){toggleOwnerChatModal(true);}else{alert('اسکریپت پنل کامل لود نشده است');}"
    class="relative w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-blue-50 dark:bg-blue-950/30
           border border-blue-200 dark:border-blue-900
           hover:bg-blue-100 dark:hover:bg-blue-900/50
           transition-all duration-200
           text-blue-600 dark:text-blue-400 shadow-sm"
    title="پیام‌های کاربران">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path>
    </svg>
    <span id="owner-chat-badge" class="hidden absolute -top-1 -left-1 min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-black flex items-center justify-center shadow-md">0</span>
</button>
				<button id="notif-bell" type="button" onclick="toggleNotifCenter(true)"
				    class="relative w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-rose-50 dark:bg-rose-950/30
				           border border-rose-200 dark:border-rose-900
				           hover:bg-rose-100 dark:hover:bg-rose-900/50
				           transition-all duration-200
				           text-rose-600 dark:text-rose-400 shadow-sm"
				    title="مرکز اعلان‌ها">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V4a2 2 0 10-4 0v1.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path>
				    </svg>
				    <span id="notif-count" class="hidden absolute -top-1 -left-1 min-w-[18px] h-[18px] px-1 rounded-full bg-gradient-to-br from-red-500 to-pink-600 text-white text-[10px] font-black flex items-center justify-center animate-pulse shadow-[0_0_12px_rgba(239,68,68,0.7)]">0</span>
				</button>

				<button id="speedtest-btn" onclick="runSpeedTest()"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-yellow-50 dark:bg-yellow-950/30
				           border border-yellow-200 dark:border-yellow-900
				           hover:bg-yellow-100 dark:hover:bg-yellow-900/50
				           transition-all duration-200
				           text-yellow-600 dark:text-yellow-400 shadow-sm"
				    title="تست سرعت / پینگ زنده">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
				    </svg>
				</button>
				<button id="help-guide-btn" onclick="toggleHelpGuideModal(true)"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-indigo-50 dark:bg-indigo-950/30
				           border border-indigo-200 dark:border-indigo-900
				           hover:bg-indigo-100 dark:hover:bg-indigo-900/50
				           transition-all duration-200
				           text-indigo-600 dark:text-indigo-400 shadow-sm"
				    title="راهنما و آموزش اتصال">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
				    </svg>
				</button>
				<button id="owner-note-btn" onclick="toggleOwnerNoteModal(true)"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-lime-50 dark:bg-lime-950/30
				           border border-lime-200 dark:border-lime-900
				           hover:bg-lime-100 dark:hover:bg-lime-900/50
				           transition-all duration-200
				           text-lime-600 dark:text-lime-400 shadow-sm"
				    title="یادداشت شخصی مالک">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
				    </svg>
				</button>
				<button id="fullscreen-btn" onclick="toggleFullscreenMode()"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-slate-100 dark:bg-slate-800/60
				           border border-slate-300 dark:border-slate-700
				           hover:bg-slate-200 dark:hover:bg-slate-700/80
				           transition-all duration-200
				           text-slate-600 dark:text-slate-400 shadow-sm"
				    title="حالت تمام‌صفحه">
				    <svg id="fullscreen-icon-expand" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"></path>
				    </svg>
				</button>
				<button id="donation-notif-btn" type="button" onclick="toggleDonationModal(true)"
    class="relative w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-amber-50 dark:bg-amber-950/30
           border border-amber-200 dark:border-amber-900
           hover:bg-amber-100 dark:hover:bg-amber-900/50
           transition-all duration-200
           text-amber-600 dark:text-amber-400 shadow-sm"
    title="اهدای کانفیگ کاربران">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="8" width="18" height="4" rx="1"/>
        <path d="M5 12v8a1 1 0 001 1h12a1 1 0 001-1v-8"/>
        <path d="M12 8v13"/>
        <path d="M12 8s-1-4-3.5-4a2 2 0 000 4H12z"/>
        <path d="M12 8s1-4 3.5-4a2 2 0 010 4H12z"/>
    </svg>
    <span id="donation-notif-badge" class="hidden absolute -top-1 -left-1 min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-black flex items-center justify-center shadow-md">0</span>
</button>
				<button id="traffic-chart-btn" onclick="openTrafficChartModal()"
    class="w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-emerald-50 dark:bg-emerald-950/30
           border border-emerald-200 dark:border-emerald-900
           hover:bg-emerald-100 dark:hover:bg-emerald-900/50
           transition-all duration-200
           text-emerald-600 dark:text-emerald-400 shadow-sm"
    title="نمودار مصرف روزانه">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
    </svg>
</button>
				<button id="pwa-install-btn" onclick="triggerPwaInstall()"
    class="w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-purple-50 dark:bg-purple-950/30
           border border-purple-200 dark:border-purple-900
           hover:bg-purple-100 dark:hover:bg-purple-900/50
           transition-all duration-200
           text-purple-600 dark:text-purple-400 shadow-sm"
    title="دانلود و نصب اپلیکیشن پنل">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path>
    </svg>
</button>
			<button id="manager-pass-btn" onclick="toggleManagerPassModal(true)"
    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-amber-100 dark:bg-amber-950/40
           border border-amber-600/50 dark:border-amber-700
           hover:bg-amber-200 dark:hover:bg-amber-900/50
           transition-all duration-200
           text-amber-800 dark:text-amber-500 shadow-sm"
    title="رمز مالکیت">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
    </svg>
</button>
			<button onclick="togglePanelPeopleModal(true)"
    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-sky-50 dark:bg-sky-950/30
           border border-sky-200 dark:border-sky-900
           hover:bg-sky-100 dark:hover:bg-sky-900/50
           transition-all duration-200
           text-sky-600 dark:text-sky-400 shadow-sm"
    title="افراد داخل پنل">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"></path>
    </svg>
</button>
			<button onclick="toggleAccessLogbookModal(true)"
    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-emerald-50 dark:bg-emerald-950/30
           border border-emerald-200 dark:border-emerald-900
           hover:bg-emerald-100 dark:hover:bg-emerald-900/50
           transition-all duration-200
           text-emerald-600 dark:text-emerald-400 shadow-sm"
    title="دفترچه ورودها (۲۴ ساعت)">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path>
    </svg>
</button>
			<button onclick="toggleFailedLoginsModal(true)"
    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-red-50 dark:bg-red-950/30
           border border-red-200 dark:border-red-900
           hover:bg-red-100 dark:hover:bg-red-900/50
           transition-all duration-200
           text-red-600 dark:text-red-400 shadow-sm"
    title="ورودهای ناموفق (IP و سیستم‌عامل)">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"></path>
    </svg>
</button>
			<button onclick="toggleSupportModal(true)"
    class="w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-rose-50 dark:bg-rose-950/30
           border border-rose-200 dark:border-rose-900
           hover:bg-rose-100 dark:hover:bg-rose-900/50
           transition-all duration-200
           text-rose-600 dark:text-rose-400 shadow-sm"
    title="حمایت از پروژه">
    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
        <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3 9.24 3 10.91 3.81 12 5.08 13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
    </svg>
</button>
			<button onclick="toggleLoginInfoModal(true)"
    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-teal-50 dark:bg-teal-950/30
           border border-teal-200 dark:border-teal-900
           hover:bg-teal-100 dark:hover:bg-teal-900/50
           transition-all duration-200
           text-teal-600 dark:text-teal-400 shadow-sm"
    title="اطلاعات ورود من">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
        <circle cx="18" cy="6" r="3" fill="currentColor" opacity="0.5"></circle>
    </svg>
</button>
<button onclick="openFactoryResetModal()"
    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-pink-50 dark:bg-pink-950/30
           border border-pink-200 dark:border-pink-900
           hover:bg-pink-100 dark:hover:bg-pink-900/50
           transition-all duration-200
           text-pink-600 dark:text-pink-400 shadow-sm"
    title="بازنشانی کامل پنل">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
    </svg>
</button>
				
				<button onclick="toggleInfoModal(true)"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-purple-50 dark:bg-purple-950/30
				           border border-purple-200 dark:border-purple-900
				           hover:bg-purple-100 dark:hover:bg-purple-900/50
				           transition-all duration-200
				           text-purple-600 dark:text-purple-400 shadow-sm"
				    title="اطلاعات">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
				    </svg>
				</button>
				
				<button onclick="restartCore()"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-blue-50 dark:bg-blue-950/30
				           border border-blue-200 dark:border-blue-900
				           hover:bg-blue-100 dark:hover:bg-blue-900/50
				           transition-all duration-200
				           text-blue-600 dark:text-blue-400 shadow-sm"
				    title="ری استارت پـنـل">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
				    </svg>
				</button>
				<button onclick="toggleThemePaletteModal(true)"
    class="w-9 h-9 rounded-full inline-flex items-center justify-center
           bg-cyan-50 dark:bg-cyan-950/30
           border border-cyan-200 dark:border-cyan-900
           hover:bg-cyan-100 dark:hover:bg-cyan-900/50
           transition-all duration-200
           text-cyan-500 dark:text-cyan-400 shadow-sm"
    title="تغییر تم رنگی">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
        <path d="M12 2a10 10 0 0 0 0 20c1.1 0 2-.9 2-2 0-.5-.2-1-.5-1.3-.3-.4-.5-.8-.5-1.2 0-1.1.9-2 2-2h2.4c2.6 0 4.6-2 4.6-4.5C22 5.6 17.5 2 12 2z"></path>
        <circle cx="6.5" cy="11.5" r="1.5" fill="currentColor"></circle>
        <circle cx="9.5" cy="7.5" r="1.5" fill="currentColor"></circle>
        <circle cx="14.5" cy="7.5" r="1.5" fill="currentColor"></circle>
        <circle cx="17.5" cy="11.5" r="1.5" fill="currentColor"></circle>
    </svg>
</button>
				<button id="grayscale-toggle"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-zinc-100 dark:bg-zinc-800/80
				           border border-zinc-300 dark:border-zinc-700
				           hover:bg-zinc-200 dark:hover:bg-zinc-700
				           transition-all duration-200
				           text-zinc-600 dark:text-zinc-400 shadow-sm"
				    title="حالت سیاه‌سفید">
				    <svg class="w-5 h-5" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
				        <path d="M12 2v20" />
				        <path d="M12 2a10 10 0 0 1 0 20Z" fill="currentColor" opacity="0.3" />
				        <path d="M12 2a10 10 0 0 0 0 20Z" />
				    </svg>
				</button>
				<button id="rgb-toggle"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-fuchsia-50 dark:bg-fuchsia-950/30
				           border border-fuchsia-200 dark:border-fuchsia-900
				           hover:bg-fuchsia-100 dark:hover:bg-fuchsia-900/50
				           transition-all duration-200
				           text-fuchsia-600 dark:text-fuchsia-400 shadow-sm"
				    title="حالت RGB / رنگین‌کمانی">
				    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				        <circle cx="12" cy="12" r="9" />
				        <path d="M12 3a9 9 0 0 1 0 18" fill="currentColor" opacity="0.25" />
				        <path d="M3 12h18" opacity="0.5" />
				        <path d="M6.3 6.3l11.4 11.4" opacity="0.4" />
				        <path d="M17.7 6.3L6.3 17.7" opacity="0.4" />
				    </svg>
				</button>
				
				<button id="theme-toggle"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-amber-50 dark:bg-amber-950/30
				           border border-amber-200 dark:border-amber-900
				           hover:bg-amber-100 dark:hover:bg-amber-900/50
				           transition-all duration-200
				           text-amber-500 dark:text-amber-400 shadow-sm"
				    title="تغییر تم">
				    <svg id="sun-icon" class="w-5 h-5 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path>
				    </svg>
				    <svg id="moon-icon" class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path>
				    </svg>
				</button>
				<button id="update-toggle" onclick="checkForUpdates(true)"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-green-50 dark:bg-green-950/30
				           border border-green-300 dark:border-green-900
				           hover:bg-green-100 dark:hover:bg-green-900/50
				           transition-all duration-200
				           text-green-700 dark:text-green-500
				           relative shadow-sm"
				    title="آپدیت">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 11l3-3m0 0l3 3m-3-3v8m0-13a9 9 0 110 18 9 9 0 010-18z"></path>
				    </svg>
				    <span id="update-badge" class="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-red-500 border-2 border-green-50 dark:border-green-900 rounded-full hidden animate-pulse"></span>
				</button>
				<button onclick="toggleSettingsModal(true)"
				    class="owner-only-btn w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-gray-50 dark:bg-zinc-800/50
				           border border-gray-200 dark:border-zinc-700
				           hover:bg-gray-100 dark:hover:bg-zinc-700/80
				           transition-all duration-200
				           text-gray-600 dark:text-zinc-400 shadow-sm"
				    title="تنظیمات">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
				    </svg>
				</button>
				
				<button onclick="logoutAdmin()"
				    class="w-9 h-9 rounded-full inline-flex items-center justify-center
				           bg-red-50 dark:bg-red-950/30
				           border border-red-200 dark:border-red-900
				           hover:bg-red-100 dark:hover:bg-red-900/50
				           transition-all duration-200
				           text-red-600 dark:text-red-400
				           shadow-sm hover:shadow-md"
				    title="خروج">
				    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
				    </svg>
				</button>
			</div>
		</div>
	</header>
	<main class="max-w-6xl mx-auto px-4 py-8 pb-56 md:pb-32 relative z-10">
<button onclick="const w = document.getElementById('stats-accordion-wrapper'); const i = document.getElementById('stats-accordion-icon'); w.classList.toggle('max-h-0'); w.classList.toggle('opacity-0'); w.classList.toggle('!mb-0'); w.classList.toggle('max-h-[500px]'); w.classList.toggle('opacity-100'); w.classList.toggle('mb-6'); i.classList.toggle('rotate-180'); localStorage.setItem('caspian_stats_hidden', w.classList.contains('max-h-0'));" class="w-full flex items-center justify-between text-xs font-bold mb-3 cursor-pointer focus:outline-none bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md px-3 py-1.5 shadow-sm hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500/50 transition-all duration-300 relative z-20">
	<div class="flex items-center gap-2">
		<div class="p-1 bg-blue-50 dark:bg-blue-900/30 text-blue-500 rounded-md">
			<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
		</div>
		<span class="text-gray-800 dark:text-zinc-200">آمار و وضعیت سرور</span>
	</div>
	<svg id="stats-accordion-icon" class="w-4 h-4 text-gray-500 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"></path></svg>
</button>
<div id="stats-accordion-wrapper" class="transition-all duration-500 ease-in-out overflow-hidden max-h-[500px] opacity-100 mb-6">
	<div class="grid grid-cols-2 lg:grid-cols-5 gap-3 pt-1 px-1 pb-2">
	<div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-indigo-400 dark:hover:border-indigo-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]">
		<div class="absolute -right-4 -bottom-4 w-16 h-16 bg-indigo-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
		<div class="flex items-center justify-between relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">تعداد کل کاربران</span>
			<div class="p-1 bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
			</div>
		</div>
		<div class="flex items-end justify-between relative z-10 w-full mt-0.5">
			<div class="text-lg font-black text-gray-900 dark:text-zinc-100 transition-all leading-none" id="stat-total-users">0</div>
			<span class="text-[9px] text-indigo-500 dark:text-indigo-400 flex items-center gap-1 font-medium whitespace-nowrap leading-none mb-0.5">
				<span class="w-1 h-1 bg-indigo-500 rounded-full animate-ping"></span>
				کل کاربران تعریف شده
			</span>
		</div>
	</div>
	<div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-green-400 dark:hover:border-green-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]">
		<div class="absolute -right-4 -bottom-4 w-16 h-16 bg-green-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
		<div class="flex items-center justify-between relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap flex items-center gap-1">
				<span>تعداد اتصال ها</span>
				<button type="button" onclick="openOnlineCounterWarning();" class="text-red-500 hover:text-red-400 transition-transform hover:scale-110 cursor-pointer inline-flex items-center" title="هشدار">
					<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
				</button>
			</span>
			<div class="p-1 bg-green-50 dark:bg-green-950/30 text-green-600 dark:text-green-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
			</div>
		</div>
		<div class="flex items-end justify-between relative z-10 w-full mt-0.5">
			<div class="text-lg font-black text-green-600 dark:text-green-400 transition-all leading-none" id="stat-active-users">0</div>
			<span class="text-[9px] text-green-500 dark:text-green-400 flex items-center gap-1 font-medium whitespace-nowrap leading-none mb-0.5">
				<span class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
				متصل در این لحظه
			</span>
		</div>
	</div>
	<div id="card-cf-requests" class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-orange-400 dark:hover:border-orange-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]">
		<div class="absolute -right-4 -bottom-4 w-16 h-16 bg-orange-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
		<div class="flex items-center justify-between relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">ریکوئست‌های روزانه</span>
			<div class="p-1 bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
			</div>
		</div>
		<div class="relative z-10 min-w-0 flex-1 w-full mt-0.5">
			<div class="flex items-end justify-between w-full mb-1.5">
				<div class="flex items-baseline gap-1">
					<span class="text-lg font-black text-orange-600 dark:text-orange-400 transition-all leading-none" id="stat-cf-requests">0</span>
					<span class="text-[9px] font-bold text-gray-400 mr-0.5 leading-none">/ 100k</span>
					<button id="cf-warning-btn" onclick="openUsageWarning()" class="hidden flex items-center justify-center w-3 h-3 bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 rounded-full font-bold text-[9px] animate-bounce shadow-sm border border-red-300 dark:border-red-700 mr-1 leading-none">!</button>
				</div>
				<span class="text-[9px] text-orange-500 dark:text-orange-400 flex items-center gap-1 font-medium whitespace-nowrap leading-none">
					<span>Total: <span id="stat-cf-total">0</span></span>
				</span>
			</div>
			<div class="w-full bg-gray-100 dark:bg-zinc-800 rounded-full h-1">
				<div id="stat-cf-progress" class="bg-orange-500 h-1 rounded-full transition-all duration-500" style="width: 0%"></div>
			</div>
		</div>
	</div>
	<div id="card-d1-usage" class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-purple-400 dark:hover:border-purple-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]">
		<div class="absolute -right-4 -bottom-4 w-16 h-16 bg-purple-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
		<div class="flex items-center justify-between relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">مصرف دیتابیس D1</span>
			<div class="p-1 bg-purple-50 dark:bg-purple-950/30 text-purple-600 dark:text-purple-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
			</div>
		</div>
		<div class="relative z-10 min-w-0 flex-1 w-full mt-1">
			<div class="grid grid-cols-2 gap-2 w-full">
				<div class="flex flex-col items-start justify-center">
					<div class="flex items-baseline gap-1">
						<span class="text-sm font-black text-purple-600 dark:text-purple-400 transition-all leading-none" id="stat-d1-writes">0</span>
						<span class="text-[9px] font-bold text-gray-400 leading-none">/ 100k</span>
					</div>
					<span class="text-[9px] font-medium text-gray-500 dark:text-zinc-400 mt-1">نوشتن</span>
				</div>
				<div class="flex flex-col items-end justify-center border-r border-gray-100 dark:border-zinc-800 pr-2">
					<div class="flex items-baseline gap-1">
						<span class="text-sm font-black text-purple-600 dark:text-purple-400 transition-all leading-none" id="stat-d1-reads">0</span>
						<span class="text-[9px] font-bold text-gray-400 leading-none">/ 5M</span>
					</div>
					<span class="text-[9px] font-medium text-gray-500 dark:text-zinc-400 mt-1">خواندن</span>
				</div>
			</div>
		</div>
	</div>
	<div class="col-span-2 lg:col-span-1 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]">
		<div class="absolute -right-4 -bottom-4 w-16 h-16 bg-blue-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
		<div class="flex items-center justify-between relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">ترافیک مصرفی سرور</span>
			<div class="p-1 bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
			</div>
		</div>
		<div class="flex items-end justify-between relative z-10 w-full mt-0.5">
			<div class="text-lg font-black text-blue-600 dark:text-blue-400 transition-all whitespace-nowrap leading-none" id="stat-total-usage">0 GB</div>
			<span class="text-[9px] text-blue-500 dark:text-blue-400 flex items-center gap-0.5 font-medium whitespace-nowrap leading-none mb-0.5">
				<svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"></path></svg>
				مجموع
			</span>
		</div>
	</div>
</div>
</div>
<script>
	if(localStorage.getItem('caspian_stats_hidden') === 'true') {
		const w = document.getElementById('stats-accordion-wrapper');
		if(w) {
			w.classList.remove('max-h-[500px]', 'opacity-100', 'mb-6');
			w.classList.add('max-h-0', 'opacity-0', '!mb-0');
		}
		const i = document.getElementById('stats-accordion-icon');
		if(i) i.classList.add('rotate-180');
	}
</script>
		<div id="loading-state" class="text-center py-12">
			<span class="text-gray-500 dark:text-gray-400">در حال بارگذاری کاربران...</span>
		</div>
		<div class="mb-5 flex flex-col md:flex-row gap-2 justify-between items-center bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2 shadow-sm">
			<div class="relative w-full md:w-80">
				<input type="text" id="search-input" oninput="filterAndRenderUsers()" placeholder="جستجوی نام کاربری یا UUID..." class="w-full pl-3 pr-8 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs">
				<div class="absolute inset-y-0 right-0 flex items-center pr-2.5 pointer-events-none text-gray-400">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
				</div>
			</div>
			<div class="flex items-center gap-2 w-full md:w-auto">
				<select id="filter-status" onchange="filterAndRenderUsers()" class="flex-1 min-w-0 px-2 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer truncate">
					<option value="all">🔍 همه</option>
					<option value="active">✅ فعال</option>
					<option value="inactive">❌ غیرفعال</option>
					<option value="online">⚡ آنلاین</option>
					<option value="offline">💤 آفلاین</option>
					<option value="expired">⏳ منقضی</option>
				</select>
				<select id="sort-users" onchange="filterAndRenderUsers()" class="flex-1 min-w-0 px-2 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer truncate">
					<option value="newest">📅 جدیدترین</option>
					<option value="name">🔤 نام کاربری (الفبا)</option>
					<option value="usage-desc">📊 بیشترین مصرف</option>
					<option value="usage-asc">📈 کمترین مصرف</option>
					<option value="expiry-asc">⏳ کمترین زمان باقی‌مانده</option>
				</select>
			</div>
		</div>
		<div class="flex items-center justify-between mb-4">
			<h2 class="text-lg font-bold text-gray-800 dark:text-zinc-200">لیست کاربران</h2>
			<div class="flex items-center gap-5">
				<button onclick="openGamingQuickModal(this)" title="سرور گیمینگ (پینگ پایین، IP ثابت)" class="p-2 rounded-full bg-yellow-50 dark:bg-yellow-950/40 border-2 border-yellow-500 dark:border-yellow-500 hover:bg-yellow-100 dark:hover:bg-yellow-900/60 transition-all duration-300 text-yellow-600 dark:text-yellow-400 shadow-[0_0_15px_rgb(var(--a500,234_179_8)/0.6)] hover:shadow-[0_0_25px_rgb(var(--a500,234_179_8)/0.95)] hover:scale-125 active:scale-110 cursor-pointer inline-flex items-center justify-center relative group">
					<span class="absolute -inset-1 rounded-full bg-yellow-500/20 animate-ping opacity-75 group-hover:opacity-100 pointer-events-none" style="animation-delay: 0.16s;"></span>
					<svg id="gaming-quick-icon" class="w-6 h-6 transition-transform duration-300 group-hover:rotate-12 drop-shadow-[0_0_6px_rgb(var(--a500,234_179_8)/0.8)] relative z-10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<path d="M6.5 8h11c1.933 0 3.5 1.567 3.5 3.5v3c0 1.657-1.343 3-3 3-.775 0-1.48-.294-2.012-.777L14 15H10l-1.988 1.723A3.001 3.001 0 013 14.5v-3C3 9.567 4.567 8 6.5 8z"></path>
						<path d="M6 12h4m-2-2v4"></path>
						<circle cx="17" cy="10.5" r="1"></circle>
						<circle cx="15" cy="13.5" r="1"></circle>
					</svg>
				</button>
				<button onclick="createDirectUser(this)" title="افزودن کاربر مستقیم (بدون پروکسی)" class="p-2 rounded-full bg-cyan-50 dark:bg-cyan-950/40 border-2 border-cyan-500 dark:border-cyan-500 hover:bg-cyan-100 dark:hover:bg-cyan-900/60 transition-all duration-300 text-cyan-600 dark:text-cyan-400 shadow-[0_0_15px_rgb(var(--a500,6_182_212)/0.6)] hover:shadow-[0_0_25px_rgb(var(--a500,6_182_212)/0.95)] hover:scale-125 active:scale-110 cursor-pointer inline-flex items-center justify-center relative group">
					<span class="absolute -inset-1 rounded-full bg-cyan-500/20 animate-ping opacity-75 group-hover:opacity-100 pointer-events-none" style="animation-delay: 0s;"></span>
					<svg id="direct-add-icon" class="w-6 h-6 transition-transform duration-300 group-hover:rotate-12 drop-shadow-[0_0_6px_rgb(var(--a500,6_182_212)/0.8)] relative z-10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<circle cx="12" cy="12" r="10"></circle>
						<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
						<path d="M2 12h20"></path>
					</svg>
				</button>
				<button onclick="openWifiQuickModal(this)" title="مخصوص اپراتور کانفیگ سریع (حجم نامحدود)" class="p-2 rounded-full bg-red-50 dark:bg-red-950/40 border-2 border-red-500 dark:border-red-500 hover:bg-red-100 dark:hover:bg-red-900/60 transition-all duration-300 text-red-600 dark:text-red-400 shadow-[0_0_15px_rgb(var(--a500,239_68_68)/0.6)] hover:shadow-[0_0_25px_rgb(var(--a500,239_68_68)/0.95)] hover:scale-125 active:scale-110 cursor-pointer inline-flex items-center justify-center relative group">
					<span class="absolute -inset-1 rounded-full bg-red-500/20 animate-ping opacity-75 group-hover:opacity-100 pointer-events-none" style="animation-delay: 0.33s;"></span>
					<svg id="wifi-quick-icon" class="w-6 h-6 transition-transform duration-300 group-hover:rotate-12 drop-shadow-[0_0_6px_rgb(var(--a500,239_68_68)/0.8)] relative z-10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<path d="M5 12.55a11 11 0 0 1 14.08 0"></path>
						<path d="M1.42 9a16 16 0 0 1 21.16 0"></path>
						<path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path>
						<line x1="12" y1="20" x2="12.01" y2="20"></line>
					</svg>
				</button>
				<button onclick="openRocketModal(this)" title="افزودن کاربر تک لوکیشن" class="p-2 rounded-full bg-orange-50 dark:bg-orange-950/40 border-2 border-orange-500 dark:border-orange-500 hover:bg-orange-100 dark:hover:bg-orange-900/60 transition-all duration-300 text-orange-600 dark:text-orange-400 shadow-[0_0_15px_rgb(var(--a500,249_115_22)/0.6)] hover:shadow-[0_0_25px_rgb(var(--a500,249_115_22)/0.95)] hover:scale-125 active:scale-110 cursor-pointer inline-flex items-center justify-center relative group">
					<span class="absolute -inset-1 rounded-full bg-orange-500/20 animate-ping opacity-75 group-hover:opacity-100 pointer-events-none" style="animation-delay: 0.66s;"></span>
					<svg id="rocket-add-icon" class="w-6 h-6 transition-transform duration-300 group-hover:-translate-y-1 group-hover:translate-x-1 drop-shadow-[0_0_6px_rgb(var(--a500,249_115_22)/0.8)] relative z-10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path>
						<path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path>
						<path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path>
						<path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"></path>
					</svg>
				</button>
				<button onclick="quickCreateUser(this)" title="افزودن کاربر مولتی لوکیشن" class="p-2 rounded-full bg-indigo-50 dark:bg-indigo-950/40 border-2 border-indigo-500 dark:border-indigo-500 hover:bg-indigo-100 dark:hover:bg-indigo-900/60 transition-all duration-300 text-indigo-600 dark:text-indigo-400 shadow-[0_0_15px_rgb(var(--a500,99_102_241)/0.6)] hover:shadow-[0_0_25px_rgb(var(--a500,99_102_241)/0.95)] hover:scale-125 active:scale-110 cursor-pointer inline-flex items-center justify-center relative group">
					<span class="absolute -inset-1 rounded-full bg-indigo-500/20 animate-ping opacity-75 group-hover:opacity-100 pointer-events-none" style="animation-delay: 1s;"></span>
					<svg id="quick-add-icon" class="w-6 h-6 transition-transform duration-300 group-hover:rotate-12 drop-shadow-[0_0_6px_rgb(var(--a500,99_102_241)/0.8)] relative z-10" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
				</button>
				<button onclick="openCreateModal()" title="افزودن کاربر" class="p-2 rounded-full bg-green-50 dark:bg-green-950/30 border-2 border-green-600 dark:border-green-700/60 hover:bg-green-100 dark:hover:bg-green-900/50 transition-all duration-300 text-green-700 dark:text-green-400 shadow-sm hover:shadow hover:scale-110 cursor-pointer inline-flex items-center justify-center">
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
				</button>
				
			</div>
		</div>
		<div id="users-table-container" class="hidden overflow-x-auto pb-4 px-1">
			<table class="w-full text-right border-separate" style="border-spacing: 0 8px;">
				<thead class="text-xs font-bold text-gray-700 dark:text-gray-300">
					<tr class="text-center">
						<th class="py-3 px-1.5 w-10 text-center rounded-r-md border-y border-r border-gray-200 dark:border-zinc-800 align-middle">
							<div class="flex flex-col items-center justify-center h-full">
								<input type="checkbox" id="select-all-users" onchange="toggleSelectAllUsers(this)" class="w-5 h-5 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-green-600 bg-white dark:bg-zinc-900 checked:bg-green-600 checked:border-green-600 focus:ring-green-500/50 focus:ring-offset-0 transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95" style="filter: none !important; accent-color: #16a34a !important;">
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
								<span>اطلاعات</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path></svg>
								<span>عملیات</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-fuchsia-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
								<span>پروتکل</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
								<span>لینک ساب</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 w-1 whitespace-nowrap align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
								<div class="flex items-center justify-center gap-1">
									<span>تعداد کانفیگ‌ها</span>
									<button type="button" onclick="openConfigCountWarning();" class="text-amber-500 hover:text-amber-400 transition-transform hover:scale-125 cursor-pointer inline-flex items-center" title="هشدار">
										<svg class="w-4 h-4 animate-pulse drop-shadow-[0_0_6px_rgb(var(--a500,245_158_11)/0.8)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
									</button>
								</div>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path></svg>
								<span>پورت</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 w-[115px] align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
								<span>حجم</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 w-[115px] align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
								<span>ریکوئست</span>
							</div>
						</th>
						<th class="py-3 px-2 border-y border-gray-200 dark:border-zinc-800 w-[115px] align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-fuchsia-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
								<span>زمان</span>
							</div>
						</th>
						<th class="py-3 px-2 rounded-l-md border-y border-l border-gray-200 dark:border-zinc-800 w-[115px] align-middle">
							<div class="flex flex-col items-center justify-center gap-1.5">
								<svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.906 14.142 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path></svg>
								<div class="flex items-center justify-center gap-1">
									<span>متصل</span>
									<button type="button" onclick="openOnlineCounterWarning();" class="text-red-500 hover:text-red-400 transition-transform hover:scale-110 cursor-pointer inline-flex items-center" title="هشدار">
										<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
									</button>
								</div>
							</div>
						</th>
					</tr>
				</thead>
				<tbody id="users-tbody" class="text-sm"></tbody>
			</table>
		</div>
		<div id="empty-state" class="hidden p-8 border-2 border-dashed border-red-500/60 dark:border-red-500/50 bg-red-50 dark:bg-red-900/10 rounded-md text-center animate-pulse shadow-sm">
			<p class="text-red-600 dark:text-red-400 font-bold text-lg flex items-center justify-center flex-wrap gap-2 leading-loose">
				<span>کاربری وجود ندارد. برای ساخت کاربر روی</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-green-50 dark:bg-green-950/30 border border-green-600 dark:border-green-700/60 text-green-700 dark:text-green-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg></span>
				<span>کلیک کنید یا از دکمه‌های</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-500 text-cyan-600 dark:text-cyan-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path><path d="M2 12h20"></path></svg></span>
				<span>،</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-orange-50 dark:bg-orange-950/40 border border-orange-500 text-orange-600 dark:text-orange-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"></path></svg></span>
				<span>و</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-500 text-indigo-600 dark:text-indigo-400 shadow-sm"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></span>
				<span>برای ایجاد سریع استفاده کنید.</span>
			</p>
		</div>
	</main>
<div id="traffic-chart-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div class="w-full max-w-2xl bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-xl shadow-2xl p-5 transform transition-all scale-95 opacity-0 duration-200" id="traffic-chart-modal-card">
		<div class="flex justify-between items-center mb-4">
			<h3 class="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
				<svg class="w-5 h-5 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
				مصرف کل پنل — مقایسه روزانه (شمسی)
			</h3>
			<button onclick="closeTrafficChartModal()" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex items-center gap-2 mb-4 flex-wrap">
			<span class="text-[11px] font-bold text-gray-500 dark:text-zinc-400">بازه:</span>
			<button type="button" onclick="loadTrafficChart(7)" class="px-2.5 py-1 rounded-md text-[11px] font-bold border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 transition" data-chart-days="7">۷ روز</button>
			<button type="button" onclick="loadTrafficChart(14)" class="px-2.5 py-1 rounded-md text-[11px] font-bold border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 transition" data-chart-days="14">۱۴ روز</button>
			<button type="button" onclick="loadTrafficChart(30)" class="px-2.5 py-1 rounded-md text-[11px] font-bold border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 transition" data-chart-days="30">۳۰ روز</button>
			<span id="traffic-chart-total" class="mr-auto text-[11px] font-bold text-gray-600 dark:text-zinc-300"></span>
		</div>
		<div id="traffic-chart-loading" class="text-center text-sm text-gray-500 dark:text-zinc-400 py-10">در حال بارگذاری...</div>
		<div id="traffic-chart-bars" class="hidden w-full h-64 relative" dir="ltr"></div>
		<div id="traffic-chart-empty" class="hidden text-center text-sm text-gray-500 dark:text-zinc-400 py-10">هنوز داده مصرف روزانه ثبت نشده است.</div>
		<p class="text-[10px] text-gray-400 dark:text-zinc-500 mt-3 leading-relaxed">نمودار خطی مصرف مجموع همه کاربران در هر روز (به وقت تهران). تاریخ‌ها شمسی هستند. اگر تاریخچه خالی باشد، مصرف امروز از مجموع daily کاربران مقداردهی اولیه می‌شود.</p>
	</div>
</div>
<div id="pwa-install-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-green-500/40 rounded-2xl shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center relative overflow-hidden">
		
		<div class="absolute -right-12 -top-12 w-32 h-32 bg-green-500/10 rounded-full blur-2xl pointer-events-none"></div>
		
		<div class="flex justify-between items-center mb-4 relative z-10">
			<h3 class="text-sm font-black text-gray-900 dark:text-white flex items-center gap-2">
				<span class="text-lg">📲</span>
				<span id="pwa-modal-title">راهنمای نصب اپلیکیشن کاسپین</span>
			</h3>
			<button onclick="togglePwaModal(false)" class="p-1 rounded-md text-gray-400 hover:text-red-500 cursor-pointer transition">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		
		<div class="flex items-center gap-3 p-3 bg-green-50/50 dark:bg-green-900/10 rounded-xl border border-green-200/70 dark:border-green-800/50 mb-4 text-right">
			<div class="w-11 h-11 rounded-xl bg-green-50 dark:bg-green-950/60 border-2 border-green-500 flex items-center justify-center text-green-600 dark:text-green-400 flex-shrink-0 shadow-md">
				<svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
			</div>
			<div>
				<h4 class="text-xs font-black text-gray-900 dark:text-white">پنل کاسپین</h4>
				<span class="text-[10px] text-gray-500 dark:text-zinc-400 block">اپلیکیشن پیشرفته و مستقل وب (PWA)</span>
			</div>
		</div>
		
		<div id="pwa-instructions-list" class="space-y-2.5 text-right text-xs text-gray-700 dark:text-zinc-300 font-medium leading-relaxed select-none mb-5 max-h-48 overflow-y-auto pr-1">
		</div>
		
		<button onclick="togglePwaModal(false)" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-400 dark:hover:bg-green-900/40 dark:hover:text-green-300 font-bold rounded-xl text-xs transition shadow-sm cursor-pointer active:scale-95">متوجه شدم</button>
	</div>
</div>
<div id="info-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-purple-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col">
		
		<div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-500 mb-3 shadow-inner mx-auto flex-shrink-0">
			<svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
			</svg>
		</div>
		
		<h3 class="font-black text-lg text-gray-900 dark:text-white mb-3">اطلاعیه مهم امنیتی و وضعیت پروژه</h3>
		
		<div class="text-xs text-gray-600 dark:text-gray-300 mb-4 leading-relaxed font-medium text-justify space-y-2">
			<p>
			همراهان گرامی، <strong>فروشندگان کانفیگ</strong>، پنل کاسپین امنیت کامل دارد و با کد های جدید مصرف اینرنت شما هم کم شده است.
			</p>
			<p>
				پروژه کاسپین همواره بر پایه شفافیت مطلق بنا شده است. سورس‌کد کامل در اختیار شماست تا بتوانید مستقلاً و حتی به کمک ابزارهای هوش مصنوعی آن را بررسی کرده و از سلامت و امنیت قطعی پروژه اطمینان حاصل کنید.
			</p>
			<p class="text-amber-600 dark:text-amber-400 font-bold text-center mt-2 border-t border-gray-100 dark:border-zinc-800/50 pt-2.5">
				ادامه این مسیر پرفراز و نشیب و مقابله با این تخریب‌های سازمان‌یافته، بدون همراهی شما دشوار است. حمایت‌های شما، تنها پشتوانه ما برای زنده نگه داشتن کاسپین است.
			</p>
		</div>
		
		<div class="flex flex-col gap-2 mt-auto">
			<div class="flex flex-col sm:flex-row gap-2 w-full">
				<button onclick="" class="flex-1 py-2 bg-transparent border-2 border-blue-600 text-blue-700 hover:bg-blue-900/20 hover:text-blue-800 dark:border-blue-500 dark:text-blue-400 dark:hover:bg-blue-900/40 dark:hover:text-blue-300 font-bold rounded-md text-[11px] transition duration-300 shadow-sm flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
					دریافت سورس‌کد
				</button>
				
				<button onclick="window.open('https://github.com/sepehr-gamer/Caspian-pannel', '_blank')" class="flex-1 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-400 dark:hover:bg-green-900/40 dark:hover:text-green-300 font-bold rounded-md text-[11px] transition duration-300 shadow-sm flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z"></path></svg>
					حمایت از پروژه
				</button>
			</div>
			
			<button onclick="toggleInfoModal(false)" class="w-full py-2.5 bg-transparent border-2 border-purple-600 text-purple-700 hover:bg-purple-900/20 hover:text-purple-800 dark:border-purple-500 dark:text-purple-400 dark:hover:bg-purple-900/40 dark:hover:text-purple-300 font-black rounded-md text-sm transition duration-300 shadow-sm">
				متوجه شدم
			</button>
		</div>
		
	</div>
</div>
<div id="login-info-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-teal-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        
        <!-- آیکون بالا -->
        <div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-teal-100 dark:bg-teal-900/30 text-teal-500 mb-3 shadow-inner">
            <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
            </svg>
        </div>
        
        <!-- عنوان -->
        <h3 class="font-black text-lg text-gray-900 dark:text-white mb-4">اطلاعات ورود شما</h3>
        
        <!-- محتوای اطلاعات -->
        <div class="space-y-3 text-right">
            
            <!-- آی‌پی -->
            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">🌐 آی‌پی شما</span>
                <span id="login-info-ip" class="block text-xs font-mono font-bold text-teal-600 dark:text-teal-400 break-all" dir="ltr">در حال دریافت...</span>
            </div>
            
            <!-- زمان ورود -->
            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">🕐 زمان ورود</span>
                <span id="login-info-time" class="block text-xs font-mono font-bold text-teal-600 dark:text-teal-400" dir="ltr">-</span>
            </div>
            
            <!-- مدت اعتبار -->
            <div class="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/50 rounded-lg">
                <span class="block text-[11px] font-bold text-amber-600 dark:text-amber-400 mb-1">⏳ مدت نمایش</span>
                <span class="block text-xs font-bold text-amber-700 dark:text-amber-300" dir="rtl">این اطلاعات تا ۱ ساعت دیگر پاک می‌شود</span>
            </div>
            
        </div>
        
        <!-- دکمه بستن -->
        <button onclick="toggleLoginInfoModal(false)" class="mt-5 w-full py-2.5 bg-transparent border-2 border-teal-600 text-teal-700 hover:bg-teal-900/20 hover:text-teal-800 dark:border-teal-500 dark:text-teal-400 dark:hover:bg-teal-900/40 dark:hover:text-teal-300 font-black rounded-md text-sm transition duration-300 shadow-sm">
            بستن
        </button>
        
    </div>
</div>
<div id="usage-warning-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-orange-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-500 mb-4 shadow-inner">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">هشدار محدودیت درخواست روزانه</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			درخواست‌های روزانه کلودفلر شما از ۹۰,۰۰۰ عبور کرده است. در صورت عبور از محدودیت رایگان ۱۰۰,۰۰۰ درخواست، دسترسی به پـنـل و اتصالات تا ساعت ۳:۳۰ بامداد (به وقت ایران) قطع خواهد شد.
		</p>
		<button onclick="closeUsageWarning()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-md text-sm transition duration-300 shadow-lg">
			متوجه شدم
		</button>
	</div>
</div>
<div id="free-panel-warning-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border-4 border-red-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 text-red-500 mb-4 shadow-inner">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-3">توجه توجه</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
	این پـنـل  <span class="text-red-500 font-bold">بهترین</span> است. پس <span class="text-amber-500 font-bold"> دوست عزیز</span> با فشار نیاوردن<span class="text-amber-500 font-bold"> به سرور</span> و ندیدن<span class="text-red-500 font-bold"> فیلم های مستهجن</span> مرا خوشحال کن
			<span class="block mt-3 px-3 py-2.5 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/50 rounded-lg text-green-700 dark:text-green-400 font-bold shadow-sm">
	    	حالا برو<span class="whitespace-nowrap"> کانفیگت رو بساز</span> خوش بگذره !
			</span>
		</p>
		<button id="free-panel-close-btn" class="relative overflow-hidden w-full h-12 bg-transparent border-2 border-green-800 text-green-900 hover:bg-green-800 hover:text-white dark:border-green-800 dark:text-green-700 dark:hover:bg-green-900 dark:hover:text-white font-black rounded-md text-sm transition-transform duration-300 shadow-lg select-none" style="touch-action: none; -webkit-touch-callout: none; -webkit-user-select: none;">
			<div id="free-panel-progress" class="absolute right-0 top-0 h-full bg-green-500/20 dark:bg-green-500/30 w-0 pointer-events-none"></div>
			<span class="relative z-10 pointer-events-none">برای تأیید ۳ ثانیه نگه دارید</span>
		</button>
	</div>
</div>
<div id="global-message-modal" class="fixed inset-0 z-[86] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border-2 border-red-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div id="global-message-content" class="mb-6 w-full text-center font-medium leading-relaxed">
		</div>
		<button id="global-message-close-btn" class="relative overflow-hidden w-full h-12 bg-transparent border-2 border-red-600 text-red-700 dark:border-red-500 dark:text-red-500 font-black rounded-md text-sm transition-transform duration-300 shadow-lg select-none" style="touch-action: none; -webkit-touch-callout: none; -webkit-user-select: none;">
			<div id="global-message-progress" class="absolute right-0 top-0 h-full bg-red-500/20 dark:bg-red-500/30 w-0 pointer-events-none"></div>
			<span class="relative z-10 pointer-events-none">برای بستن ۲ ثانیه نگه دارید</span>
		</button>
	</div>
</div>
<div id="online-counter-warning-modal" class="fixed inset-0 z-[87] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-red-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 text-red-500 mb-4 shadow-inner">
			<svg class="w-8 h-8 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">هشدار شمارنده آنلاین</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			به دلیل ساختار کلودفلر، آمار شمارنده کاربران آنلاین دقیق نمی باشد؛ همچنین تست پینگ یا آپدیت لینک های ساب توسط کلاینت ممکن است به صورت موقت منجر به نمایش افزایش کاذب تعداد کاربران فعال گردد. </p>
		<button onclick="closeOnlineCounterWarning()" class="w-full py-3.5 bg-transparent border-2 border-red-600 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-500 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-black rounded-md text-sm transition duration-300 shadow-lg">
			متوجه شدم
		</button>
	</div>
</div>
<div id="pattng-info-modal" class="fixed inset-0 z-[115] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-pattng/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-pattng/10 text-pattng mb-4 shadow-[0_0_15px_rgb(var(--a500,51_251_31)/0.2)]">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">توجه: پیش‌نیاز بهینه‌سازی</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			قابلیت‌های <b>Patterniha</b> در حال حاضر منحصراً روی اپلیکیشن‌های <span class="text-pattng font-bold">PattNG (اندروید)</span> و <span class="text-pattng font-bold">PattN (ویندوز)</span> پشتیبانی می‌شود. لطفاً برای استفاده از این قابلیت، نرم‌افزار مربوطه را نصب کنید.
		</p>
		<div class="flex flex-col gap-3">
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
				<a href="https://github.com/patterniha/PattNG/releases/latest" target="_blank" class="w-full py-3 bg-pattng/10 hover:bg-pattng/20 text-pattng border border-pattng/50 font-black rounded-md text-xs transition duration-300 shadow-[0_0_10px_rgb(var(--a500,51_251_31)/0.2)] flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					اندروید (PattNG)
				</a>
				<a href="https://github.com/patterniha/PattN/releases/latest/download/PattN-windows-64.zip" target="_blank" class="w-full py-3 bg-pattng/10 hover:bg-pattng/20 text-pattng border border-pattng/50 font-black rounded-md text-xs transition duration-300 shadow-[0_0_10px_rgb(var(--a500,51_251_31)/0.2)] flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					ویندوز (PattN)
				</a>
			</div>
			<button onclick="togglePattNgModal(false)" class="w-full py-3.5 bg-transparent border-2 border-gray-500 text-gray-600 hover:bg-gray-100 dark:border-gray-600 dark:text-gray-400 dark:hover:bg-zinc-800 font-bold rounded-md text-sm transition duration-300 mt-1">
				فهمیدم
			</button>
		</div>
	</div>
</div>
<div id="config-count-warning-modal" class="fixed inset-0 z-[88] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-amber-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-500 mb-4 shadow-inner">
			<svg class="w-8 h-8 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-3">محاسبه تعداد کانفیگ‌ها</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-4 leading-relaxed font-medium">
			تعداد کل کانفیگ‌های هر کاربر از این فرمول به دست می‌آید
		</p>
		<div class="bg-gray-50 dark:bg-zinc-800/50 border border-gray-200 dark:border-zinc-700 rounded-md p-3 mb-2 text-[10px] sm:text-xs font-bold text-gray-800 dark:text-zinc-200 text-center shadow-inner whitespace-nowrap overflow-x-auto" dir="rtl">
			۳ + (تعداد لوکیشن‌ها) × (تعداد آی‌پی تمیز) × (تعداد پورت) × (تعداد پروتکل)
		</div>
		<p class="text-[10px] text-gray-500 dark:text-gray-400 mb-4 font-medium leading-relaxed">
			* منظور از لوکیشن‌ها، مجموع پروکسی‌های وارد شده به علاوه اتصال مستقیم (در صورت فعال بودن) است.
		</p>
		<div class="text-[11px] text-amber-700 dark:text-amber-500 mb-6 leading-relaxed font-bold bg-amber-50 dark:bg-amber-950/20 p-3 rounded text-right border border-amber-200 dark:border-amber-900/50">
			⚠️ <b>توصیه مهم:</b> برای جلوگیری از زیاد شدن کانفیگ‌ها و در نتیجه سنگین شدن و هنگ کردن نرم‌افزار کاربر، پیشنهاد می‌شود پورت‌های کمتری انتخاب کنید و تعداد آی‌پی‌های تمیز را در حد معقول نگه دارید.
		</div>
		<button onclick="closeConfigCountWarning()" class="w-full py-3.5 bg-transparent border-2 border-amber-600 text-amber-700 hover:bg-amber-900/20 hover:text-amber-800 dark:border-amber-500 dark:text-amber-500 dark:hover:bg-amber-900/40 dark:hover:text-amber-400 font-black rounded-md text-sm transition duration-300 shadow-lg">
			متوجه شدم
		</button>
	</div>
</div>
	<div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-black/75 backdrop-blur-sm opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
		<div id="user-modal-card" class="w-full max-w-5xl bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-[opacity,transform] duration-200 opacity-0 scale-95 ease-out flex flex-col max-h-[92vh] transform-gpu">
			<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
				<div class="flex items-center gap-3">
					<div class="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
					</div>
					<div>
						<h3 id="modal-title" class="font-black text-gray-900 dark:text-zinc-100 text-sm sm:text-base tracking-tight">ایجاد کاربر جدید</h3>
						<p class="text-[11px] text-gray-500 dark:text-zinc-400 font-medium">مشخصات، دسترسی‌ها و پروتکل‌های اتصال کاربر</p>
					</div>
				</div>
				<button type="button" onclick="toggleModal(false)" class="p-2 rounded-lg bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 shadow-sm" title="بستن">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			</div>
			<form id="create-user-form" class="flex flex-col flex-1 min-h-0 overflow-hidden" onsubmit="handleFormSubmit(event)">
				<input type="hidden" id="hidden-auto-rotate" value="0">
				<input type="hidden" id="hidden-rotate-time" value="">
				<input type="hidden" id="hidden-ip-operator" value="all">
				<input type="hidden" id="hidden-ip-count" value="20">
				<div class="flex flex-col md:flex-row flex-1 min-h-0 overflow-hidden">
					<div class="w-full md:w-64 bg-gray-50/90 dark:bg-amoled-bg/80 border-b md:border-b-0 md:border-l border-gray-200 dark:border-amoled-border p-3 md:p-4 flex flex-row md:flex-col gap-2 flex-shrink-0 overflow-x-auto md:overflow-x-visible md:justify-between">
						<div class="flex flex-row md:flex-col gap-2 w-full">
							<button type="button" onclick="switchUserTab('tab-user-info')" id="tab-btn-user-info" class="user-modal-tab-btn active flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-blue-600/10 dark:bg-blue-500/15 border border-blue-500/30 text-blue-600 dark:text-blue-400 font-bold shadow-sm">
								<div class="flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-blue-500/15 dark:bg-blue-400/20 text-blue-600 dark:text-blue-300">
									<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
								</div>
								<div class="hidden sm:block text-right">
									<div class="text-xs font-black">نام کاربری و مشخصات</div>
									<div class="text-[10px] opacity-75 font-normal">حجم، زمان، محدودیت و تمدید</div>
								</div>
								<span class="sm:hidden text-[10px] sm:text-xs font-bold whitespace-nowrap">مشخصات</span>
							</button>
							<button type="button" onclick="switchUserTab('tab-ports-network')" id="tab-btn-ports-network" class="user-modal-tab-btn flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-transparent hover:bg-gray-100 dark:hover:bg-amoled-input/50 border border-transparent text-gray-600 dark:text-zinc-400 font-medium">
								<div class="flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-gray-200/60 dark:bg-slate-900 text-gray-500 dark:text-zinc-400">
									<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
								</div>
								<div class="hidden sm:block text-right">
									<div class="text-xs font-black">پورت‌های اتصال و شبکه</div>
									<div class="text-[10px] opacity-75 font-normal">پورت‌ها، آی‌پی تمیز و فرگمنت</div>
								</div>
								<span class="sm:hidden text-[10px] sm:text-xs font-bold whitespace-nowrap">پورت و IP</span>
							</button>
							<button type="button" onclick="switchUserTab('tab-proxy-settings')" id="tab-btn-proxy-settings" class="user-modal-tab-btn flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-transparent hover:bg-gray-100 dark:hover:bg-amoled-input/50 border border-transparent text-gray-600 dark:text-zinc-400 font-medium">
								<div class="flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-gray-200/60 dark:bg-slate-900 text-gray-500 dark:text-zinc-400">
									<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
								</div>
								<div class="hidden sm:block text-right">
									<div class="text-xs font-black">تنظیم پروکسی و کشور</div>
									<div class="text-[10px] opacity-75 font-normal">آی‌پی ثابت و زنجیره اتصال</div>
								</div>
								<span class="sm:hidden text-[10px] sm:text-xs font-bold whitespace-nowrap">پروکسی</span>
							</button>
						</div>
						
						<div class="hidden md:flex flex-col gap-2 mt-auto pt-4 border-t border-gray-200 dark:border-amoled-border w-full">
							<button type="submit" id="submit-btn-desktop" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-600 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 font-black rounded-xl text-sm transition shadow-lg flex items-center justify-center gap-1.5 cursor-pointer">
								<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
								<span>ایجاد کاربر</span>
							</button>
							<button type="button" onclick="toggleModal(false)" class="w-full py-2 bg-transparent border-2 border-red-600 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 font-bold rounded-xl text-xs transition shadow-sm">
								انصراف
							</button>
						</div>
					</div>
					<div class="flex-1 p-4 sm:p-6 overflow-y-auto max-h-[72vh] space-y-4 custom-scrollbar overscroll-contain">
						
						<div id="tab-user-info" class="user-tab-panel space-y-4">
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 uppercase tracking-wider flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-indigo-500"></span>
										<span>پروتکل‌های اتصال (انتخاب حداقل یک مورد الزامی است)</span>
									</label>
								</div>
								<div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
									<label class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-xl cursor-pointer hover:border-blue-500 dark:hover:border-blue-500 transition select-none">
										<div class="flex items-center gap-2.5">
											<div class="w-8 h-8 rounded-lg bg-blue-500/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-black text-xs">
												<svg class="w-5 h-5 -ml-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"></path></svg>
											</div>
											<div>
												<span class="text-xs font-black text-gray-800 dark:text-zinc-200 block">پروتکل VLESS</span>
												<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal">پروتکل سبک و پرسرعت </span>
											</div>
										</div>
										<input type="checkbox" id="input-proto-vless" checked onchange="handleProtocolChange(this)" class="w-4 h-4 rounded focus:ring-green-500/50 bg-white dark:bg-amoled-input border-gray-300 dark:border-amoled-border cursor-pointer text-green-600" style="filter: none !important; accent-color: #16a34a !important;">
									</label>
									<label class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-xl cursor-pointer hover:border-purple-500 dark:hover:border-purple-500 transition select-none">
										<div class="flex items-center gap-2.5">
											<div class="w-8 h-8 rounded-lg bg-purple-500/10 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 flex items-center justify-center font-black text-xs">
												<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 11a2 2 0 100-4 2 2 0 000 4z"></path><path d="M12 11v3"></path></svg>
											</div>
											<div>
												<span class="text-xs font-black text-gray-800 dark:text-zinc-200 block">پروتکل Trojan</span>
												<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal">پروتکل امنیتی پیشرفته </span>
											</div>
										</div>
										<input type="checkbox" id="input-proto-trojan" onchange="handleProtocolChange(this)" class="w-4 h-4 rounded focus:ring-green-500/50 bg-white dark:bg-amoled-input border-gray-300 dark:border-amoled-border cursor-pointer text-green-600" style="filter: none !important; accent-color: #16a34a !important;">
									</label>
									<label class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-xl cursor-pointer hover:border-yellow-500 dark:hover:border-yellow-500 transition select-none">
										<div class="flex items-center gap-2.5">
											<div class="w-8 h-8 rounded-lg bg-yellow-500/10 dark:bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 flex items-center justify-center font-black text-xs">
												<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg>
											</div>
											<div>
												<span class="text-xs font-black text-gray-800 dark:text-zinc-200 block">پروتکل Shadowsocks</span>
												<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal">پروتکل امن سبک</span>
											</div>
										</div>
										<input type="checkbox" id="input-proto-ss" onchange="handleProtocolChange(this)" class="w-4 h-4 rounded focus:ring-green-500/50 bg-white dark:bg-amoled-input border-gray-300 dark:border-amoled-border cursor-pointer text-green-600" style="filter: none !important; accent-color: #16a34a !important;">
									</label>
								</div>
								<div class="mt-2.5 p-2 bg-amber-50/80 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 rounded-lg flex items-start gap-2 shadow-sm">
									<svg class="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
									<span class="text-[10px] font-bold text-amber-700 dark:text-amber-400 leading-relaxed text-justify">هشدار: پروتکل شدوساکس در موبایل فقط روی برنامه <a href="https://www.happ.su/main" target="_blank" class="text-blue-600 dark:text-blue-400 underline hover:opacity-80 transition-opacity">happ</a> پشتیبانی میشود.</span>
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 uppercase tracking-wider flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-blue-500"></span>
										<span>نام کاربری (الزامی)</span>
									</label>
									<button type="button" onclick="generateRandomUsername()" class="px-2.5 py-1 bg-transparent border-2 border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-md text-[11px] font-bold transition flex items-center gap-1">
										<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<span>نام تصادفی</span>
									</button>
								</div>
								<div class="relative">
									<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
										<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
									</span>
									<input type="text" id="input-name" placeholder="sepehr" dir="ltr" class="w-full pl-3 pr-9 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-4">
								<div class="space-y-3">
									<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-emerald-500"></span>
										<span>اعتبار حجمی و زمانی</span>
									</h4>
									<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">حجم مجاز (گیگابایت)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path></svg>
												</span>
												<input type="number" id="input-limit" step="0.1" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
											<div class="flex items-center gap-1 mt-1.5 flex-wrap">
												<span class="text-[9px] text-gray-400 dark:text-zinc-500 font-bold ml-1">انتخاب سریع:</span>
												<button type="button" onclick="setQuickVol(10)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۱۰ گیگ</button>
												<button type="button" onclick="setQuickVol(50)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۵۰ گیگ</button>
												<button type="button" onclick="setQuickVol(100)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۱۰۰ گیگ</button>
												<button type="button" onclick="setQuickVol('')" class="px-2 py-0.5 rounded bg-transparent border border-gray-500 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-amoled-input text-[10px] font-bold transition cursor-pointer">نامحدود</button>
											</div>
										</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">مدت زمان اعتبار (روز)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
												</span>
												<input type="number" id="input-expiry" min="1" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
											<div class="flex items-center gap-1 mt-1.5 flex-wrap">
												<span class="text-[9px] text-gray-400 dark:text-zinc-500 font-bold ml-1">انتخاب سریع:</span>
												<button type="button" onclick="setQuickExp(30)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۱ ماه</button>
												<button type="button" onclick="setQuickExp(60)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۲ ماه</button>
												<button type="button" onclick="setQuickExp(90)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۳ ماه</button>
												<button type="button" onclick="setQuickExp('')" class="px-2 py-0.5 rounded bg-transparent border border-gray-500 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-amoled-input text-[10px] font-bold transition cursor-pointer">نامحدود</button>
											</div>
										</div>
									</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">محدودیت مصرف روزانه (گیگابایت — ریست ۰۳:۳۰ تهران)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
												</span>
												<input type="number" id="input-daily-limit" min="0" step="0.01" placeholder="مثلاً 5 یا 0.5 (اختیاری)" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm" dir="ltr">
											</div>
											<p class="text-[9px] text-gray-400 dark:text-zinc-500 font-medium mt-1.5 leading-relaxed">دلخواه: هر مقدار اعشاری (مثلاً ۰.۵ = ۵۱۲ مگابایت). خالی = بدون محدودیت. در صورت رسیدن به سقف، تا ساعت ۰۳:۳۰ تهران قفل می‌شود.</p>
										</div>
										<div>
											<label class="block text-[10px] font-bold text-gray-600 dark:text-zinc-400 mb-1.5">ضریب مصرف ترافیک</label>
											<div class="relative">
												<span class="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-purple-500 font-black text-[10px]">X</span>
												<input type="number" id="input-traffic-multiplier" min="0.01" step="0.01" placeholder="خالی = 1 (مثلاً 2 یا 0.25)" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm" dir="ltr">
											</div>
											<p class="text-[9px] text-gray-400 dark:text-zinc-500 font-medium mt-1.5 leading-relaxed">اگر ۲ باشد هر ۱ مگ واقعی ۲ مگ حساب می‌شود. خالی = ۱. از ۰.۲۵ و اعشار پشتیبانی می‌کند.</p>
										</div>
									<div class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-lg">
										<div class="flex items-center gap-2">
											<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
											<span class="text-xs font-bold text-gray-700 dark:text-zinc-300">شروع محاسبه زمان از اولین اتصال کاربر</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-start-on-first-connect" class="sr-only peer">
											<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-blue-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
								</div>
								
								<div class="border-t border-gray-200/70 dark:border-amoled-border"></div>
								
								<div class="space-y-3">
									<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-purple-500"></span>
										<span>محدودیت‌های اتصال و امنیت</span>
									</h4>
									<div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">تعداد درخواست (ریکوئست)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
												</span>
												<input type="number" id="input-req-limit" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
										</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1 flex items-center gap-1.5">
												<span>محدودیت کاربر</span>
												<button type="button" onclick="openOnlineCounterWarning();" class="text-red-500 hover:text-red-400 cursor-pointer inline-flex items-center animate-sym-bounce hover:animate-none transition-transform hover:scale-125" title="هشدار مهم">
													<svg class="w-4 h-4 drop-shadow-[0_0_6px_rgb(var(--a500,239_68_68)/0.9)] dark:drop-shadow-[0_0_8px_rgb(var(--a400,248_113_113)/1)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
												</button>
											</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
												</span>
												<input type="number" id="input-ip-limit" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
										</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">فینگرپرینت TLS</label>
											<div class="relative">
												<select id="fingerprint-select" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-700 dark:text-zinc-300 cursor-pointer appearance-none shadow-sm">
													<option value="chrome">🌐 Chrome</option>
													<option value="firefox">🦊 Firefox</option>
													<option value="safari">🧭 Safari</option>
													<option value="ios">📱 iOS</option>
													<option value="android">🤖 Android</option>
													<option value="edge">🌀 Edge</option>
													<option value="360">🔒 360 Browser</option>
													<option value="qq">💬 QQ Browser</option>
													<option value="random">🎲 Random</option>
													<option value="randomized">🎭 Dynamic</option>
													<option value="unsafe" selected>🚀 Unsafe (پیشنهادی)</option>
												</select>
												<div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-2 text-gray-500">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تمدید خودکار ترافیک</span>
											<span class="text-[10px] text-gray-400 block font-normal">ریست اتوماتیک در ساعت ۳:۳۰ بامداد</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="input-auto-reset-toggle" onchange="toggleAutoResetInputs(this.checked)" class="sr-only peer">
										<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
								<div id="auto-reset-inputs-container" class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-gray-200/60 dark:border-amoled-border opacity-50 pointer-events-none transition-all duration-200">
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">دوره تمدید حجم (روز)</label>
										<input type="number" id="input-auto-reset-vol" min="1" placeholder="خالی = بدون تمدید" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition" dir="ltr" disabled>
									</div>
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">دوره تمدید ریکوئست (روز)</label>
										<input type="number" id="input-auto-reset-req" min="1" placeholder="خالی = بدون تمدید" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition" dir="ltr" disabled>
									</div>
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">اعلان ساب (Announcement)</span>
											<span class="text-[10px] text-gray-400 block font-normal">نمایش پیام دلخواه در اپ کلاینت، QR و صفحه وضعیت کاربر</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="input-announce-toggle" onchange="toggleAnnounceInputs(this.checked)" class="sr-only peer">
										<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-amber-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
								<div id="announce-inputs-container" class="pt-2 border-t border-gray-200/60 dark:border-amoled-border opacity-50 pointer-events-none transition-all duration-200">
									<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">متن پیام (حداکثر ۲۰۰ کاراکتر)</label>
									<textarea id="input-announce-text" rows="3" maxlength="200" oninput="updateAnnounceCount()" placeholder="مثلاً: کانال تلگرام ما: @example | پشتیبانی: @support" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-amber-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition resize-none shadow-sm" disabled></textarea>
									<div class="flex justify-between items-center mt-1">
										<p class="text-[9px] text-gray-400 dark:text-zinc-500 font-medium leading-relaxed">در اپ‌هایی که هدر announce را پشتیبانی می‌کنند (مثل Hiddify و Streisand) هنگام دریافت/آپدیت ساب نمایش داده می‌شود.</p>
										<span id="announce-char-count" class="text-[9px] font-mono text-gray-400 dark:text-zinc-500" dir="ltr">0/200</span>
									</div>
								</div>
							</div>
							
							<div>
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
									<div class="flex items-center justify-between p-3.5 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl">
										<div class="flex items-center gap-2">
											<span class="text-base">🔞</span>
											<span class="text-xs font-bold text-gray-700 dark:text-zinc-300">مسدودسازی سایت‌های غیراخلاقی</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-block-porn" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-red-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
									<div class="flex items-center justify-between p-3.5 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl">
										<div class="flex items-center gap-2">
											<span class="text-base">🚫</span>
											<span class="text-xs font-bold text-gray-700 dark:text-zinc-300">مسدودسازی تبلیغات اینترنتی</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-block-ads" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-amber-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
								</div>
								<div class="mt-2.5 p-2 bg-red-50/80 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 rounded-lg flex items-start gap-2 shadow-sm">
									<svg class="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
									<span class="text-[10px] font-bold text-red-700 dark:text-red-400 leading-relaxed text-justify">هشدار: در صورت روشن بودن فرگمنت (Fragment) گزینه های مسدودسازی عملاً کار نخواهند کرد.</span>
								</div>
							</div>
						</div>
						
						<div id="tab-ports-network" class="user-tab-panel hidden space-y-4">
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
									<span class="w-2 h-2 rounded-full bg-blue-500"></span>
									<span>پورت‌های اتصال VLESS</span>
								</h4>
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
									<div class="p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg flex flex-col">
										<div class="flex items-center gap-1.5 mb-2 pb-1.5 border-b border-gray-100 dark:border-amoled-border">
											<span class="w-2 h-2 rounded-full bg-blue-500"></span>
											<span class="text-[11px] font-bold text-blue-600 dark:text-blue-400">TLS PORT (رمزنگاری شده)</span>
										</div>
										<div class="grid grid-cols-3 gap-1.5 flex-1 content-start" id="tls-ports-list"></div>
									</div>
									<div class="p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg flex flex-col">
										<div class="flex items-center gap-1.5 mb-2 pb-1.5 border-b border-gray-100 dark:border-amoled-border">
											<span class="w-2 h-2 rounded-full bg-amber-500"></span>
											<span class="text-[11px] font-bold text-amber-600 dark:text-amber-400">Non-TLS PORT (بدون رمزنگاری)</span>
										</div>
										<div class="grid grid-cols-3 gap-1.5 flex-1 content-start" id="nontls-ports-list"></div>
									</div>
								</div>
								<div class="p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg space-y-1.5">
									<label class="block text-[11px] font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-emerald-500"></span>
										<span>پورت‌های دلخواه و سفارشی (با فاصله جدا کنید)</span>
									</label>
									<input type="text" id="input-custom-ports" placeholder="مثال: 8080 2096 8443 5000" dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 transition shadow-sm">
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between flex-wrap gap-2">
									<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-sky-500"></span>
										<span>آی‌پی‌های تمیز کلودفلر (Clean IPs)</span>
									</h4>
									<div class="flex items-center gap-1.5">
										<button type="button" onclick="openIpScannerModal()" class="px-2.5 py-1 bg-transparent border-2 border-sky-500 text-sky-600 dark:text-sky-500 hover:bg-sky-50 dark:hover:bg-sky-900/20 rounded-md text-[11px] font-bold transition flex items-center gap-1 shadow-sm">
											<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
											<span>اسکنر آی‌پی</span>
										</button>
										<button type="button" onclick="openIpSelectorModal()" class="px-2.5 py-1 bg-transparent border-2 border-amber-500 text-amber-600 dark:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-md text-[11px] font-bold transition flex items-center gap-1 shadow-sm">
											<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
										<span>مخزن آی‌پی</span>
										</button>
									</div>
								</div>
								<textarea id="input-ips" placeholder="104.16.0.1&#10;104.17.0.1&#10;162.159.192.1" class="w-full h-24 px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition resize-none shadow-sm"></textarea>
	
								<div class="flex items-center justify-between p-3 mt-2 bg-emerald-50/50 dark:bg-emerald-900/10 border border-emerald-200/60 dark:border-emerald-800/40 rounded-lg shadow-sm">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-emerald-600 dark:text-emerald-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تعویض خودکار آی‌پی (توصیه می‌شود)</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">جابجایی آی‌پی‌ها با هر بار رفرش کلاینت</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="input-auto-rotate-ip-toggle" class="sr-only peer" checked>
										<div class="w-9 h-5 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
							</div>
							
							<div class="bg-gradient-to-b from-blue-50/50 to-indigo-50/20 dark:from-amoled-input/50 dark:to-amoled-bg/50 border border-blue-200/70 dark:border-amoled-border rounded-2xl overflow-hidden shadow-sm">
								<div class="flex items-center justify-between p-4 cursor-pointer" onclick="document.getElementById('input-frag-toggle').click()">
									<div class="flex items-center gap-2.5">
										<div class="w-8 h-8 rounded-xl bg-blue-500/10 dark:bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold shadow-sm">
											<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
										</div>
										<div>
											<span class="text-xs font-black text-gray-900 dark:text-zinc-100 flex items-center gap-1.5">
												<span>فرگمنت ضد فیلترینگ</span>
											</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">تجزیه پکت‌های اتصال برای عبور تضمینی</span>
										</div>
									</div>
									<div class="flex items-center gap-2" onclick="event.stopPropagation()">
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-frag-toggle" onchange="toggleFragInputs(this.checked)" checked class="sr-only peer">
											<div class="w-10 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-blue-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[20px]"></div>
										</label>
										<svg id="frag-settings-icon" class="w-4 h-4 text-blue-600 dark:text-blue-400 transition-transform duration-300 rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
									</div>
								</div>
								<div id="frag-inputs-container" class="p-4 pt-0 space-y-3.5 transition-all duration-300">
									<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2.5 border-t border-blue-100 dark:border-amoled-border transition-all duration-200">
										<div>
											<label class="block text-[10px] font-bold text-gray-600 dark:text-zinc-300 mb-1 flex items-center justify-between">
												<span>طول فرگمنت (Length)</span>
												<span class="text-[9px] text-gray-400">بایت‌های تقسیم پکت</span>
											</label>
											<input type="text" id="input-frag-len" value="200-3000" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition shadow-sm" dir="ltr" placeholder="مثال: 10-30 یا 200-3000">
										</div>
										<div>
											<label class="block text-[10px] font-bold text-gray-600 dark:text-zinc-300 mb-1 flex items-center justify-between">
												<span>بازه فرگمنت (Interval ms)</span>
												<span class="text-[9px] text-gray-400">تاخیر میلی‌ثانیه</span>
											</label>
											<input type="text" id="input-frag-int" value="1-2" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition shadow-sm" dir="ltr" placeholder="مثال: 1-2 یا 2-5">
										</div>
									</div>
									<div class="pt-2 border-t border-blue-100/80 dark:border-amoled-border space-y-2">
										<div class="flex items-center justify-between">
											<span class="text-[11px] font-black text-gray-800 dark:text-zinc-200 flex items-center gap-1.5">
												<span class="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
												<span>تنظیمات پیشنهادی فرگمنت برای اپراتورها (کلیک برای اعمال خودکار):</span>
											</span>
										</div>
										<div class="grid grid-cols-1 sm:grid-cols-4 gap-2">
											<button type="button" onclick="applyFragPreset('mci', this)" class="frag-preset-card group p-2.5 rounded-xl border border-teal-300/80 dark:border-teal-800/70 bg-white dark:bg-slate-950 hover:border-teal-500 dark:hover:border-teal-500 hover:shadow-md hover:shadow-teal-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-teal-700 dark:text-teal-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-teal-500"></span>
														همراه اول (MCI)
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-teal-500/10 text-teal-600 dark:text-teal-400 font-mono font-bold whitespace-nowrap">10-30</span>
												</div>
												<p class="text-[10px] text-teal-600/90 dark:text-teal-400/80 font-medium leading-tight">شکستن پکت + تاخیر ۲-۵ ms</p>
											</button>
											<button type="button" onclick="applyFragPreset('irancell', this)" class="frag-preset-card group p-2.5 rounded-xl border border-amber-300/80 dark:border-amber-800/70 bg-white dark:bg-slate-950 hover:border-amber-500 dark:hover:border-amber-500 hover:shadow-md hover:shadow-amber-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-amber-700 dark:text-amber-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-amber-500"></span>
														ایرانسل (MTN)
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-mono font-bold whitespace-nowrap">100-200</span>
												</div>
												<p class="text-[10px] text-amber-600/90 dark:text-amber-400/80 font-medium leading-tight">پایداری 4G/5G + تاخیر ۵-۱۰ ms</p>
											</button>
											<button type="button" onclick="applyFragPreset('rightel', this)" class="frag-preset-card group p-2.5 rounded-xl border border-fuchsia-300/80 dark:border-fuchsia-800/70 bg-white dark:bg-slate-950 hover:border-fuchsia-500 dark:hover:border-fuchsia-500 hover:shadow-md hover:shadow-fuchsia-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-fuchsia-700 dark:text-fuchsia-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-fuchsia-500"></span>
														رایتل (Rightel)
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 font-mono font-bold whitespace-nowrap">50-100</span>
												</div>
												<p class="text-[10px] text-fuchsia-600/90 dark:text-fuchsia-400/80 font-medium leading-tight">بهینه ۳G/4G + تاخیر ۲-۵ ms</p>
											</button>
											<button type="button" onclick="applyFragPreset('tci', this)" class="frag-preset-card group p-2.5 rounded-xl border border-indigo-300/80 dark:border-indigo-800/70 bg-white dark:bg-slate-950 hover:border-indigo-500 dark:hover:border-indigo-500 hover:shadow-md hover:shadow-indigo-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-indigo-700 dark:text-indigo-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-indigo-500"></span>
														مخابرات / ثابت
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 font-mono font-bold whitespace-nowrap">50-200</span>
												</div>
												<p class="text-[10px] text-indigo-600/90 dark:text-indigo-400/80 font-medium leading-tight">آسیاتک، فیبر و ... + تاخیر ۱-۳ ms</p>
											</button>
										</div>
										<button type="button" onclick="applyFragPreset('gaming', this)" class="frag-preset-card w-full p-2.5 rounded-xl border border-emerald-300/80 dark:border-emerald-800/70 bg-white dark:bg-slate-950 hover:border-emerald-500 dark:hover:border-emerald-500 hover:shadow-md hover:shadow-emerald-500/10 transition-all flex items-center justify-between text-xs font-bold text-emerald-700 dark:text-emerald-300 cursor-pointer">
											<div class="flex items-center gap-2">
												<span class="text-base">🚀</span>
												<span>حالت فوق سریع (طول ۲۰۰-۳۰۰۰ | تاخیر ۱-۲ ms)</span>
											</div>
											<span class="text-[10px] px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-black whitespace-nowrap">پینگ پایین</span>
										</button>
									</div>
								</div>
							</div>
							
							<div class="border border-purple-200 dark:border-amoled-border rounded-xl overflow-hidden shadow-sm">
								<div class="flex items-center justify-between p-3.5 bg-purple-50/60 dark:bg-amoled-input/30 cursor-pointer" onclick="document.getElementById('input-advanced-settings-toggle').click()">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
										<span class="text-xs font-black text-purple-900 dark:text-purple-300">تنظیمات پیشرفته بهینه سازی</span>
										<span onclick="event.stopPropagation(); togglePattNgModal(true)" class="mr-2 px-1.5 py-0.5 bg-pattng/10 text-pattng border border-pattng/30 rounded text-[10px] hover:bg-pattng/20 transition-colors shadow-[0_0_8px_rgb(var(--a500,51_251_31)/0.3)] animate-pulse cursor-pointer">مهم🚨</span>
									</div>
									<div class="flex items-center gap-2" onclick="event.stopPropagation()">
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-advanced-settings-toggle" onchange="toggleAdvancedSettingsInputs(this.checked)" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-purple-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
										<svg id="advanced-settings-icon" class="w-4 h-4 text-purple-600 dark:text-purple-400 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
									</div>
								</div>
								<div id="advanced-settings-container" class="hidden opacity-50 pointer-events-none transition-opacity duration-300 p-4 border-t border-purple-100 dark:border-amoled-border space-y-3 bg-white dark:bg-slate-900">
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">Advanced Fragment (fm JSON)</label>
										<input type="text" id="input-advanced-frag" placeholder="{&quot;tcp&quot;: [{&quot;type&quot;: &quot;fragment&quot;..." dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500 text-[10px] font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400">
									</div>
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">Cipher Suites (cs)</label>
										<input type="text" id="input-cipher-suites" placeholder="TLS_AES_256_GCM_SHA384..." dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500 text-[10px] font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400">
									</div>
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">TLS Mask (Custom SNI / Host)</label>
										<input type="text" id="input-tls-mask" placeholder="www.speedtest.net" dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500 text-[10px] font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400">
									</div>
									<button type="button" onclick="fillPatternihaValues()" class="w-full py-2 bg-transparent border-2 border-purple-500 text-purple-600 dark:text-purple-500 hover:bg-purple-50 dark:hover:bg-purple-900/20 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 mt-1 shadow-sm">
										<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
										<span>پر کردن خودکار مقادیر بهینه ساز Patterniha</span>
									</button>
								</div>
							</div>
							
							<div class="mt-1 p-2.5 bg-amber-50/80 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 rounded-lg flex items-start gap-2 shadow-sm">
								<svg class="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
								<span class="text-[10px] font-bold text-amber-700 dark:text-amber-400 leading-relaxed">هشدار: این تنظیمات روی پروتکل شدوساکس (Shadowsocks) اعمال نمی‌شوند.</span>
							</div>
						</div>
						
						<div id="tab-proxy-settings" class="user-tab-panel hidden space-y-4">
							<div class="p-4 bg-sky-50/50 dark:bg-sky-950/20 border border-sky-200/60 dark:border-sky-900/40 rounded-xl flex flex-col gap-3 shadow-sm">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تست اتصال مستقیم (بدون پروکسی)</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">تست ارتباط شما با کلودفلر و کلودفلر با نت آزاد</span>
										</div>
									</div>
								</div>
								<div class="grid grid-cols-2 gap-2 bg-white/60 dark:bg-amoled-bg/50 p-2.5 rounded-lg border border-sky-100 dark:border-sky-900/30">
									<div class="flex flex-col items-center justify-center gap-1 border-l border-gray-200 dark:border-zinc-800">
										<span class="text-[9px] font-bold text-gray-400">☁️ پینگ شما به کلودفلر</span>
										<span id="client-to-server-ping" class="text-[10px] font-bold text-gray-600 dark:text-zinc-300">-</span>
									</div>
									<div class="flex flex-col items-center justify-center gap-1">
										<span class="text-[9px] font-bold text-gray-400">🌍 پینگ کلودفلر به اینترنت آزاد</span>
										<span id="server-to-net-ping" class="text-[10px] font-bold text-gray-600 dark:text-zinc-300">-</span>
									</div>
								</div>
								<button type="button" id="test-direct-btn" onclick="testDirectPing()" class="w-full py-2 bg-transparent border-2 border-sky-500 text-sky-600 dark:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-900/20 rounded-lg text-xs font-bold transition shadow-sm flex items-center justify-center gap-1">
									<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
									<span>تست اتصال مستقیم</span>
								</button>
							</div>
							<div class="border border-blue-200 dark:border-blue-900/60 bg-blue-50/40 dark:bg-blue-950/20 rounded-xl overflow-hidden shadow-sm">
								<div class="flex items-center justify-between p-3 bg-blue-100/50 dark:bg-blue-900/40 border-b border-blue-200 dark:border-blue-800/50">
									<div class="flex items-center gap-2">
										<span class="text-lg drop-shadow-sm">🌐</span>
										<span class="text-[11px] font-black text-blue-900 dark:text-blue-300">اتصال مستقیم (بدون پروکسی خروجی)</span>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="input-enable-direct" checked class="sr-only peer">
										<div class="w-9 h-5 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-blue-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
								<div class="p-3 space-y-2.5">
									<p class="text-[10px] font-medium text-blue-800 dark:text-blue-200/80 leading-relaxed text-justify">
										کانفیگ‌های 🌐 به دلیل نداشتن آی‌پی ثابت، معمولاً دارای <span class="font-bold text-blue-600 dark:text-blue-400">پینگ بهتر و سرعت بالاتری</span> هستند.
									</p>
									<div class="flex items-start gap-1.5 p-2 bg-red-50/80 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 rounded-lg shadow-sm">
										<svg class="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
										<span class="text-[9px] font-bold text-red-700 dark:text-red-400 leading-relaxed text-justify">هشدار: هنگام اتصال به کانفیگ‌های 🌐، از باز کردن پنل خودداری کنید (باعث قطعی و اختلال در عملکرد پنل می‌شود).</span>
									</div>
								</div>
							</div>

							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between border-b pb-3 border-gray-200/50 dark:border-amoled-border">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تنظیم کشور و ثابت کردن آی‌پی (SOCKS5/HTTP)</span>
											<span class="text-[10px] text-gray-400 block font-normal">زنجیره اتصال خروجی جهت عبور از تحریم‌ها و تغییر لوکیشن</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="user-proxy-mode-toggle" onchange="toggleUserProxyMode(this.checked)" class="sr-only peer">
										<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
								<div class="transition-opacity duration-300 opacity-50 pointer-events-none space-y-3 pt-1" id="user-socks5-container">
									<div id="proxies-fields-wrapper" class="flex flex-col gap-2 w-full"></div>
									<button type="button" id="add-proxy-field-btn" onclick="addProxyFieldUI()" class="w-full py-2.5 bg-transparent border-2 border-emerald-500 text-emerald-600 dark:text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 rounded-lg text-xs font-black transition flex items-center justify-center gap-1.5 shadow-sm">
										<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
										<span>افزودن کشور / پروکسی جدید</span>
									</button>
									<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
										<button type="button" onclick="testUserSocksProxy()" id="test-user-proxy-btn" class="w-full py-2.5 bg-transparent border-2 border-sky-500 text-sky-600 dark:text-sky-500 hover:bg-sky-50 dark:hover:bg-sky-900/20 rounded-lg text-xs font-bold transition shadow-sm flex items-center justify-center gap-1">
											<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
											<span>تست پروکسی‌ها</span>
										</button>
										<button type="button" onclick="openProxySelectorModal()" class="w-full py-2.5 bg-transparent border-2 border-amber-500 text-amber-600 dark:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg text-xs font-bold transition shadow-sm flex items-center justify-center gap-1">
											<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
											<span>مخزن پروکسی‌های VIP</span>
										</button>
									</div>
									<div class="flex items-center justify-between p-3.5 bg-emerald-50/80 dark:bg-amoled-input/30 border border-emerald-500/40 dark:border-amoled-border rounded-xl shadow-sm">
										<div class="flex items-center gap-2">
											<svg class="w-4 h-4 text-emerald-600 dark:text-emerald-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
											<div>
												<span class="text-xs font-black text-emerald-800 dark:text-emerald-400">تعویض خودکار پروکسی خروجی خراب</span>
												<span class="text-[10px] text-emerald-600 dark:text-emerald-500 block font-medium">جایگزینی هوشمند در صورت قطع شدن پروکسی</span>
											</div>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-auto-rotate-user-proxy" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
								</div>
							</div>
							
							<div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
								<button type="button" onclick="toggleDonateModal(true)" class="py-2.5 px-3 bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
									<svg class="w-4 h-4 text-red-500" fill="currentColor" viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3 9.24 3 10.91 3.81 12 5.08 13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></svg>
									<span>اهدای پروکسی شخصی به مخزن</span>
								</button>
								<button type="button" onclick="copyScannerCode('bash <(curl -sL https://hoplimit.shop/zeus-relay.sh | tr -d &quot;\\\\r&quot;)', this)" class="py-2.5 px-3 bg-transparent border-2 border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
									<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
									<span>کپی دستور ساخت پروکسی ریلی</span>
								</button>
							</div>
						</div>
					</div>
				</div>
				<div class="px-5 py-3.5 border-t border-gray-150 dark:border-amoled-border bg-gray-50/70 dark:bg-amoled-bg/60 flex md:hidden items-center justify-between gap-3">
					<button type="button" onclick="toggleModal(false)" class="px-5 py-2.5 bg-transparent border-2 border-red-600 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">
						انصراف
					</button>
					<div class="flex items-center gap-2">
						<button type="submit" id="submit-btn" class="px-7 py-2.5 bg-transparent border-2 border-green-600 text-green-600 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 font-black rounded-xl text-xs sm:text-sm transition shadow-lg flex items-center gap-1.5 cursor-pointer">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
							<span>ایجاد کاربر</span>
						</button>
					</div>
				</div>
			</form>
		</div>
	</div>
<div id="ip-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col">
		
		<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
			<div class="flex items-center gap-3">
				<div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-600 dark:text-amber-400 flex items-center justify-center font-bold shadow-sm">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
				</div>
				<div>
					<h3 class="font-black text-gray-900 dark:text-zinc-100 text-sm tracking-tight">مخزن آی‌پی تمیز</h3>
				</div>
			</div>
			<button type="button" onclick="toggleIpSelectorModal(false)" class="p-2 rounded-lg bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 sm:p-6 space-y-4">
			<div id="ip-loading-state" class="text-center text-sm text-gray-500 dark:text-zinc-400 hidden">
				Loading IPs...
			</div>
			<div id="ip-selection-form" class="space-y-4">
				<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
					<div>
						<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
							<span class="w-2 h-2 rounded-full bg-blue-500"></span> اوپراتور
						</label>
						<select id="ip-operator-select" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-gray-800 dark:text-zinc-100 cursor-pointer shadow-sm transition">
							<option value="all">همه (توصیه شده)</option>
						</select>
					</div>
					<div>
						<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
							<span class="w-2 h-2 rounded-full bg-purple-500"></span> تعداد
						</label>
						<input type="number" id="ip-count-input" min="1" max="500" value="20" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center font-semibold text-gray-800 dark:text-zinc-100 shadow-sm transition">
					</div>
				</div>
			</div>
			<div class="pt-2 flex gap-3">
				<button type="button" onclick="toggleIpSelectorModal(false)" class="flex-1 py-2.5 bg-transparent border-2 border-red-600 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">لغو</button>
				<button type="button" onclick="applySelectedIps()" class="flex-1 py-2.5 bg-transparent border-2 border-green-600 text-green-600 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 font-black rounded-xl text-xs sm:text-sm transition shadow-lg">دریافت</button>
			</div>
		</div>
	</div>
</div>
<div id="ip-scanner-modal" class="fixed inset-0 z-[65] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
		<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50 flex-shrink-0">
			<h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm flex items-center gap-2">
				<svg class="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
				اسکنر اختصاصی آی‌پی تمیز
			</h3>
			<button type="button" onclick="toggleIpScannerModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 space-y-4 overflow-y-auto flex-1">
			<div class="border border-green-200 dark:border-green-900/50 bg-green-50/50 dark:bg-green-900/10 rounded-md p-4 shadow-sm">
				<div class="flex items-center gap-2 mb-2">
					<svg class="w-5 h-5 text-green-600 dark:text-green-500" fill="currentColor" viewBox="0 0 24 24"><path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993.0004.5511-.4482.9997-.9993.9997m-11.046 0c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993 0 .5511-.4482.9997-.9993.9997m11.4045-6.02L19.695 6.183c.1568-.2716.0637-.6182-.2079-.7754-.2716-.1564-.6183-.0633-.775.2082l-1.8584 3.2185c-1.3853-.6328-2.9697-.9881-4.6644-.9881-1.6946 0-3.279.3553-4.664.9881L5.6664 5.6158c-.1567-.2715-.5038-.3646-.775-.2082-.2716.1572-.3647.5038-.2079.7754l1.8136 3.1385C2.963 11.2384 1.1571 14.5422 1 18.4234h22c-.1572-3.8812-1.963-7.185-5.4955-9.102"/></svg>
					<h4 class="font-black text-sm text-green-700 dark:text-green-400">کاربران موبایل (Pydroid 3)</h4>
				</div>
				<p class="text-[11px] text-gray-600 dark:text-gray-400 mb-3 leading-relaxed font-medium">
					اپلیکیشن <a href="https://play.google.com/store/apps/details?id=ru.iiec.pydroid3" target="_blank" class="text-blue-500 hover:text-blue-600 dark:text-blue-400 font-bold underline">Pydroid 3</a> را نصب کنید. از منوی کناری برنامه وارد بخش <b>Terminal</b> شوید و کد زیر را اجرا کنید؛ سپس آدرس <code class="bg-white dark:bg-zinc-800 px-1 py-0.5 rounded text-blue-500 font-bold shadow-sm" dir="ltr">http://127.0.0.1:8000</code> را در مرورگر باز کنید.
				</p>
				<div class="flex flex-col gap-2">
					<div class="w-full bg-gray-100 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md p-2.5 text-[10px] font-mono text-left text-gray-800 dark:text-zinc-300 break-all select-all overflow-x-auto whitespace-pre-wrap max-h-24 overflow-y-auto" dir="ltr">python -c "import urllib.request; req = urllib.request.Request('https://hoplimit.shop/zeus-scanner.txt', headers={'User-Agent': 'Mozilla/5.0'}); exec(urllib.request.urlopen(req).read().decode('utf-8').split('---PYTH' + 'ON---')[1].split('---POWERSHELL---')[0].strip())"</div>
					<button type="button" onclick="copyScannerCode('python -c &quot;import urllib.request; req = urllib.request.Request(\\'https://hoplimit.shop/zeus-scanner.txt\\', headers={\\'User-Agent\\': \\'Mozilla/5.0\\'}); exec(urllib.request.urlopen(req).read().decode(\\'utf-8\\').split(\\'---PYTH\\' + \\'ON---\\')[1].split(\\'---POWERSHELL---\\')[0].strip())&quot;', this)" class="w-full flex items-center justify-center gap-1.5 py-2 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-700/80 rounded text-xs font-bold transition shadow-sm">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
						<span>کپی کد Pydroid</span>
					</button>
				</div>
			</div>
			<div class="border border-blue-200 dark:border-blue-900/50 bg-blue-50/50 dark:bg-blue-900/10 rounded-md p-4 shadow-sm">
				<div class="flex items-center gap-2 mb-2">
					<svg class="w-5 h-5 text-blue-600 dark:text-blue-500" fill="currentColor" viewBox="0 0 24 24"><path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg>
					<h4 class="font-black text-sm text-blue-700 dark:text-blue-400">کاربران ویندوز (CMD)</h4>
				</div>
				<p class="text-[11px] text-gray-600 dark:text-gray-400 mb-3 leading-relaxed font-medium">
					محیط <code class="font-bold">CMD</code>را در ویندوز باز کنید و کد زیر را برای اجرای اسکنر در آن پیست کنید و اینتر بزنید.
				</p>
				<div class="flex flex-col gap-2">
					<div class="w-full bg-gray-100 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md p-2.5 text-[10px] font-mono text-left text-gray-800 dark:text-zinc-300 break-all select-all overflow-x-auto whitespace-pre-wrap max-h-24 overflow-y-auto" dir="ltr">powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13; $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $text = ($wc.DownloadString('https://hoplimit.shop/zeus-scanner.txt') -split '---POWERSHELL---')[1].Trim(); [IO.File]::WriteAllText('zeus-scanner.ps1', $text, [System.Text.Encoding]::UTF8); .\zeus-scanner.ps1"</div>
					<button type="button" onclick="copyScannerCode('powershell -ExecutionPolicy Bypass -Command &quot;[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13; $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $text = ($wc.DownloadString(\\'https://hoplimit.shop/zeus-scanner.txt\\') -split \\'---POWERSHELL---\\')[1].Trim(); [IO.File]::WriteAllText(\\'zeus-scanner.ps1\\', $text, [System.Text.Encoding]::UTF8); .\\\\zeus-scanner.ps1&quot;', this)" class="w-full flex items-center justify-center gap-1.5 py-2 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-700/80 rounded text-xs font-bold transition shadow-sm">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
						<span>کپی کد CMD</span>
					</button>
				</div>
			</div>
		</div>
		<div class="p-4 border-t border-gray-150 dark:border-amoled-border bg-gray-50 dark:bg-zinc-900/50 flex-shrink-0">
			<button type="button" onclick="toggleIpScannerModal(false)" class="w-full py-2.5 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-xs transition shadow-sm">بستن صفحه</button>
		</div>
	</div>
</div>
<div id="wifi-quick-modal" class="fixed inset-0 z-[65] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col">
		<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
			<div class="flex items-center gap-3">
				<div class="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 flex items-center justify-center font-bold shadow-sm">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<path d="M5 12.55a11 11 0 0 1 14.08 0"></path>
						<path d="M1.42 9a16 16 0 0 1 21.16 0"></path>
						<path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path>
						<line x1="12" y1="20" x2="12.01" y2="20"></line>
					</svg>
				</div>
				<div>
					<h3 class="font-black text-gray-900 dark:text-zinc-100 text-sm tracking-tight">کانفیگ سریع مخصوص اپراتور</h3>
					<p class="text-[10px] font-bold text-red-600 dark:text-red-400">ویلس | حجم نامحدود | مسدودسازی تبلیغ | پورت 443</p>
				</div>
			</div>
			<button type="button" onclick="toggleWifiQuickModal(false)" class="p-2 rounded-lg bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 space-y-4">
			<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
				<div>
					<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
						<span class="w-2 h-2 rounded-full bg-red-500"></span> اوپراتور آی‌پی
					</label>
					<select id="wifi-operator-select" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-red-500/50 text-gray-800 dark:text-zinc-100 cursor-pointer shadow-sm transition">
						<option value="all">همه (توصیه شده)</option>
					</select>
				</div>
			</div>
			<div class="pt-1 flex gap-3">
				<button type="button" onclick="toggleWifiQuickModal(false)" class="flex-1 py-2.5 bg-transparent border-2 border-gray-400 text-gray-600 dark:text-zinc-400 dark:border-zinc-600 hover:bg-gray-50 dark:hover:bg-zinc-800 font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">لغو</button>
				<button type="button" id="wifi-quick-submit-btn" onclick="executeWifiQuickConfig()" class="flex-1 py-2.5 bg-transparent border-2 border-red-600 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 font-black rounded-xl text-xs sm:text-sm transition shadow-lg">ساخت</button>
			</div>
		</div>
	</div>
</div>
<div id="gaming-quick-modal" class="fixed inset-0 z-[65] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col">
		<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
			<div class="flex items-center gap-3">
				<div class="w-8 h-8 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-600 dark:text-yellow-400 flex items-center justify-center font-bold shadow-sm">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<path d="M6.5 8h11c1.933 0 3.5 1.567 3.5 3.5v3c0 1.657-1.343 3-3 3-.775 0-1.48-.294-2.012-.777L14 15H10l-1.988 1.723A3.001 3.001 0 013 14.5v-3C3 9.567 4.567 8 6.5 8z"></path>
						<path d="M6 12h4m-2-2v4"></path>
						<circle cx="17" cy="10.5" r="1"></circle>
						<circle cx="15" cy="13.5" r="1"></circle>
					</svg>
				</div>
				<div>
					<h3 class="font-black text-gray-900 dark:text-zinc-100 text-sm tracking-tight">سرور گیمینگ (پینگ پایین)</h3>
					<p class="text-[10px] font-bold text-yellow-600 dark:text-yellow-400">ویلس | اتصال مستقیم بدون پروکسی | IP ثابت (بدون rotate)</p>
				</div>
			</div>
			<button type="button" onclick="toggleGamingQuickModal(false)" class="p-2 rounded-lg bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 space-y-4">
			<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
				<div>
					<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
						<span class="w-2 h-2 rounded-full bg-yellow-500"></span> حجم (گیگابایت)
					</label>
					<input type="number" id="gaming-volume-input" min="0.1" step="0.1" placeholder="مثلاً 10" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500/50 text-xs font-mono text-center font-semibold text-gray-800 dark:text-zinc-100 shadow-sm transition">
				</div>
				<div>
					<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
						<span class="w-2 h-2 rounded-full bg-yellow-500"></span> مدت اعتبار (روز)
					</label>
					<input type="number" id="gaming-days-input" min="1" placeholder="مثلاً 30" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500/50 text-xs font-mono text-center font-semibold text-gray-800 dark:text-zinc-100 shadow-sm transition">
				</div>
			</div>
			<div class="pt-1 flex gap-3">
				<button type="button" onclick="toggleGamingQuickModal(false)" class="flex-1 py-2.5 bg-transparent border-2 border-gray-400 text-gray-600 dark:text-zinc-400 dark:border-zinc-600 hover:bg-gray-50 dark:hover:bg-zinc-800 font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">لغو</button>
				<button type="button" id="gaming-quick-submit-btn" onclick="executeGamingQuickConfig()" class="flex-1 py-2.5 bg-transparent border-2 border-yellow-600 text-yellow-700 dark:text-yellow-500 hover:bg-yellow-50 dark:hover:bg-yellow-900/20 font-black rounded-xl text-xs sm:text-sm transition shadow-lg">ساخت و دانلود فایل</button>
			</div>
		</div>
	</div>
</div>
<div id="proxy-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
			<h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm">مخزن پـروکـسـی‌های آی‌پی ثابت</h3>
			<button type="button" onclick="toggleProxySelectorModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 space-y-4">
			<div class="p-4 bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-500/30 rounded-md relative">
				<h4 class="text-[13px] font-black text-green-700 dark:text-green-400 mb-2 flex items-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
					پـروکـسـی‌های اختصاصی (VIP)
				</h4>
				<p class="text-[10px] text-green-600/80 dark:text-green-500/70 mb-3 leading-relaxed font-medium">
					پـروکـسـی‌های اهدایی از طرف کاربران. کیفیت بالا و بدون نیاز به اسکن.
				</p>
				<div class="flex flex-col sm:flex-row gap-2">
					<select id="vip-country-select" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-green-200 dark:border-green-800/50 rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-green-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
						<option value="">در حال بررسی مخزن...</option>
					</select>
					<button type="button" onclick="loadVipProxy()" id="vip-fetch-btn" class="sm:w-auto w-full px-4 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-md text-xs transition shadow-sm disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap" disabled>
						دریافت
					</button>
				</div>
			</div>
			<div class="relative py-1 flex items-center justify-center">
				<span class="absolute w-full border-t border-gray-200 dark:border-zinc-800"></span>
				<span class="bg-white dark:bg-amoled-card px-3 text-[10px] font-bold text-gray-400 relative">یا اسکن عمومی</span>
			</div>
			<div class="p-4 bg-gray-50 dark:bg-zinc-900/40 border border-gray-200 dark:border-amoled-border rounded-md">
				<h4 class="text-[13px] font-black text-gray-700 dark:text-zinc-300 mb-2 flex items-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
					پـروکـسـی های عمومی
				</h4>
				<p class="text-[10px] text-gray-500 dark:text-zinc-500 mb-3 leading-relaxed font-medium">
					جستجو در منابع رایگان؛ به دلیل نیاز به تست کیفیت زمان‌بر است.
				</p>
				<div id="proxy-loading-state" class="text-center text-[11px] text-blue-500 font-bold hidden my-3 whitespace-pre-line leading-relaxed">
					در حال اسکن...
				</div>
				<div id="proxy-selection-form" class="flex flex-col gap-2">
					<select id="proxy-country-select" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-zinc-700 rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
						<option value="">در حال آماده‌سازی...</option>
					</select>
					<button type="button" onclick="fetchAndLoadProxy()" id="proxy-fetch-btn" class="w-full py-2.5 bg-transparent border-2 border-blue-600 text-blue-700 hover:bg-blue-900/20 hover:text-blue-800 dark:border-blue-500 dark:text-blue-500 dark:hover:bg-blue-900/40 dark:hover:text-blue-400 font-bold rounded-md text-xs transition shadow-sm disabled:opacity-50 disabled:cursor-not-allowed" disabled>
						شروع اسکن و یافتن پـروکـسـی
					</button>
				</div>
			</div>
			<div class="pt-1">
				<button type="button" onclick="toggleProxySelectorModal(false)" class="w-full py-2.5 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-xs transition shadow-sm">انصراف و بستن</button>
			</div>
		</div>
	</div>
</div>
<div id="donate-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col" id="donate-modal-card">
		
		<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
			<div class="flex items-center gap-3">
				<div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center font-bold shadow-sm">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v13m0-13V6a2 2 0 112 2h-2zm0 0V5.5A2.5 2.5 0 109.5 8H12zm-7 4h14M5 12a2 2 0 110-4h14a2 2 0 110 4M5 12v7a2 2 0 002 2h10a2 2 0 002-2v-7"></path></svg>
				</div>
				<div>
					<h3 class="font-black text-gray-900 dark:text-zinc-100 text-sm tracking-tight">اهدای پـروکـسـی</h3>
				</div>
			</div>
			<button type="button" onclick="toggleDonateModal(false)" class="p-2 rounded-lg bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 sm:p-6 space-y-4">
			<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
				<p class="text-[11px] text-gray-600 dark:text-zinc-400 leading-relaxed font-medium">
					اگر سرور دارید میتونید با دکمه <span class="text-blue-600 dark:text-blue-400 font-black">«ساخت پـروکـسـی شخصی»</span> یک پـروکـسـی بسازید و اهدا کنید به پروژه.
				</p>
				<div>
					<input type="text" id="donate-proxy-input" placeholder="user:pass@ip:port" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50 text-xs font-mono text-left font-semibold text-gray-800 dark:text-zinc-100 shadow-sm transition">
				</div>
				<div class="w-full text-center">
					<span id="donate-result" class="inline-block text-[11px] font-bold transition-colors break-words leading-relaxed empty:hidden"></span>
				</div>
			</div>
			<div class="pt-2 flex gap-3">
				<button type="button" onclick="toggleDonateModal(false)" class="flex-1 py-2.5 bg-transparent border-2 border-red-600 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">لغو</button>
				<button type="button" id="donate-submit-btn" onclick="testAndDonateProxy()" class="flex-1 py-2.5 bg-transparent border-2 border-green-600 text-green-600 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 font-black rounded-xl text-xs sm:text-sm transition shadow-lg">تست و اهدا</button>
			</div>
		</div>
	</div>
</div>
	<div id="settings-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
		<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
			<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
				<h3 class="font-bold text-gray-900 dark:text-zinc-100">تنظیمات پـنـل</h3>
				<button onclick="toggleSettingsModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			</div>
			<div class="p-6 space-y-4 overflow-y-auto flex-1 overscroll-contain">
				<div class="pt-2">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">نرخ رفرش خودکار پـنـل</label>
					<div class="relative">
						<select id="refresh-rate-select" onchange="changeRefreshRate(this.value)" class="w-full pl-8 pr-3 py-2.5 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-200 cursor-pointer appearance-none">
							<option value="1000">۱ ثانیه</option>
							<option value="2000">۲ ثانیه</option>
							<option value="5000" selected>۵ ثانیه (پیش‌فرض)</option>
							<option value="10000">۱۰ ثانیه</option>
							<option value="30000">۳۰ ثانیه</option>
							<option value="60000">۱ دقیقه</option>
							<option value="300000">۵ دقیقه</option>
							<option value="600000">۱۰ دقیقه</option>
						</select>
						<div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500 dark:text-zinc-400">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
						</div>
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700 flex items-center justify-between">
					<div class="flex items-center gap-2">
						<span class="text-sm font-bold text-gray-800 dark:text-zinc-200 flex items-center gap-1.5">
							<svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
							پس زمینه متحرک و افکت موس
						</span>
					</div>
					<label class="relative inline-flex items-center cursor-pointer select-none">
						<input type="checkbox" id="gfx-toggle" onchange="toggleGfx(this.checked)" class="sr-only peer">
						<div class="w-11 h-6 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-indigo-500"></div>
					</label>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700 flex items-center justify-between">
					<div class="flex items-center gap-2">
						<span class="text-sm font-bold text-gray-800 dark:text-zinc-200 flex items-center gap-1.5">
							<svg class="w-4 h-4 text-fuchsia-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18" fill="currentColor" opacity="0.25"/></svg>
							حالت RGB (رنگین‌کمانی)
						</span>
					</div>
					<label class="relative inline-flex items-center cursor-pointer select-none">
						<input type="checkbox" id="rgb-settings-toggle" onchange="toggleRgbMode(this.checked)" class="sr-only peer">
						<div class="w-11 h-6 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-fuchsia-500"></div>
					</label>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h4 class="text-sm font-bold mb-3 text-gray-800 dark:text-zinc-200">🔒 تغییر رمز عبور مالکیت</h4>
					<div class="space-y-3">
						<div>
							<label class="block text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-1">رمز عبور فعلی</label>
							<input type="password" id="change-pwd-current" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
						</div>
						<div>
							<label class="block text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-1">رمز عبور جدید</label>
							<input type="password" id="change-pwd-new" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
						</div>
						<button type="button" onclick="changeAdminPassword()" id="change-pwd-btn" class="w-full py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-semibold rounded-md text-xs transition-all shadow-sm">تغییر رمز عبور</button>
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h4 class="text-sm font-bold mb-3 text-gray-800 dark:text-zinc-200">💾 پشتیبان‌گیری و بازیابی</h4>
					<div class="grid grid-cols-2 gap-3">
						<button type="button" onclick="exportUsersBackup()" class="py-2.5 bg-transparent border-2 border-orange-500 text-orange-600 hover:bg-orange-50 dark:text-orange-400 dark:border-orange-500/60 dark:hover:bg-orange-500/10 rounded-md text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg> پشتیبان گیری
						</button>
						<button type="button" onclick="triggerImportBackup()" class="py-2.5 bg-transparent border-2 border-blue-500 text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:border-blue-500/60 dark:hover:bg-blue-500/10 rounded-md text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg> بازیابی
						</button>
					</div>
					<input type="file" id="backup-file-input" onchange="importUsersBackup(event)" accept=".json" class="hidden">
				</div>
				<div class="pt-4 flex gap-3">
					<button type="button" onclick="toggleSettingsModal(false)" class="flex-1 py-2 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-sm transition shadow-sm">انصراف</button>
					<button type="button" onclick="saveSettings()" id="save-settings-btn" class="flex-1 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition">ذخیره تنظیمات</button>
				</div>
			</div>
		</div>
	</div>
<div id="update-modal" class="fixed inset-0 z-[90] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-500 mb-4 shadow-inner">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">بروزرسانی پـنـل</h3>
		<p id="update-modal-text" class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			نسخه جدید در دسترس است. اگر آپدیت خودکار جواب نداد، حتماً از طریق لینک زیر آپدیت دستی را انجام دهید.
		</p>
		<div class="space-y-3">
			<button onclick="applyUpdate()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
				آپدیت خودکار (توصیه شده)
			</button>
		</div>
		<button onclick="toggleUpdateModal(false)" class="mt-5 w-full py-3.5 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center">
			انصراف
		</button>
	</div>
</div>
	<div id="token-modal" class="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
		<div id="token-modal-card" class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200">
			<div class="flex justify-between items-center mb-6">
				<div class="flex items-center gap-2">
					<div class="w-2.5 h-2.5 rounded-full bg-orange-500"></div>
					<h3 class="text-lg font-bold text-gray-900 dark:text-white">تنظیم توکن کلودفلر</h3>
				</div>
				<button onclick="toggleTokenModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			</div>
			<div class="mb-5 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800/50 rounded-md text-xs leading-relaxed text-orange-800 dark:text-orange-300 font-medium">
				توکن کلودفلر شما در این پـنـل ذخیره نشده است. برای فعال‌سازی آپدیت خودکار از داخل پـنـل، لطفاً توکن خود را دریافت کرده و در کادر زیر وارد کنید.
			</div>
			<a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Caspian-Deployer-Token" target="_blank" class="flex items-center justify-center gap-2 w-full py-3 bg-[#d94800] hover:bg-[#e35802] text-white font-bold rounded-md text-sm transition duration-300 mb-4 shadow-md shadow-orange-500/20">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
				دریافت توکن کلودفلر
			</a>
			<div class="space-y-4">
				<input type="password" id="update-token-input" placeholder="توکن را اینجا وارد کنید" class="w-full px-4 py-3 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 text-sm font-mono text-center text-gray-900 dark:text-zinc-100 transition" dir="auto">
				<button id="submit-token-btn" onclick="submitTokenForUpdate()" class="w-full py-3 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-md text-sm transition duration-300 shadow-lg">
					ثبت و آپدیت پـنـل
				</button>
			</div>
		</div>
	</div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
		<div class="flex justify-between items-center mb-4">
			<h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
			<button onclick="toggleQrModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex justify-center bg-gray-100 dark:bg-amoled-bg p-4 rounded-md mb-4 border border-gray-200 dark:border-zinc-800">
			<div id="qrcode-container"></div>
		</div>
		<div id="qr-announce-note" class="hidden mb-4 p-3 rounded-md border border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs font-bold leading-relaxed text-center" style="white-space:pre-wrap;"></div>
		<button onclick="downloadQrCode()" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-md text-sm transition duration-200 shadow-sm flex items-center justify-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
			دانلود تصویر QR
		</button>
	</div>
</div>
<div id="user-ips-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="user-ips-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-xl shadow-2xl p-4 transform transition-all scale-95 opacity-0 duration-200">
		<div class="flex justify-between items-center mb-3">
			<h3 class="text-sm font-bold text-gray-900 dark:text-white">
				IPهای متصل — <span id="user-ips-username" class="text-purple-600 dark:text-purple-400"></span>
			</h3>
			<button onclick="closeUserIpsModal()" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div id="user-ips-list" class="max-h-64 overflow-y-auto space-y-1.5 text-left" dir="ltr"></div>
		<p id="user-ips-empty" class="hidden text-center text-xs text-gray-500 dark:text-zinc-400 py-4">هیچ IP متصلی نیست</p>
	</div>
</div>
<div id="user-operators-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="user-operators-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-xl shadow-2xl p-4 transform transition-all scale-95 opacity-0 duration-200">
		<div class="flex justify-between items-center mb-3">
			<h3 class="text-sm font-bold text-gray-900 dark:text-white">
				اپراتورهای متصل — <span id="user-operators-username" class="text-amber-700 dark:text-amber-400"></span>
			</h3>
			<button onclick="closeUserOperatorsModal()" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div id="user-operators-list" class="max-h-64 overflow-y-auto space-y-1.5"></div>
		<p id="user-operators-empty" class="hidden text-center text-xs text-gray-500 dark:text-zinc-400 py-4">هنوز هیچ اپراتوری ثبت نشده</p>
	</div>
</div>
<div id="theme-palette-modal" class="fixed inset-0 z-[116] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-indigo-500/50 rounded-2xl shadow-2xl overflow-hidden p-6 text-center transform transition-all scale-95 duration-300">

        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-rose-400 via-amber-400 to-indigo-500 text-white mb-4 shadow-inner">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
                <path d="M12 2a10 10 0 0 0 0 20c1.1 0 2-.9 2-2 0-.5-.2-1-.5-1.3-.3-.4-.5-.8-.5-1.2 0-1.1.9-2 2-2h2.4c2.6 0 4.6-2 4.6-4.5C22 5.6 17.5 2 12 2z"></path>
            </svg>
        </div>

        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">انتخاب تم رنگی</h3>
        <p class="text-[11px] text-gray-500 dark:text-zinc-400 mb-5 leading-relaxed font-medium">
            یکی از تم‌های زیر را انتخاب کنید تا رنگ پنل تغییر کند 🎨
        </p>

        <div class="grid grid-cols-3 gap-3 mb-5">
            <button onclick="applyTheme('blue')" data-theme="blue" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-blue-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">آبی</span>
            </button>
            <button onclick="applyTheme('gold')" data-theme="gold" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-amber-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-amber-300 to-yellow-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">طلایی</span>
            </button>
            <button onclick="applyTheme('emerald')" data-theme="emerald" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-emerald-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-emerald-400 to-green-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">زمردی</span>
            </button>
            <button onclick="applyTheme('rose')" data-theme="rose" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-rose-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-rose-400 to-pink-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">رز</span>
            </button>
            <button onclick="applyTheme('violet')" data-theme="violet" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-violet-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-violet-400 to-purple-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">بنفش</span>
            </button>
            <button onclick="applyTheme('cyan')" data-theme="cyan" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-cyan-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-400 to-teal-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">فیروزه‌ای</span>
            </button>
            <button onclick="applyTheme('orange')" data-theme="orange" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-orange-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-orange-400 to-red-500 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">نارنجی</span>
            </button>
            <button onclick="applyTheme('slate')" data-theme="slate" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-slate-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-slate-400 to-gray-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">خاکستری</span>
            </button>
            <button onclick="applyTheme('default')" data-theme="default" class="theme-choice group p-3 rounded-xl border-2 border-gray-200 dark:border-amoled-border hover:border-indigo-500 transition flex flex-col items-center gap-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-400 via-blue-500 to-purple-600 shadow-md"></div>
                <span class="text-[11px] font-bold text-gray-700 dark:text-zinc-300">پیش‌فرض</span>
            </button>
        </div>

        <button onclick="toggleThemePaletteModal(false)"
            class="w-full py-2.5 bg-transparent border-2 border-red-600 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-500 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-black rounded-xl text-sm transition duration-300 shadow-sm">
            بستن
        </button>
    </div>
</div>
<div id="manager-pass-modal" class="fixed inset-0 z-[118] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-amber-500/40 dark:border-amber-700/40 rounded-2xl shadow-2xl overflow-hidden p-5 transform transition-all scale-95 duration-300">
		<div class="flex justify-between items-center mb-4">
			<div>
				<h3 class="font-black text-base text-gray-900 dark:text-white">رمز مدیریت</h3>
				<p class="text-[10px] font-bold text-amber-700 dark:text-amber-500">ساخت رمز محدود برای مدیر (غیر مالک)</p>
			</div>
			<button type="button" onclick="toggleManagerPassModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 text-red-600 hover:bg-red-100 transition">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<p class="text-[11px] text-gray-500 dark:text-zinc-400 mb-3 leading-relaxed">رمز <b>مالک</b> همه قابلیت‌ها را دارد. رمز <b>مدیریت</b> به تنظیمات، دفترچه ورود، افراد داخل پنل، بازنشانی کامل ، اطلاعات ورود و ورود های ناموفق دسترسی ندارد.</p>
		<p id="manager-pass-status" class="text-xs font-bold mb-3 text-gray-600 dark:text-zinc-300">وضعیت: در حال بررسی...</p>
		<label class="block text-[11px] font-bold text-gray-700 dark:text-zinc-300 mb-1">رمز مدیریت جدید</label>
		<input id="manager-pass-input" type="password" class="w-full px-3 py-2 rounded-lg border border-amber-300 dark:border-amber-800 bg-white dark:bg-zinc-900 text-sm mb-3" placeholder="حداقل ۴ کاراکتر" dir="ltr">
		<div class="flex gap-2">
			<button type="button" onclick="saveManagerPassword()" class="flex-1 py-2.5 rounded-lg text-xs font-black bg-amber-700 hover:bg-amber-800 text-white transition">ذخیره رمز مدیریت</button>
			<button type="button" onclick="deleteManagerPassword()" class="px-3 py-2.5 rounded-lg text-xs font-black border border-red-300 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30 transition">حذف</button>
		</div>
	</div>
</div>
<div id="panel-people-modal" class="fixed inset-0 z-[116] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-xl bg-white dark:bg-amoled-card border border-sky-400/50 dark:border-sky-700/40 rounded-2xl shadow-2xl overflow-hidden p-5 transform transition-all scale-95 duration-300">
		<div class="flex justify-between items-center mb-4">
			<div>
				<h3 class="font-black text-base text-gray-900 dark:text-white">افراد داخل پنل</h3>
				<p class="text-[10px] font-bold text-sky-600 dark:text-sky-400">نشست‌های فعال مدیریت</p>
			</div>
			<button type="button" onclick="togglePanelPeopleModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 transition shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<button type="button" onclick="loadPanelPeople()" class="w-full mb-3 py-2 rounded-lg text-[11px] font-black border border-sky-300 dark:border-sky-700 text-sky-700 dark:text-sky-300 hover:bg-sky-50 dark:hover:bg-sky-950/40 transition">بروزرسانی لیست</button>
		<div id="panel-people-list" class="max-h-64 overflow-y-auto space-y-2 text-right mb-4">
			<p class="text-center text-xs text-gray-500 py-6">در حال بارگذاری...</p>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-3">
			<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 mb-2">مسدودشده‌ها</h4>
			<div id="panel-blocks-list" class="max-h-36 overflow-y-auto space-y-1.5 text-right">
				<p class="text-center text-[11px] text-gray-400 py-2">خالی</p>
			</div>
		</div>
		<p class="mt-3 text-[10px] text-gray-400 dark:text-zinc-500">سطل زباله = اخراج و ورود مجدد · بلاک آی‌پی / سیستم‌عامل = جلوگیری از ورود</p>
	</div>
</div>
<div id="access-logbook-modal" class="fixed inset-0 z-[115] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-300 ease-out">
<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-emerald-400/50 dark:border-emerald-600/40 rounded-2xl shadow-2xl overflow-hidden p-5 transform transition-all scale-95 duration-300" style="box-shadow:0 0 40px rgb(var(--a500, 16 185 129) / 0.25);">		<div class="flex justify-between items-center mb-4">
			<div class="flex items-center gap-2">
				<div class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-green-600 text-white flex items-center justify-center shadow-md shadow-emerald-500/40">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path></svg>
</div>
				<div>
					<h3 class="font-black text-base text-gray-900 dark:text-white">دفترچه ورودها</h3>
<p class="text-[10px] font-bold text-emerald-600 dark:text-emerald-400">ثبت IP ورود تا ۲۴ ساعت</p>				</div>
			</div>
			<button onclick="toggleAccessLogbookModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex gap-2 mb-3">
<button type="button" onclick="loadAccessLogbook()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 transition">بروزرسانی</button>			<button type="button" onclick="clearAccessLogbook()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition">پاک‌سازی همه</button>
		</div>
		<div id="access-logbook-list" class="max-h-80 overflow-y-auto space-y-2 text-right">
			<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>
		</div>
		<p class="mt-3 text-[10px] text-gray-400 dark:text-zinc-500 leading-relaxed">هر ورود به پنل با آی‌پی و مرورگر ثبت می‌شود و بعد از ۲۴ ساعت به‌صورت خودکار حذف می‌گردد.</p>
	</div>
</div>
<div id="failed-logins-modal" class="fixed inset-0 z-[115] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-300 ease-out">
<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-red-400/50 dark:border-red-600/40 rounded-2xl shadow-2xl overflow-hidden p-5 transform transition-all scale-95 duration-300">
	<div class="flex justify-between items-center mb-4">
		<div class="flex items-center gap-2">
			<div class="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-rose-600 text-white flex items-center justify-center shadow-md shadow-red-500/40">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"></path></svg>
			</div>
			<div>
				<h3 class="font-black text-base text-gray-900 dark:text-white">ورودهای ناموفق</h3>
				<p class="text-[10px] font-bold text-red-600 dark:text-red-400">آی‌پی و سیستم‌عامل تلاش‌های ناموفق ورود</p>
			</div>
		</div>
		<button onclick="toggleFailedLoginsModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm">
			<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
		</button>
	</div>
	<div class="flex gap-2 mb-3">
		<button type="button" onclick="loadFailedLogins()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/40 transition">بروزرسانی</button>
		<button type="button" onclick="clearFailedLogins()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition">پاک‌سازی همه</button>
	</div>
	<div id="failed-logins-list" class="max-h-64 overflow-y-auto space-y-2 text-right mb-4">
		<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>
	</div>
	<div class="border-t border-gray-100 dark:border-zinc-800 pt-3">
		<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 mb-2">مسدودشده‌ها</h4>
		<div id="failed-logins-blocks-list" class="max-h-36 overflow-y-auto space-y-1.5 text-right">
			<p class="text-center text-[11px] text-gray-400 py-2">خالی</p>
		</div>
	</div>
	<p class="mt-3 text-[10px] text-gray-400 dark:text-zinc-500 leading-relaxed">⛔ = بلاک آی‌پی · 💻 = بلاک سیستم‌عامل · رکوردها بعد از ۷ روز خودکار پاک می‌شوند.</p>
</div>
</div>
<div id="support-modal" class="fixed inset-0 z-[115] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-rose-500/50 rounded-2xl shadow-2xl overflow-hidden p-6 text-center transform transition-all scale-95 duration-300">

        <!-- آیکون قلب -->
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-rose-100 dark:bg-rose-900/30 text-rose-500 mb-4 shadow-inner">
            <svg class="w-8 h-8" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3 9.24 3 10.91 3.81 12 5.08 13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
            </svg>
        </div>

        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">حمایت از پروژه کاسپین</h3>
        <p class="text-[11px] text-gray-500 dark:text-zinc-400 mb-5 leading-relaxed font-medium">
            اگر این پروژه برایتان مفید بوده، می‌توانید از توسعه‌دهنده آن حمایت کنید ❤️
        </p>

        <!-- اطلاعات کارت -->
        <div class="space-y-3 text-right mb-5">
            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">💳 شماره کارت</span>
                <div class="flex items-center justify-between gap-2">
                    <span class="text-xs font-mono font-bold text-rose-600 dark:text-rose-400 tracking-wider" dir="ltr">5057851013268393</span>
                    <button onclick="copySupportCard()" class="p-1.5 rounded-md bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-rose-600 dark:text-rose-400 hover:bg-rose-100 dark:hover:bg-rose-900/60 transition shadow-sm" title="کپی شماره کارت">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                    </button>
                </div>
            </div>

            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">👤 به نام</span>
                <span class="block text-xs font-bold text-gray-800 dark:text-zinc-200">سید علی گلستانه</span>
            </div>
        </div>

        <!-- دکمه‌های پی وی -->
        <div class="grid grid-cols-2 gap-3 mb-3">
            <a href="https://t.me/PV_Golestaneh" target="_blank" rel="noopener noreferrer"
               class="w-full py-2.5 bg-transparent border-2 border-sky-500 text-sky-600 dark:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-900/20 font-bold rounded-xl text-xs transition shadow-sm flex items-center justify-center gap-1.5">
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/>
                </svg>
                <span>پی وی تلگرام</span>
            </a>
            <a href="https://ble.ir/PV_Goles" target="_blank" rel="noopener noreferrer"
               class="w-full py-2.5 bg-transparent border-2 border-emerald-500 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 font-bold rounded-xl text-xs transition shadow-sm flex items-center justify-center gap-1.5">
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
                <span>پی وی بله</span>
            </a>
        </div>

        <!-- دکمه بستن -->
        <button onclick="toggleSupportModal(false)"
            class="w-full py-2.5 bg-transparent border-2 border-red-600 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-500 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-black rounded-xl text-sm transition duration-300 shadow-sm">
            بستن
        </button>
    </div>
</div>
<div id="owner-chat-modal" style="display:none; position:fixed; top:0; right:0; bottom:0; left:0; z-index:500; align-items:center; justify-content:center; padding:16px; background:rgba(0,0,0,0.7);">	<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-blue-400/50 dark:border-blue-600/40 rounded-2xl shadow-2xl overflow-hidden p-5" style="max-height:90vh; overflow-y:auto; box-shadow:0 0 40px rgba(59,130,246,0.25);">
		<div class="flex justify-between items-center mb-4">
			<div class="flex items-center gap-2">
				<div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 text-white flex items-center justify-center shadow-md shadow-blue-500/40">
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path></svg>
				</div>
				<div>
					<h3 class="font-black text-base text-gray-900 dark:text-white">پیام‌های کاربران</h3>
					<p id="owner-chat-subtitle" class="text-[10px] font-bold text-blue-600 dark:text-blue-400">پیام‌های ارسالی از صفحه وضعیت اشتراک</p>
				</div>
			</div>
			<button onclick="toggleOwnerChatModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div id="owner-chat-list-view">
			<div class="flex gap-2 mb-3">
				<button type="button" onclick="loadOwnerChatThreads()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-950/40 transition">بروزرسانی</button>
			</div>
			<div id="owner-chat-threads" class="max-h-80 overflow-y-auto space-y-2 text-right">
				<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>
			</div>
		</div>
		<div id="owner-chat-conv-view" style="display:none;">
			<div class="flex items-center justify-between gap-2 mb-3">
				<button type="button" onclick="backToOwnerChatList()" class="px-3 py-1.5 rounded-lg text-[11px] font-black border border-gray-300 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-800 transition">بازگشت</button>
				<span id="owner-chat-current-user" class="text-xs font-black font-mono text-blue-600 dark:text-blue-400" dir="ltr"></span>
				<button type="button" onclick="deleteOwnerChatThread()" class="px-3 py-1.5 rounded-lg text-[11px] font-black border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition">حذف گفتگو</button>
			</div>
			<div id="owner-chat-messages" class="h-72 overflow-y-auto space-y-2 p-3 rounded-xl bg-gray-50 dark:bg-amoled-bg/60 border border-gray-200 dark:border-amoled-border mb-3"></div>
			<div class="flex items-end gap-2">
				<textarea id="owner-chat-input" rows="2" maxlength="1000" placeholder="پاسخ خود را بنویسید..." class="flex-1 px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-800 dark:text-zinc-200 resize-none"></textarea>
				<button type="button" id="owner-chat-send-btn" onclick="sendOwnerChatReply()" class="px-4 py-2.5 rounded-lg text-[11px] font-black bg-blue-600 hover:bg-blue-700 text-white transition shadow-sm">ارسال</button>
			</div>
		</div>
	</div>
	</div>


<div id="speedtest-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-yellow-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-yellow-100 dark:bg-yellow-900/30 text-yellow-500 mb-3 shadow-inner">
            <svg id="speedtest-icon" class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
            </svg>
        </div>
        <h3 class="font-black text-lg text-gray-900 dark:text-white mb-4">تست سرعت اتصال به پـنـل</h3>
        <div class="space-y-3 text-right">
            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">🏓 پینگ (میانگین)</span>
                <span id="speedtest-ping" class="block text-xs font-mono font-bold text-yellow-600 dark:text-yellow-400" dir="ltr">در حال سنجش...</span>
            </div>
            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">⬇️ سرعت دانلود (تقریبی)</span>
                <span id="speedtest-download" class="block text-xs font-mono font-bold text-yellow-600 dark:text-yellow-400" dir="ltr">در حال سنجش...</span>
            </div>
            <div class="p-3 bg-gray-50 dark:bg-amoled-input/40 border border-gray-200 dark:border-amoled-border rounded-lg">
                <span class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">📶 وضعیت</span>
                <span id="speedtest-status" class="block text-xs font-bold text-yellow-600 dark:text-yellow-400" dir="rtl">در حال اتصال به سرور...</span>
            </div>
        </div>
        <button onclick="runSpeedTest()" class="mt-5 w-full py-2 bg-yellow-600/10 border-2 border-yellow-600 text-yellow-700 hover:bg-yellow-600/20 dark:border-yellow-500 dark:text-yellow-400 font-black rounded-md text-sm transition duration-300 shadow-sm">
            تست مجدد
        </button>
        <button onclick="toggleSpeedtestModal(false)" class="mt-2 w-full py-2.5 bg-transparent border-2 border-gray-400 text-gray-600 hover:bg-gray-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800 font-black rounded-md text-sm transition duration-300 shadow-sm">
            بستن
        </button>
    </div>
</div>
<div id="help-guide-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-indigo-500/50 rounded-md shadow-2xl overflow-hidden p-6 transition-all transform duration-300 opacity-0 scale-95 ease-out max-h-[85vh] overflow-y-auto">
        <div class="text-center">
            <div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-indigo-100 dark:bg-indigo-900/30 text-indigo-500 mb-3 shadow-inner">
                <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
            </div>
            <h3 class="font-black text-lg text-gray-900 dark:text-white mb-4">راهنمای اتصال</h3>
        </div>
        <div class="space-y-2 text-right" id="help-guide-accordion">
            <div class="border border-gray-200 dark:border-amoled-border rounded-lg overflow-hidden">
                <button onclick="const b=document.getElementById('hg-android');b.classList.toggle('hidden');" class="w-full flex items-center justify-between px-3 py-2.5 bg-gray-50 dark:bg-amoled-input/40 text-xs font-bold text-gray-800 dark:text-zinc-200">
                    <span>📱 اندروید</span><span>+</span>
                </button>
                <div id="hg-android" class="hidden px-3 py-2.5 text-[11px] leading-relaxed text-gray-600 dark:text-zinc-400">
                    اپلیکیشن v2rayNG یا Hiddify را نصب کنید، سپس لینک اشتراک خود را از قسمت «دریافت لینک» کپی کرده و در برنامه، گزینه Import from Clipboard را بزنید.
                </div>
            </div>
            <div class="border border-gray-200 dark:border-amoled-border rounded-lg overflow-hidden">
                <button onclick="const b=document.getElementById('hg-ios');b.classList.toggle('hidden');" class="w-full flex items-center justify-between px-3 py-2.5 bg-gray-50 dark:bg-amoled-input/40 text-xs font-bold text-gray-800 dark:text-zinc-200">
                    <span>🍏 آیفون</span><span>+</span>
                </button>
                <div id="hg-ios" class="hidden px-3 py-2.5 text-[11px] leading-relaxed text-gray-600 dark:text-zinc-400">
                    اپلیکیشن Streisand یا Shadowrocket را نصب کنید، لینک اشتراک را کپی کرده و داخل برنامه از گزینه Add Subscription استفاده کنید.
                </div>
            </div>
            <div class="border border-gray-200 dark:border-amoled-border rounded-lg overflow-hidden">
                <button onclick="const b=document.getElementById('hg-windows');b.classList.toggle('hidden');" class="w-full flex items-center justify-between px-3 py-2.5 bg-gray-50 dark:bg-amoled-input/40 text-xs font-bold text-gray-800 dark:text-zinc-200">
                    <span>🖥️ ویندوز</span><span>+</span>
                </button>
                <div id="hg-windows" class="hidden px-3 py-2.5 text-[11px] leading-relaxed text-gray-600 dark:text-zinc-400">
                    نرم‌افزار v2rayN یا NekoRay را دانلود کنید، لینک اشتراک را کپی کرده و از منوی برنامه، Import from Clipboard را انتخاب کنید.
                </div>
            </div>
        </div>
        <button onclick="toggleHelpGuideModal(false)" class="mt-5 w-full py-2.5 bg-transparent border-2 border-indigo-600 text-indigo-700 hover:bg-indigo-900/20 hover:text-indigo-800 dark:border-indigo-500 dark:text-indigo-400 dark:hover:bg-indigo-900/40 dark:hover:text-indigo-300 font-black rounded-md text-sm transition duration-300 shadow-sm">
            بستن
        </button>
    </div>
</div>
<div id="owner-note-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-lime-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-lime-100 dark:bg-lime-900/30 text-lime-500 mb-3 shadow-inner">
            <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
            </svg>
        </div>
        <h3 class="font-black text-lg text-gray-900 dark:text-white mb-4">یادداشت شخصی مالک</h3>
        <textarea id="owner-note-textarea" rows="6" placeholder="یادداشت خودتو اینجا بنویس... (فقط روی همین مرورگر ذخیره میشه)" class="w-full text-right text-xs p-3 rounded-lg border border-gray-200 dark:border-amoled-border bg-gray-50 dark:bg-amoled-input/40 text-gray-800 dark:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-lime-500 resize-none"></textarea>
        <span id="owner-note-saved-hint" class="block text-[10px] text-lime-600 dark:text-lime-400 font-bold mt-1 h-4"></span>
        <button onclick="saveOwnerNote()" class="mt-2 w-full py-2.5 bg-lime-600 hover:bg-lime-700 text-white font-black rounded-md text-sm transition duration-300 shadow-sm">
            ذخیره یادداشت
        </button>
        <button onclick="toggleOwnerNoteModal(false)" class="mt-2 w-full py-2.5 bg-transparent border-2 border-gray-400 text-gray-600 hover:bg-gray-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800 font-black rounded-md text-sm transition duration-300 shadow-sm">
            بستن
        </button>
    </div>
</div>

<div id="notif-center-overlay" class="fixed inset-0 z-[200] bg-black/40 opacity-0 pointer-events-none transition-opacity duration-300" onclick="toggleNotifCenter(false)"></div>
<div id="notif-center-drawer" class="fixed top-0 bottom-0 z-[201] w-full max-w-sm bg-white dark:bg-zinc-900 border-l border-gray-200 dark:border-zinc-700 shadow-2xl flex flex-col transition-transform duration-300 ease-out" style="right:0; transform: translateX(100%);" dir="rtl">
	<div class="flex items-center justify-between gap-3 p-4 border-b border-gray-200 dark:border-zinc-800">
		<div>
			<h3 class="font-black text-base text-gray-900 dark:text-white">مرکز اعلان‌ها</h3>
			<p class="text-[10px] text-gray-500 dark:text-zinc-400 mt-0.5">پیام · اهدا · آپدیت · سیستم</p>
		</div>
		<div class="flex items-center gap-2">
			<button type="button" onclick="markAllNotifsRead()" class="text-[10px] font-bold px-2 py-1 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-100">خواندم همه</button>
			<button type="button" onclick="clearNotifCenter()" class="text-[10px] font-bold px-2 py-1 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 text-red-600 hover:bg-red-100">پاک کردن</button>
			<button type="button" onclick="toggleNotifCenter(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 text-red-600">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
	</div>
	<div id="notif-center-list" class="flex-1 overflow-y-auto p-3 space-y-2">
		<p class="text-center text-xs text-gray-400 py-10">در حال بارگذاری...</p>
	</div>
	<div class="p-3 border-t border-gray-100 dark:border-zinc-800 text-[10px] text-gray-400 text-center">اعلان‌ها هر ۳۰ ثانیه به‌روز می‌شوند</div>
</div>
<div id="donation-modal" style="display:none; position:fixed; top:0; right:0; bottom:0; left:0; z-index:500; align-items:center; justify-content:center; padding:16px; background:rgba(0,0,0,0.7);">	<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-amber-400/50 dark:border-amber-600/40 rounded-2xl shadow-2xl overflow-hidden p-5" style="max-height:90vh; overflow-y:auto; box-shadow:0 0 40px rgba(245,158,11,0.25);">
		<div class="flex justify-between items-center mb-4">
			<div class="flex items-center gap-2">
				<div class="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-600 text-white flex items-center justify-center shadow-md shadow-amber-500/40">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="8" width="18" height="4" rx="1"/>
        <path d="M5 12v8a1 1 0 001 1h12a1 1 0 001-1v-8"/>
        <path d="M12 8v13"/>
        <path d="M12 8s-1-4-3.5-4a2 2 0 000 4H12z"/>
        <path d="M12 8s1-4 3.5-4a2 2 0 010 4H12z"/>
    </svg>
</div>
				<div>
					<h3 class="font-black text-base text-gray-900 dark:text-white">اهدای کانفیگ کاربران</h3>
					<p class="text-[10px] font-bold text-amber-600 dark:text-amber-400">لیست حجم‌هایی که کاربران به دوستان خود اهدا کرده‌اند</p>
				</div>
			</div>
		<button onclick="toggleDonationModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition shadow-sm" title="بستن">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M6 18L18 6M6 6l12 12"></path>
    </svg>
</button>
		</div>
		<div class="flex gap-2 mb-3">
			<button type="button" onclick="loadDonationNotifications()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-950/40 transition">بروزرسانی</button>
			<button type="button" onclick="ackDonationNotifications()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-gray-300 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-800 transition">علامت‌گذاری همه به‌عنوان خوانده‌شده</button>
			<button type="button" onclick="clearDonationNotifications()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition">پاک کردن لیست</button>
		</div>
		<div id="donation-list" class="max-h-96 overflow-y-auto space-y-2 text-right">
			<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>
		</div>
	</div>
</div>

	<div id="bulk-actions-bar" class="fixed bottom-4 left-1/2 -translate-x-1/2 z-[40] bg-white dark:bg-zinc-900/90 border border-gray-200 dark:border-zinc-800/80 px-6 py-4 rounded-md shadow-2xl flex flex-wrap items-center justify-between gap-4 w-[95%] max-w-4xl transition-all duration-300 transform translate-y-28 opacity-0 pointer-events-none ">
		<div class="flex items-center gap-2">
			<span class="w-3 h-3 bg-blue-500 rounded-full animate-pulse shadow-sm shadow-blue-500/50"></span>
			<span id="bulk-selected-count" class="text-sm font-bold text-gray-800 dark:text-zinc-200">۰ کاربر انتخاب شده</span>
		</div>
		<div class="flex flex-wrap gap-2 justify-end">
			<button onclick="bulkToggleStatus(1)" class="px-3 py-1.5 bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-500 hover:bg-green-100 dark:hover:bg-green-900/30 rounded-md text-xs font-bold transition border border-green-200 dark:border-green-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg> فعال‌سازی
			</button>
			<button onclick="bulkToggleStatus(0)" class="px-3 py-1.5 bg-amber-50 dark:bg-amber-950/20 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/30 rounded-md text-xs font-bold transition border border-amber-200 dark:border-amber-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg> غیرفعال‌سازی
			</button>
			<button onclick="bulkReset('volume')" class="px-3 py-1.5 bg-blue-50 dark:bg-blue-950/20 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-md text-xs font-bold transition border border-blue-200 dark:border-blue-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg> ریست حجم
			</button>
			<button onclick="bulkReset('req')" class="px-3 py-1.5 bg-sky-50 dark:bg-sky-950/20 text-sky-600 dark:text-sky-400 hover:bg-sky-100 dark:hover:bg-sky-900/30 rounded-md text-xs font-bold transition border border-sky-200 dark:border-sky-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> ریست ریکوئست
			</button>
			<button onclick="bulkReset('time')" class="px-3 py-1.5 bg-purple-50 dark:bg-purple-950/20 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900/30 rounded-md text-xs font-bold transition border border-purple-200 dark:border-purple-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> ریست زمان
			</button>
			<button onclick="bulkDelete()" class="px-3 py-1.5 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-450 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-md text-xs font-bold transition border border-red-200 dark:border-red-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg> حذف گروهی
			</button>
		</div>
	</div>
	<div id="update-success-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
		<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-green-600/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
			<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 text-green-600 mb-4 shadow-inner">
				<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>
			</div>
			<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">آپدیت موفقیت‌آمیز</h3>
			<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
				آپدیت با موفقیت انجام شد. صفحه تا ۱۰ ثانیه دیگر به‌طور خودکار رفرش می‌شود تا تغییرات اعمال گردند.
			</p>
			<button onclick="sessionStorage.setItem('caspian_last_update', Date.now()); window.location.href = window.location.pathname + '?t=' + Date.now()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-md text-sm transition duration-300 shadow-lg">
				رفرش فوری صفحه
			</button>
		</div>
	</div>
${COMMON_TOAST_HTML}
<div id="custom-confirm-modal" class="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div id="custom-confirm-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl overflow-hidden p-6 text-center transform transition-all scale-95 duration-300">
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-3">تأیید عملیات</h3>
		<p id="custom-confirm-message" class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium"></p>
		<div class="flex gap-3">
			<button id="custom-confirm-cancel" class="flex-1 py-3 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-sm transition duration-200 shadow-sm">انصراف</button>
			<button id="custom-confirm-ok" class="flex-1 py-3 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-md text-sm transition duration-200 shadow-lg">تأیید</button>
		</div>
	</div>
</div>
<div id="loop-warning-modal" class="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/75 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div id="loop-warning-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border-2 border-red-600/80 dark:border-red-500/80 rounded-xl shadow-[0_0_30px_rgb(var(--a600,220_38_38)/0.3)] overflow-hidden p-6 text-center transform transition-all scale-95 duration-300 flex flex-col items-center">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-500 mb-4 shadow-inner animate-violent-shake">
			<svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-red-600 dark:text-red-500 mb-3">اخطار اتصال مستقیم!</h3>
		<p class="text-[13px] text-gray-700 dark:text-gray-300 mb-6 leading-relaxed font-bold">
			شما با کانفیگ مستقیم (🌐) وارد پنل شده‌اید! در این حالت قابلیت‌های پنل کار نمی‌کنند.<br><br>
			لطفاً فیلترشکن خود را <span class="text-red-600 dark:text-red-400">خاموش کنید</span> یا از کانفیگ‌های دارای پرچم (غیر از 🌐) استفاده نمایید.
		</p>
		<button onclick="window.location.reload();" class="w-full py-3.5 bg-red-600 hover:bg-red-700 text-white font-black rounded-lg text-sm transition duration-300 shadow-lg hover:shadow-red-500/50 flex items-center justify-center gap-2">
			<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
				<path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
			</svg>
			رفرش صفحه
		</button>
	</div>
</div>
<div id="rocket-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-orange-500/50 rounded-2xl shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200">
		<div class="flex justify-between items-center mb-4">
			<div class="flex items-center gap-2">
				<div class="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/20 text-orange-600 dark:text-orange-400 flex items-center justify-center shadow-sm">
					<svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
						<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path>
						<path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path>
						<path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path>
						<path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"></path>
					</svg>
				</div>
				
				<h3 class="text-sm font-black text-gray-900 dark:text-white">کانفیگ تک لوکیشن</h3>
			</div>
			<button onclick="toggleRocketModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<p class="text-[11px] text-gray-600 dark:text-gray-400 mb-5 font-medium leading-relaxed">کشور مورد نظر را انتخاب کنید تا کانفیگ تک لوکیشن پرسرعت ساخته شود.</p>
		<div class="space-y-4">
			<div>
				<select id="rocket-country-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-orange-500/50 text-gray-800 dark:text-zinc-100 cursor-pointer shadow-sm transition">
					<option value="">در حال بارگذاری کشورها...</option>
				</select>
			</div>
			<button id="rocket-submit-btn" onclick="executeRocketCreate()" class="w-full py-2.5 bg-transparent border-2 border-orange-600 text-orange-700 hover:bg-orange-900/20 hover:text-orange-800 dark:border-orange-500 dark:text-orange-500 dark:hover:bg-orange-900/40 dark:hover:text-orange-400 font-black rounded-xl text-xs sm:text-sm transition shadow-lg">شروع اسکن و ساخت</button>
		</div>
	</div>
</div>
<div id="factory-reset-modal" class="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/80 opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div id="factory-reset-modal-card" class="w-full max-w-md bg-white dark:bg-amoled-card border-4 border-pink-500/70 rounded-xl shadow-[0_0_40px_rgb(var(--a500,236_72_153)/0.4)] overflow-hidden p-6 text-center transform transition-all scale-95 duration-300">
        
        <div class="inline-flex items-center justify-center w-20 h-20 rounded-full bg-pink-100 dark:bg-pink-900/40 text-pink-600 dark:text-pink-500 mb-4 shadow-inner animate-violent-shake">
            <svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
            </svg>
        </div>
        
        <h3 class="font-black text-2xl text-pink-600 dark:text-pink-500 mb-3">⚠️ بازنشانی کامل پنل ⚠️</h3>
        
        <div class="text-sm text-gray-700 dark:text-gray-300 mb-6 leading-relaxed font-bold text-right space-y-2 bg-pink-50 dark:bg-pink-950/30 p-4 rounded-lg border border-pink-200 dark:border-pink-900/50">
            <p class="text-red-600 dark:text-red-400 text-center text-base">🚨 این عملیات غیرقابل بازگشت است! 🚨</p>
            <p>با تأیید این عملیات، تمام موارد زیر <b class="text-red-500">برای همیشه پاک می‌شوند</b>:</p>
            <ul class="list-disc pr-6 text-[13px] space-y-1">
                <li>تمام کاربران و کانفیگ‌ها</li>
                <li>تمام تنظیمات پنل</li>
                <li>رمز عبور مدیریت</li>
                <li>آمار مصرف و ترافیک</li>
                <li>توکن‌های ذخیره شده کلودفلر</li>
                <li>پروکسی‌های VIP اهدایی</li>
            </ul>
            <p class="text-center mt-3 text-pink-700 dark:text-pink-400 font-black">پنل به حالت اولیه (نصب تازه) برمی‌گردد.</p>
        </div>
        
        <div class="mb-4">
            <label class="block text-xs font-bold text-gray-700 dark:text-zinc-300 mb-2 text-right">
                برای تأیید، عبارت زیر را دقیقاً وارد کنید:
            </label>
            <div class="bg-gray-100 dark:bg-zinc-900 border border-gray-300 dark:border-zinc-700 rounded-lg py-2 px-3 text-center font-mono font-black text-pink-600 dark:text-pink-500 text-lg select-all mb-3" dir="ltr">
                RESET-ALL
            </div>
            <input type="text" id="factory-reset-confirm-input" placeholder="RESET-ALL" dir="ltr"
                class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border-2 border-gray-300 dark:border-zinc-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-pink-500 text-sm font-mono text-center font-black text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition"
                oninput="checkResetInput(this.value)">
        </div>
        
        <div class="flex gap-3">
            <button onclick="closeFactoryResetModal()" class="flex-1 py-3 bg-transparent border-2 border-gray-500 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-zinc-800 font-bold rounded-lg text-sm transition">
                انصراف
            </button>
            <button id="factory-reset-confirm-btn" onclick="executeFactoryReset()" disabled
                class="flex-1 py-3 bg-transparent border-2 border-pink-600 text-pink-700 dark:text-pink-500 hover:bg-pink-900/20 hover:text-pink-800 dark:hover:bg-pink-900/40 dark:hover:text-pink-400 font-black rounded-lg text-sm transition shadow-lg disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:bg-transparent">
                🗑️ پاک‌سازی کامل
            </button>
        </div>
    </div>
</div>
	<script>
		window.PANEL_ROLE = '/*{{PANEL_ROLE}}*/';
async function fetchWithFallbackUI(path, options = {}) {
	const primaryUrl = 'https://hoplimit.shop/' + path;
	const fallbackUrl = 'https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/main/' + path;
	try {
		const res = await fetch(primaryUrl, options);
		if (res.ok) return res;
	} catch (e) {}
	return await fetch(fallbackUrl, options);
}
async function fetchUpdateSourceUI(path, options = {}) {
	const url = 'https://raw.githubusercontent.com/sepehr-gamer/Caspian-pannel/main/' + path;
	return await fetch(url, options);
}
		function updateSubmitBtnState(text, disable = null) {
			const btnMob = document.getElementById('submit-btn');
			const btnDesk = document.getElementById('submit-btn-desktop');
			if (btnMob && btnMob.querySelector('span')) {
				btnMob.querySelector('span').innerText = text;
				if (disable !== null) btnMob.disabled = disable;
			}
			if (btnDesk && btnDesk.querySelector('span')) {
				btnDesk.querySelector('span').innerText = text;
				if (disable !== null) btnDesk.disabled = disable;
			}
		}
		function showToast(message, type = 'success') {
			const container = document.getElementById('toast-container');
			const toast = document.createElement('div');
			const colors = type === 'error' 
				? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
				: 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
			toast.className = 'px-4 py-3 border rounded-md shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
			toast.innerText = message;
			container.appendChild(toast);
			requestAnimationFrame(() => {
				toast.classList.remove('-translate-y-full', 'opacity-0');
			});
			setTimeout(() => {
				toast.classList.add('-translate-y-full', 'opacity-0');
				setTimeout(() => toast.remove(), 300);
			}, 3000);
		}
		function customConfirm(message) {
			return new Promise((resolve) => {
				const modal = document.getElementById('custom-confirm-modal');
				const card = document.getElementById('custom-confirm-card');
				const msgEl = document.getElementById('custom-confirm-message');
				const btnOk = document.getElementById('custom-confirm-ok');
				const btnCancel = document.getElementById('custom-confirm-cancel');
				msgEl.innerText = message;
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('scale-95');
				card.classList.add('scale-100');
				const cleanup = () => {
					modal.classList.remove('opacity-100', 'pointer-events-auto');
					modal.classList.add('opacity-0', 'pointer-events-none');
					card.classList.remove('scale-100');
					card.classList.add('scale-95');
					btnOk.removeEventListener('click', onOk);
					btnCancel.removeEventListener('click', onCancel);
				};
				const onOk = () => { cleanup(); resolve(true); };
				const onCancel = () => { cleanup(); resolve(false); };
				btnOk.addEventListener('click', onOk);
				btnCancel.addEventListener('click', onCancel);
			});
		}
		window.alert = function(message) {
			const msgStr = message ? message.toString() : '';
			if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
				showToast(msgStr, 'error');
			} else {
				showToast(msgStr, 'success');
			}
		};
		window.selectedUsernames = new Set();
		function toggleSelectAllUsers(el) {
			const checkboxes = document.querySelectorAll('input[name="select-user"]');
			checkboxes.forEach(cb => {
				cb.checked = el.checked;
				const username = decodeURIComponent(cb.value);
				if (el.checked) {
					window.selectedUsernames.add(username);
				} else {
					window.selectedUsernames.delete(username);
				}
			});
			updateBulkActionsBar();
		}
		function onUserSelectChange(el) {
			const username = decodeURIComponent(el.value);
			if (el.checked) {
				window.selectedUsernames.add(username);
			} else {
				window.selectedUsernames.delete(username);
			}
			updateBulkActionsBar();
		}
		function updateBulkActionsBar() {
			const bar = document.getElementById('bulk-actions-bar');
			const countSpan = document.getElementById('bulk-selected-count');
			const selectAllCheckbox = document.getElementById('select-all-users');
			const selectedCount = window.selectedUsernames.size;
			if (countSpan) {
				countSpan.innerText = selectedCount + ' کاربر انتخاب شده';
			}
			const checkboxes = document.querySelectorAll('input[name="select-user"]');
			if (checkboxes.length > 0) {
				const allChecked = Array.from(checkboxes).every(cb => cb.checked);
				if (selectAllCheckbox) selectAllCheckbox.checked = allChecked;
			} else {
				if (selectAllCheckbox) selectAllCheckbox.checked = false;
			}
			if (selectedCount > 0) {
				bar.classList.remove('opacity-0', 'pointer-events-none', 'translate-y-28');
				bar.classList.add('opacity-100', 'pointer-events-auto', 'translate-y-0');
			} else {
				bar.classList.remove('opacity-100', 'pointer-events-auto', 'translate-y-0');
				bar.classList.add('opacity-0', 'pointer-events-none', 'translate-y-28');
			}
		}
		async function bulkDelete() {
			const usernames = Array.from(window.selectedUsernames);
			if (usernames.length === 0) return;
			if (await customConfirm('⚠️ آیا از حذف گروهی ' + usernames.length + ' کاربر انتخاب شده مطمئن هستید؟ این عمل غیرقابل بازگشت است.')) {
				const bar = document.getElementById('bulk-actions-bar');
				const buttons = bar.querySelectorAll('button');
				buttons.forEach(btn => btn.disabled = true);
				try {
					let successCount = 0;
					await Promise.all(usernames.map(async (uname) => {
						try {
							const res = await fetch('/api/users/' + encodeURIComponent(uname), { method: 'DELETE' });
							if (res.ok) {
								successCount++;
								window.selectedUsernames.delete(uname);
							}
						} catch(e) {}
					}));
					alert('✅ عملیات حذف گروهی انجام شد. ' + successCount + ' کاربر با موفقیت حذف شدند.');
				} finally {
					buttons.forEach(btn => btn.disabled = false);
					updateBulkActionsBar();
					await loadUsers(true);
				}
			}
		}
		async function bulkToggleStatus(targetActive) {
			const usernames = Array.from(window.selectedUsernames);
			if (usernames.length === 0) return;
			const actionText = targetActive === 1 ? 'فعال‌سازی' : 'غیرفعال‌سازی';
			if (await customConfirm('آیا از ' + actionText + ' گروهی ' + usernames.length + ' کاربر انتخاب شده مطمئن هستید؟')) {
				const bar = document.getElementById('bulk-actions-bar');
				const buttons = bar.querySelectorAll('button');
				buttons.forEach(btn => btn.disabled = true);
				try {
					let successCount = 0;
					await Promise.all(usernames.map(async (uname) => {
						const user = window.allUsers.find(u => u.username === uname);
						if (!user) return;
						const isCurrentActive = user.is_active !== 0;
						const shouldToggle = (targetActive === 1 && !isCurrentActive) || (targetActive === 0 && isCurrentActive);
						if (shouldToggle) {
							try {
								const res = await fetch('/api/users/' + encodeURIComponent(uname), {
									method: 'PUT',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify({ toggle_only: true })
								});
								if (res.ok) successCount++;
							} catch(e) {}
						} else {
							successCount++;
						}
					}));
					alert('✅ عملیات ' + actionText + ' با موفقیت برای تمامی کاربران واجد شرایط اعمال شد.');
				} finally {
					buttons.forEach(btn => btn.disabled = false);
					updateBulkActionsBar();
					await loadUsers(true);
				}
			}
		}
		async function bulkReset(actionType) {
			const usernames = Array.from(window.selectedUsernames);
			if (usernames.length === 0) return;
			let actionName = '';
			if (actionType === 'volume') actionName = 'حجم مصرفی';
			else if (actionType === 'req') actionName = 'تعداد ریکوئست‌ها';
			else if (actionType === 'time') actionName = 'زمان اشتراک';
			if (await customConfirm('آیا از ریست کردن گروهی ' + actionName + ' برای ' + usernames.length + ' کاربر انتخاب شده مطمئن هستید؟')) {
				const bar = document.getElementById('bulk-actions-bar');
				const buttons = bar.querySelectorAll('button');
				buttons.forEach(btn => btn.disabled = true);
				try {
					let successCount = 0;
					await Promise.all(usernames.map(async (uname) => {
						try {
							const res = await fetch('/api/users/' + encodeURIComponent(uname), {
								method: 'PUT',
								headers: { 'Content-Type': 'application/json' },
								body: JSON.stringify({ reset_action: actionType })
							});
							if (res.ok) {
								successCount++;
								if (window.smoothCache && window.smoothCache[uname]) {
									if (actionType === 'volume') window.smoothCache[uname].gb = 0;
									if (actionType === 'req') window.smoothCache[uname].req = 0;
								}
							}
						} catch(e) {}
					}));
					alert('✅ عملیات ریست گروهی ' + actionName + ' با موفقیت برای ' + successCount + ' کاربر اعمال شد.');
				} finally {
					buttons.forEach(btn => btn.disabled = false);
					updateBulkActionsBar();
					await loadUsers(true);
				}
			}
		}
		const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
		const nonTlsPorts = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];
		let isEditMode = false;
		let editingUsername = '';
		function renderPortCheckboxes() {
			const tlsContainer = document.getElementById('tls-ports-list');
			const nonTlsContainer = document.getElementById('nontls-ports-list');
			
			if (nonTlsContainer) {
				nonTlsContainer.className = "grid grid-cols-12 gap-1.5 flex-1 content-start";
			}
			
			tlsContainer.innerHTML = tlsPorts.map(function(port) {
				const isCheckedDefault = port === '443' ? 'checked' : '';
				return '<label class="relative cursor-pointer">' +
					'<input type="checkbox" name="ports" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
					'<div class="flex items-center justify-center gap-1 px-1.5 py-1 border border-gray-200 dark:border-amoled-border rounded-md text-[11px] font-semibold select-none transition-all duration-200 hover:bg-gray-50 dark:hover:bg-amoled-input/50 text-gray-700 dark:text-zinc-200 peer-checked:bg-blue-50 dark:peer-checked:bg-blue-950/25 peer-checked:border-blue-500 dark:peer-checked:border-blue-500 peer-checked:text-blue-600 dark:peer-checked:text-blue-400 shadow-sm">' +
						'<span>' + port + '</span>' +
						'<svg class="w-3 h-3 hidden peer-checked:block text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
					'</div>' +
				'</label>';
			}).join('');
			
			nonTlsContainer.innerHTML = nonTlsPorts.map(function(port, index) {
				const isCheckedDefault = port === '80' ? 'checked' : '';
				const colSpanClass = index < 3 ? 'col-span-4' : 'col-span-3';
				return '<label class="relative cursor-pointer ' + colSpanClass + '">' +
					'<input type="checkbox" name="ports" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
					'<div class="flex items-center justify-center gap-1 px-1.5 py-1 border border-gray-200 dark:border-amoled-border rounded-md text-[11px] font-semibold select-none transition-all duration-200 hover:bg-gray-50 dark:hover:bg-amoled-input/50 text-gray-700 dark:text-zinc-200 peer-checked:bg-amber-50 dark:peer-checked:bg-amber-950/25 peer-checked:border-amber-500 dark:peer-checked:border-amber-500 peer-checked:text-amber-600 dark:peer-checked:text-amber-400 shadow-sm">' +
						'<span>' + port + '</span>' +
						'<svg class="w-3 h-3 hidden peer-checked:block text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
					'</div>' +
				'</label>';
			}).join('');
		}
		setTimeout(function() {
			const cb443 = document.querySelector('input[name="ports"][value="443"]');
			if (cb443) cb443.checked = true;
			const cb80 = document.querySelector('input[name="ports"][value="80"]');
			if (cb80) cb80.checked = false;
		}, 100);
		function toggleSettingsModal(show) { setModalState('settings-modal', show); }
		window.toggleAutoResetInputs = function(show) {
			const container = document.getElementById('auto-reset-inputs-container');
			const volInput = document.getElementById('input-auto-reset-vol');
			const reqInput = document.getElementById('input-auto-reset-req');
			if (container) {
				if (show) {
					container.classList.remove('opacity-50', 'pointer-events-none');
					if (volInput) volInput.disabled = false;
					if (reqInput) reqInput.disabled = false;
				} else {
					container.classList.add('opacity-50', 'pointer-events-none');
					if (volInput) volInput.disabled = true;
					if (reqInput) reqInput.disabled = true;
				}
			}
		};
		window.toggleAnnounceInputs = function(show) {
			const container = document.getElementById('announce-inputs-container');
			const textInput = document.getElementById('input-announce-text');
			if (container) {
				if (show) {
					container.classList.remove('opacity-50', 'pointer-events-none');
					if (textInput) textInput.disabled = false;
				} else {
					container.classList.add('opacity-50', 'pointer-events-none');
					if (textInput) textInput.disabled = true;
				}
			}
		};
		window.updateAnnounceCount = function() {
			const textInput = document.getElementById('input-announce-text');
			const counter = document.getElementById('announce-char-count');
			if (textInput && counter) counter.textContent = textInput.value.length + '/200';
		};
		window.setAnnounceInputs = function(enabled, text) {
			const on = Number(enabled) === 1;
			const toggle = document.getElementById('input-announce-toggle');
			const textInput = document.getElementById('input-announce-text');
			if (toggle) toggle.checked = on;
			if (textInput) textInput.value = text || '';
			window.toggleAnnounceInputs(on);
			window.updateAnnounceCount();
		};
		window.resetAnnounceInputs = function() {
			window.setAnnounceInputs(0, '');
		};
		window.toggleAdvancedSettingsInputs = function(show) {
			const container = document.getElementById('advanced-settings-container');
			const icon = document.getElementById('advanced-settings-icon');
			if (container) {
				if (show) {
					container.classList.remove('opacity-50', 'pointer-events-none', 'hidden');
					if (icon) icon.classList.add('rotate-180');
					const fragToggle = document.getElementById('input-frag-toggle');
					if (fragToggle && fragToggle.checked) {
						fragToggle.checked = false;
						if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(false);
					}
				} else {
					container.classList.add('opacity-50', 'pointer-events-none', 'hidden');
					if (icon) icon.classList.remove('rotate-180');
				}
			}
		};
		window.toggleAutoRotateIpInputs = function(show) {
			const container = document.getElementById('auto-rotate-ip-inputs-container');
			if (container) {
				if (show) container.classList.remove('hidden');
				else container.classList.add('hidden');
			}
		};
		
		window.applyFragPreset = function(op, btnEl) {
			const presets = {
				'mci': { len: '10-30', int: '2-5', name: 'همراه اول' },
				'irancell': { len: '100-200', int: '5-10', name: 'ایرانسل' },
				'rightel': { len: '50-100', int: '2-5', name: 'رایتل' },
				'tci': { len: '50-200', int: '1-3', name: 'مخابرات و اینترنت ثابت' },
				'gaming': { len: '200-3000', int: '1-2', name: 'پینگ پایین' }
			};
			const p = presets[op];
			if (!p) return;
			
			const lenInput = document.getElementById('input-frag-len');
			const intInput = document.getElementById('input-frag-int');
			
			const isActive = btnEl && btnEl.classList.contains('ring-2');
			
			document.querySelectorAll('.frag-preset-card').forEach(card => {
				card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40');
			});

			if (isActive) {
				if (lenInput) lenInput.value = '200-3000';
				if (intInput) intInput.value = '1-2';
				if (typeof showToast === 'function') {
					showToast('🔄 تنظیمات فرگمنت به حالت پیش‌فرض بازگشت.', 'success');
				}
				return;
			}

			const toggle = document.getElementById('input-frag-toggle');
			if (toggle && !toggle.checked) {
				toggle.checked = true;
				if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(true);
			}
			
			if (lenInput) lenInput.value = p.len;
			if (intInput) intInput.value = p.int;
			
			if (btnEl) {
				btnEl.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40');
			}
			if (typeof showToast === 'function') {
				showToast('⚡ تنظیمات فرگمنت ' + p.name + ' با موفقیت اعمال شد.', 'success');
			}
		};
		window.setQuickVol = function(val) {
			const input = document.getElementById('input-limit');
			if (input) input.value = val;
		};
		window.setQuickExp = function(val) {
			const input = document.getElementById('input-expiry');
			if (input) input.value = val;
		};
		window.toggleFragInputs = function(show) {
			const container = document.getElementById('frag-inputs-container');
			const icon = document.getElementById('frag-settings-icon');
			if (container) {
				if (show) {
					container.classList.remove('hidden', 'opacity-50', 'pointer-events-none');
					if (icon) icon.classList.add('rotate-180');
					const advToggle = document.getElementById('input-advanced-settings-toggle');
					if (advToggle && advToggle.checked) {
						advToggle.checked = false;
						if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(false);
					}
				} else {
					container.classList.add('hidden', 'opacity-50', 'pointer-events-none');
					if (icon) icon.classList.remove('rotate-180');
				}
			}
		};
		window.switchUserTab = function(tabId) {
			const tabs = [
				{ id: 'tab-user-info', btn: 'tab-btn-user-info' },
				{ id: 'tab-ports-network', btn: 'tab-btn-ports-network' },
				{ id: 'tab-proxy-settings', btn: 'tab-btn-proxy-settings' }
			];
			tabs.forEach(t => {
				const panel = document.getElementById(t.id);
				const btn = document.getElementById(t.btn);
				if (panel) {
					if (t.id === tabId) {
						panel.classList.remove('hidden');
					} else {
						panel.classList.add('hidden');
					}
				}
				if (btn) {
					if (t.id === tabId) {
						btn.className = 'user-modal-tab-btn active flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-blue-600/10 dark:bg-blue-500/15 border border-blue-500/30 text-blue-600 dark:text-blue-400 font-bold shadow-sm';
						const iconBox = btn.querySelector('div.flex-shrink-0');
						if (iconBox) iconBox.className = 'flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-blue-500/15 dark:bg-blue-400/20 text-blue-600 dark:text-blue-300';
					} else {
						btn.className = 'user-modal-tab-btn flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-transparent hover:bg-gray-100 dark:hover:bg-zinc-800/60 border border-transparent text-gray-600 dark:text-zinc-400 font-medium';
						const iconBox = btn.querySelector('div.flex-shrink-0');
						if (iconBox) iconBox.className = 'flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-gray-200/60 dark:bg-zinc-800 text-gray-500 dark:text-zinc-400';
					}
				}
			});
		};
		function toggleModal(show) {
			setModalState('user-modal', show);
			if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
			if (!show) {
				isEditMode = false;
				editingUsername = '';
				document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
				updateSubmitBtnState('ایجاد کاربر');
				document.getElementById('input-name').disabled = false;
				document.getElementById('create-user-form').reset();
				const vlessCb1 = document.getElementById('input-proto-vless');
				const trojanCb1 = document.getElementById('input-proto-trojan');
				const ssCb1 = document.getElementById('input-proto-ss');
				if (vlessCb1) vlessCb1.checked = true;
				if (trojanCb1) trojanCb1.checked = false;
				if (ssCb1) ssCb1.checked = false;
				const cb443 = document.querySelector('input[name="ports"][value="443"]');
				if (cb443) cb443.checked = true;
				const cb80 = document.querySelector('input[name="ports"][value="80"]');
				if (cb80) cb80.checked = false;
				const fpSelect = document.getElementById('fingerprint-select');
				if (fpSelect) fpSelect.value = 'unsafe';
				const bpCheck = document.getElementById('input-block-porn');
				if (bpCheck) bpCheck.checked = false;
				const baCheck = document.getElementById('input-block-ads');
				if (baCheck) baCheck.checked = false;
				const autoRotateUserProxyCheck = document.getElementById('input-auto-rotate-user-proxy');
				if (autoRotateUserProxyCheck) autoRotateUserProxyCheck.checked = false;
				const fragLenInput = document.getElementById('input-frag-len');
				if (fragLenInput) fragLenInput.value = '200-3000';
				const fragIntInput = document.getElementById('input-frag-int');
				if (fragIntInput) fragIntInput.value = '1-2';
				document.querySelectorAll('.frag-preset-card').forEach(card => card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'));
				const fragToggle = document.getElementById('input-frag-toggle');
				if (fragToggle) fragToggle.checked = false;
				if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(false);
				const customPortInput = document.getElementById('input-custom-ports');
				if (customPortInput) customPortInput.value = '';
				const advFragInput = document.getElementById('input-advanced-frag');
				if (advFragInput) advFragInput.value = '';
				const csInput = document.getElementById('input-cipher-suites');
				if (csInput) csInput.value = '';
				const maskInput = document.getElementById('input-tls-mask');
				if (maskInput) maskInput.value = '';
				const advSettingsToggle = document.getElementById('input-advanced-settings-toggle');
				if (advSettingsToggle) advSettingsToggle.checked = false;
				if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(false);
				document.getElementById('hidden-auto-rotate').value = '0';
				document.getElementById('hidden-rotate-time').value = '';
				document.getElementById('hidden-ip-operator').value = 'all';
				document.getElementById('hidden-ip-count').value = '15';
				const autoResetToggle = document.getElementById('input-auto-reset-toggle');
				if (autoResetToggle) autoResetToggle.checked = false;
				document.getElementById('input-auto-reset-vol').value = '';
				document.getElementById('input-auto-reset-req').value = '';
				window.toggleAutoResetInputs(false); if (typeof window.resetAnnounceInputs === 'function') window.resetAnnounceInputs();
				const startOnFirstConnectCheck = document.getElementById('input-start-on-first-connect');
				if (startOnFirstConnectCheck) startOnFirstConnectCheck.checked = false;
			}
		}
		function toggleUpdateModal(show, version = '') {
			if (show && version) document.getElementById('update-modal-text').innerHTML = 'نسخه جدید (<b>v' + version + '</b>) در دسترس است.<br>اگر آپدیت خودکار عمل نکرد لطفا از ربات استفاده کنید.';
			setModalState('update-modal', show);
		}
		async function createDirectUser(btn) {
			if (window.isQuickCreateLocked) {
				showToast('⏳ لطفاً ۵ ثانیه صبر کنید...', 'error');
				return;
			}
			window.isQuickCreateLocked = true;
			btn.disabled = true;
			const icon = btn.querySelector('svg');
			if (icon) {
				icon.classList.add('animate-spin');
				icon.classList.remove('group-hover:rotate-12');
			}
			try {
				const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
				let randStr = '';
				for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
				const username = randStr;
				
				let availableIps = [];
				if (Object.keys(cachedIpsData).length === 0) {
					try {
						const resIps = await fetchWithFallbackUI('ips.txt');
						if (resIps.ok) {
							const text = await resIps.text();
							const blocks = text.split('----------');
							blocks.forEach(block => {
								const lines = block.trim().split('\\n').map(l => l.trim()).filter(l => l.length > 0);
								lines.forEach(line => {
									if (!line.includes('#') && !line.startsWith('[source')) availableIps.push(line);
								});
							});
						}
					} catch(e) {}
				} else {
					Object.values(cachedIpsData).forEach(ips => { availableIps = availableIps.concat(ips); });
				}
				availableIps = [...new Set(availableIps)];
				let selectedIps = [];
				if (availableIps.length > 0) {
					const shuffledIps = availableIps.slice();
					for (let i = shuffledIps.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[shuffledIps[i], shuffledIps[j]] = [shuffledIps[j], shuffledIps[i]];
					}
					selectedIps = shuffledIps.slice(0, 30);
				}
				const ipsStr = selectedIps.join('\\n');
				
				const response = await fetch('/api/users', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						username: username, limit_gb: null, expiry_days: null, limit_req: null, ip_limit: null,
						auto_reset_vol_days: 0, auto_reset_req_days: 0, frag_len: "", frag_int: "",
						fingerprint: "unsafe", block_ads: 1, block_porn: 0, port: "443", tls: "on",
						ips: ipsStr, ip_operator: "all", ip_count: 30, auto_rotate_ip: 1, rotate_time: 5,
						user_socks5: null, auto_rotate_user_proxy: 0, connection_type: "vless", enable_direct: true
					})
				});
				if (response.ok) {
					showToast('✅ کاربر مستقیم (بدون پروکسی) با موفقیت ایجاد شد.');
					await loadUsers(true);
				} else {
					const errData = await response.json();
					alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			} finally {
				setTimeout(() => {
					window.isQuickCreateLocked = false;
					btn.disabled = false;
					if (icon) {
						icon.classList.remove('animate-spin');
						icon.classList.add('group-hover:rotate-12');
					}
				}, 1000); 
			}
		}
		async function quickCreateUser(btn) {
			if (window.isQuickCreateLocked) {
				showToast('⏳ لطفاً ۵ ثانیه صبر کنید...', 'error');
				return;
			}
			window.isQuickCreateLocked = true;
			btn.disabled = true;
			const icon = btn.querySelector('svg');
			if (icon) {
				icon.classList.add('animate-spin');
				icon.classList.remove('group-hover:rotate-12');
			}
			try {
				const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
				let randStr = '';
				for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
				const username = randStr;
				
				if (!cachedVipList || cachedVipList.length === 0) {
					await initVipCache();
				}
				
				let vipCountries = cachedVipList ? [...cachedVipList] : [];
				
				if (vipCountries.length < 1) {
					const fallbackCountries = ["DE", "US", "GB", "NL", "FR", "TR"];
					await Promise.all(fallbackCountries.map(async (country) => {
						try {
							const resVip = await fetchWithFallbackUI('proxy_vip/' + country + '.txt');
							if (resVip.ok) {
								const text = await resVip.text();
								const lines = text.split('\\n').map(l => l.trim()).filter(l => l.length > 5);
								if (lines.length > 0) {
									cachedVipProxies[country] = lines;
									vipCountries.push(country);
								}
							}
						} catch(e) {}
					}));
				}
				
				if (vipCountries.length < 1) {
					alert('خطا: مخزن VIP شما در دسترس نیست یا ارتباط سرور کلودفلر قطع است.');
					btn.disabled = false;
					if (icon) {
						icon.classList.remove('animate-spin');
						icon.classList.add('group-hover:rotate-12');
					}
					return;
				}
				
				for (let i = vipCountries.length - 1; i > 0; i--) {
					const j = Math.floor(Math.random() * (i + 1));
					[vipCountries[i], vipCountries[j]] = [vipCountries[j], vipCountries[i]];
				}
				const selectedCountries = vipCountries.slice(0, 12);
				let candidateProxies = [];
				
				selectedCountries.forEach(country => {
					const lines = cachedVipProxies[country];
					if (lines && lines.length > 0) {
						lines.forEach(proxyLine => {
							candidateProxies.push({ proxy: proxyLine, country: country });
						});
					}
				});
				for (let i = candidateProxies.length - 1; i > 0; i--) {
					const j = Math.floor(Math.random() * (i + 1));
					[candidateProxies[i], candidateProxies[j]] = [candidateProxies[j], candidateProxies[i]];
				}
				const proxiesToTest = candidateProxies.slice(0, 50);
				const controller = new AbortController();
				let successProxies = [];
				let foundCountries = new Set();
				const racePromise = new Promise((resolveRace) => {
					let activeCount = 0;
					let isDone = false;
					if (proxiesToTest.length === 0) {
						resolveRace();
						return;
					}
					const fireRequests = async () => {
						for (const item of proxiesToTest) {
							if (isDone) break;
							activeCount++;
							
							const randomDelay = Math.floor(Math.random() * 9) + 2; 
							await new Promise(r => setTimeout(r, randomDelay));
							
							fetch('/api/test-proxy', {
								method: 'POST',
								headers: { 'Content-Type': 'application/json' },
								body: JSON.stringify({ proxy: item.proxy, skip_country: true }),
								signal: controller.signal
							})
							.then(res => res.json())
							.then(data => {
								if (isDone) return;
								if (data.success && !foundCountries.has(item.country)) {
									foundCountries.add(item.country);
									successProxies.push({ proxy: item.proxy, ping: data.ping });
									if (successProxies.length >= 6) {
										isDone = true;
										resolveRace();
									}
								}
							})
							.catch(() => {})
							.finally(() => {
								activeCount--;
								if (activeCount === 0 && !isDone) {
									resolveRace();
								}
							});
						}
					};
					fireRequests();
				});
				const timeoutPromise = new Promise(resolve => setTimeout(resolve, 8000));
				await Promise.race([racePromise, timeoutPromise]);
				controller.abort(); 
				if (successProxies.length === 0) {
					alert('خطا: هیچ پروکسی سالمی در زمان مجاز یافت نشد.');
					btn.disabled = false;
					if (icon) {
						icon.classList.remove('animate-spin');
						icon.classList.add('group-hover:rotate-12');
					}
					return;
				}
				successProxies.sort((a, b) => a.ping - b.ping);
				const fastestProxies = successProxies.slice(0, 6).map(p => p.proxy);
				const userSocks5 = JSON.stringify(fastestProxies);
				
				let availableIps = [];
				if (Object.keys(cachedIpsData).length === 0) {
					try {
						const resIps = await fetchWithFallbackUI('ips.txt');
						if (resIps.ok) {
							const text = await resIps.text();
							const blocks = text.split('----------');
							blocks.forEach(block => {
								const lines = block.trim().split('\\n').map(l => l.trim()).filter(l => l.length > 0);
								lines.forEach(line => {
									if (!line.includes('#') && !line.startsWith('[source')) availableIps.push(line);
								});
							});
						}
					} catch(e) {}
				} else {
					Object.values(cachedIpsData).forEach(ips => { availableIps = availableIps.concat(ips); });
				}
				availableIps = [...new Set(availableIps)];
				let selectedIps = [];
				if (availableIps.length > 0) {
					const shuffledIps = availableIps.slice();
					for (let i = shuffledIps.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[shuffledIps[i], shuffledIps[j]] = [shuffledIps[j], shuffledIps[i]];
					}
					selectedIps = shuffledIps.slice(0, 5);
				}
				const ipsStr = selectedIps.join('\\n');
				
				const response = await fetch('/api/users', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						username: username, limit_gb: null, expiry_days: null, limit_req: null, ip_limit: null,
						auto_reset_vol_days: 0, auto_reset_req_days: 0, frag_len: "", frag_int: "",
						fingerprint: "unsafe", block_ads: 1, block_porn: 0, port: "443", tls: "on",
						ips: ipsStr, ip_operator: "all", ip_count: 5, auto_rotate_ip: 1, rotate_time: 5,
						user_socks5: userSocks5, auto_rotate_user_proxy: 1, connection_type: "vless", enable_direct: false
					})
				});
				if (response.ok) {
					showToast('✅ کاربر مولتی لوکیشن با موفقیت ایجاد شد.');
					await loadUsers(true);
				} else {
					const errData = await response.json();
					alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			} finally {
				setTimeout(() => {
					window.isQuickCreateLocked = false;
					btn.disabled = false;
					if (icon) {
						icon.classList.remove('animate-spin');
						icon.classList.add('group-hover:rotate-12');
					}
				}, 1000); 
			}
		}
let activeRocketBtn = null;

function toggleRocketModal(show) {
	setModalState('rocket-modal', show);
}

async function openRocketModal(btn) {
	if (window.isQuickCreateLocked) {
		showToast('⏳ لطفاً کمی صبر کنید...', 'error');
		return;
	}
	activeRocketBtn = btn;
	toggleRocketModal(true);
	
	const select = document.getElementById('rocket-country-select');
	const submitBtn = document.getElementById('rocket-submit-btn');
	
	select.innerHTML = '<option value="">در حال بررسی مخزن...</option>';
	submitBtn.disabled = true;

	if (!cachedVipList || cachedVipList.length === 0) {
		await initVipCache();
	}

	if (cachedVipList && cachedVipList.length > 0) {
		select.innerHTML = '<option value="">یک کشور انتخاب کنید...</option>';
		cachedVipList.forEach(function(country) {
			const option = document.createElement('option');
			option.value = country;
			const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(country) : '🌐';
			option.textContent = flag + ' ' + country;
			select.appendChild(option);
		});
		submitBtn.disabled = false;
	} else {
		select.innerHTML = '<option value="">پـروکـسـی اختصاصی موجود نیست</option>';
	}
}

async function executeRocketCreate() {
	const select = document.getElementById('rocket-country-select');
	const country = select.value;
	if (!country) {
		alert('لطفاً یک کشور انتخاب کنید.');
		return;
	}
	toggleRocketModal(false);

	if (window.isQuickCreateLocked) return;
	window.isQuickCreateLocked = true;
	
	const btn = activeRocketBtn;
	if (btn) btn.disabled = true;
	const icon = btn ? btn.querySelector('svg') : null;
	if (icon) {
		icon.classList.add('animate-spin');
		icon.classList.remove('group-hover:-translate-y-1', 'group-hover:translate-x-1');
	}

	try {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		let randStr = '';
		for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
		const username = randStr;

		const lines = cachedVipProxies[country];
		if (!lines || lines.length === 0) {
			alert('هیچ پروکسی در این کشور یافت نشد.');
			return;
		}

		showToast('🚀 در حال اسکن پینگ ' + lines.length + ' پروکسی از کشور ' + country + '...');

		const controller = new AbortController();
		let successProxies = [];
		
		const testPromises = lines.map(async (proxyLine) => {
			await new Promise(r => setTimeout(r, Math.floor(Math.random() * 200)));
			try {
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: proxyLine, skip_country: true }), 
					signal: controller.signal
				});
				const data = await res.json();
				if (data.success && data.ping) {
					successProxies.push({ proxy: proxyLine, ping: data.ping });
				}
			} catch(e) {}
		});

		const timeoutPromise = new Promise(resolve => setTimeout(resolve, 12000));
		await Promise.race([Promise.all(testPromises), timeoutPromise]);
		controller.abort();

		if (successProxies.length === 0) {
			alert('خطا: هیچ پروکسی سالمی با پینگ موفق در این کشور یافت نشد.');
			return;
		}

		successProxies.sort((a, b) => a.ping - b.ping);
		const bestProxy = successProxies[0].proxy;
		
		let availableIps = [];
		if (Object.keys(cachedIpsData).length === 0) {
			try {
				const resIps = await fetchWithFallbackUI('ips.txt');
				if (resIps.ok) {
					const text = await resIps.text();
					const blocks = text.split('----------');
					blocks.forEach(block => {
						const l = block.trim().split('\\n').map(x => x.trim()).filter(x => x.length > 0);
						l.forEach(line => {
							if (!line.includes('#') && !line.startsWith('[source')) availableIps.push(line);
						});
					});
				}
			} catch(e) {}
		} else {
			Object.values(cachedIpsData).forEach(ips => { availableIps = availableIps.concat(ips); });
		}
		
		availableIps = [...new Set(availableIps)];
		let selectedIps = [];
		
		if (availableIps.length > 0) {
			const shuffledIps = availableIps.slice();
			for (let i = shuffledIps.length - 1; i > 0; i--) {
				const j = Math.floor(Math.random() * (i + 1));
				[shuffledIps[i], shuffledIps[j]] = [shuffledIps[j], shuffledIps[i]];
			}
			selectedIps = shuffledIps.slice(0, 30); 
		}
		const ipsStr = selectedIps.join('\\n');

		const finalSocks5 = JSON.stringify([{ proxy: bestProxy, country: country }]);

		const response = await fetch('/api/users', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username: username, limit_gb: null, expiry_days: null, limit_req: null, ip_limit: null,
				auto_reset_vol_days: 0, auto_reset_req_days: 0, frag_len: "", frag_int: "",
				fingerprint: "unsafe", block_ads: 1, block_porn: 0, port: "443", tls: "on",
				ips: ipsStr, ip_operator: "all", ip_count: 30, auto_rotate_ip: 1, rotate_time: 5,
				user_socks5: finalSocks5, auto_rotate_user_proxy: 1, connection_type: "vless", enable_direct: false
			})
		});

		if (response.ok) {
			showToast('🚀 کاربر تک کشوره با بهترین پینگ با موفقیت ایجاد شد.');
			await loadUsers(true);
		} else {
			const errData = await response.json();
			alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
		}
	} catch(err) {
		alert('خطا در برقراری ارتباط با سرور');
	} finally {
		setTimeout(() => {
			window.isQuickCreateLocked = false;
			if (btn) {
				btn.disabled = false;
				if (icon) {
					icon.classList.remove('animate-spin');
					icon.classList.add('group-hover:-translate-y-1', 'group-hover:translate-x-1');
				}
			}
		}, 1000);
	}
}
		function openCreateModal() {
			isEditMode = false;
			editingUsername = '';
			document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
			updateSubmitBtnState('ایجاد کاربر');
			document.getElementById('input-name').disabled = false;
			document.getElementById('create-user-form').reset();
			const vlessCb2 = document.getElementById('input-proto-vless');
			const trojanCb2 = document.getElementById('input-proto-trojan');
			const ssCb2 = document.getElementById('input-proto-ss');
			if (vlessCb2) vlessCb2.checked = true;
			if (trojanCb2) trojanCb2.checked = false;
			if (ssCb2) ssCb2.checked = false;
			const cb443 = document.querySelector('input[name="ports"][value="443"]');
			if (cb443) cb443.checked = true;
			const cb80 = document.querySelector('input[name="ports"][value="80"]');
			if (cb80) cb80.checked = false;
			const fpSelect = document.getElementById('fingerprint-select');
			if (fpSelect) fpSelect.value = 'unsafe';
			const fragToggle = document.getElementById('input-frag-toggle');
			if (fragToggle) fragToggle.checked = false;
			if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(false);
			const autoResetToggle = document.getElementById('input-auto-reset-toggle');
			if (autoResetToggle) autoResetToggle.checked = false;
			document.getElementById('input-auto-reset-vol').value = '';
			document.getElementById('input-auto-reset-req').value = '';
			window.toggleAutoResetInputs(false); if (typeof window.resetAnnounceInputs === 'function') window.resetAnnounceInputs();
			const blockAdsToggle = document.getElementById('input-block-ads');
			if (blockAdsToggle) blockAdsToggle.checked = true;
			const autoRotateUserProxyCheck = document.getElementById('input-auto-rotate-user-proxy');
			if (autoRotateUserProxyCheck) autoRotateUserProxyCheck.checked = false;
			const startOnFirstConnectCheck = document.getElementById('input-start-on-first-connect');
			if (startOnFirstConnectCheck) startOnFirstConnectCheck.checked = false;
			const userProxyToggle = document.getElementById('user-proxy-mode-toggle');
			if (userProxyToggle) userProxyToggle.checked = false;
			if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(false);
			const enableDirectCheck = document.getElementById('input-enable-direct');
			if (enableDirectCheck) enableDirectCheck.checked = true;
			window.proxyFieldsData = [""];
			window.activeProxyIndex = 0;
			if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
			const autoRotateIpToggle = document.getElementById('input-auto-rotate-ip-toggle');
			if (autoRotateIpToggle) autoRotateIpToggle.checked = false;
			document.getElementById('hidden-rotate-time').value = '';
			document.getElementById('hidden-ip-operator').value = 'all';
			document.getElementById('hidden-ip-count').value = '15';
			toggleModal(true);
		}
		
		const themeToggleBtn = document.getElementById('theme-toggle');
		themeToggleBtn.addEventListener('click', () => {
			if (document.documentElement.classList.contains('dark')) {
				document.documentElement.classList.remove('dark');
				localStorage.setItem('color-theme', 'light');
			} else {
				document.documentElement.classList.add('dark');
				localStorage.setItem('color-theme', 'dark');
			}
		});
		
		const grayscaleToggleBtn = document.getElementById('grayscale-toggle');
		if (grayscaleToggleBtn) {
			grayscaleToggleBtn.addEventListener('click', () => {
				if (document.documentElement.classList.contains('grayscale-active')) {
					document.documentElement.classList.remove('grayscale-active');
					localStorage.setItem('grayscale-theme', 'false');
				} else {
					document.documentElement.classList.add('grayscale-active');
					localStorage.setItem('grayscale-theme', 'true');
					// RGB و سیاه‌سفید با هم سازگار نیستند
					if (typeof stopRgbMode === 'function') stopRgbMode(true);
				}
			});
		}
		/* ---- RGB / Rainbow mode ---- */
		window.__rgbRaf = null;
		window.__rgbHue = 0;
		function __hslToRgbTriplet(h, s, l) {
			s /= 100; l /= 100;
			const k = n => (n + h / 30) % 12;
			const a = s * Math.min(l, 1 - l);
			const f = n => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
			return [Math.round(255 * f(0)), Math.round(255 * f(8)), Math.round(255 * f(4))].join(' ');
		}
		function __applyRgbHue(hue) {
			const root = document.documentElement;
			root.style.setProperty('--rgb-hue', String(hue));
			// map a full shade ladder so buttons / borders / progress all wave
			const shades = [
				[50, 95], [100, 90], [200, 80], [300, 70], [400, 62],
				[500, 55], [600, 48], [700, 40], [800, 32], [900, 25], [950, 15]
			];
			for (const [name, light] of shades) {
				const rgb = __hslToRgbTriplet(hue, 90, light);
				root.style.setProperty('--a' + name, rgb);
			}
			// hex-ish fallbacks for --t* (used by waves / cursors)
			const toHex = (triplet) => '#' + triplet.split(' ').map(x => (+x).toString(16).padStart(2, '0')).join('');
			for (const [name, light] of shades) {
				if (name === 950) continue;
				root.style.setProperty('--t' + name, toHex(__hslToRgbTriplet(hue, 90, light)));
			}
		}
		function __rgbTick() {
			window.__rgbHue = (window.__rgbHue + 0.6) % 360;
			__applyRgbHue(window.__rgbHue);
			window.__rgbRaf = requestAnimationFrame(__rgbTick);
		}
		function startRgbMode() {
			const root = document.documentElement;
			root.classList.add('rgb-active');
			root.classList.remove('grayscale-active');
			localStorage.setItem('grayscale-theme', 'false');
			localStorage.setItem('rgb-theme', 'true');
			if (window.__rgbRaf) cancelAnimationFrame(window.__rgbRaf);
			window.__rgbRaf = requestAnimationFrame(__rgbTick);
			const st = document.getElementById('rgb-settings-toggle');
			if (st) st.checked = true;
		}
		function stopRgbMode(skipToast) {
			const root = document.documentElement;
			root.classList.remove('rgb-active');
			localStorage.setItem('rgb-theme', 'false');
			if (window.__rgbRaf) { cancelAnimationFrame(window.__rgbRaf); window.__rgbRaf = null; }
			// clear inline overrides so static theme (or default) returns
			['50','100','200','300','400','500','600','700','800','900','950'].forEach(function(n) {
				root.style.removeProperty('--a' + n);
				root.style.removeProperty('--t' + n);
			});
			root.style.removeProperty('--rgb-hue');
			const st = document.getElementById('rgb-settings-toggle');
			if (st) st.checked = false;
		}
		window.toggleRgbMode = function(forceOn) {
			const wantOn = (typeof forceOn === 'boolean')
				? forceOn
				: !document.documentElement.classList.contains('rgb-active');
			if (wantOn) {
				startRgbMode();
				if (typeof showToast === 'function') showToast('🌈 حالت RGB فعال شد — رنگ‌ها موج می‌زنند');
			} else {
				stopRgbMode();
				if (typeof showToast === 'function') showToast('حالت RGB خاموش شد');
			}
		};
		const rgbToggleBtn = document.getElementById('rgb-toggle');
		if (rgbToggleBtn) {
			rgbToggleBtn.addEventListener('click', function () { window.toggleRgbMode(); });
		}
		// restore after load
		if (localStorage.getItem('rgb-theme') === 'true') {
			startRgbMode();
		}
		async function handleCoreAction(actionType, token = null) {
			window.pendingCoreAction = actionType;
			const isUpdate = actionType === 'update';
			if (!isUpdate && !await customConfirm('آیا از ری استارت پـنـل مطمئن هستید؟ کاربران شما لحظه ای قطع خواهند شد.')) return;
			if (isUpdate && !token) toggleUpdateModal(false);
			const btn = isUpdate ? document.getElementById('update-toggle') : document.querySelector('button[title="ری استارت پـنـل"]');
			if (btn) {
				btn.disabled = true;
				if (!isUpdate) btn.classList.add('animate-pulse');
			}
			if (isUpdate && !token) alert('در حال دریافت و اعمال آپدیت... لطفاً چند ثانیه صبر کنید.');
			try {
				const reqBody = token ? JSON.stringify({ cf_token: token }) : "{}";
				const res = await fetch(isUpdate ? '/api/update-panel' : '/api/restart-core', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: isUpdate ? reqBody : undefined
				});
				const data = await res.json();
				if (res.status === 400 && data.error === "TOKEN_REQUIRED") {
					toggleTokenModal(true);
					if (btn) {
						btn.disabled = false;
						if (!isUpdate) btn.classList.remove('animate-pulse');
					}
					return;
				}
				if (res.ok && data.success) {
					if (isUpdate) {
						const successModal = document.getElementById('update-success-modal');
						const successCard = successModal.querySelector('div');
						successModal.classList.remove('opacity-0', 'pointer-events-none');
						successModal.classList.add('opacity-100', 'pointer-events-auto');
						successCard.classList.remove('opacity-0', 'scale-95');
						successCard.classList.add('opacity-100', 'scale-100');
						setTimeout(() => {
							sessionStorage.setItem('caspian_last_update', Date.now());
							window.location.href = window.location.pathname + '?t=' + Date.now();
						}, 10000);
					} else {
						alert('پـنـل ری استارت شد صفحه رفرش می شود.');
						window.location.href = window.location.pathname + '?t=' + Date.now();
					}
				} else {
					alert(isUpdate ? ('خطا در بروزرسانی: ' + (data.error || 'ناشناخته') + '\n\nاگر مشکل ادامه داشت از آپدیت دستی استفاده کنید.') : ('خطا در ری‌استارت پـن‌ل: ' + (data.error || 'ناشناخته')));
					if (btn) {
						btn.disabled = false;
						if (!isUpdate) btn.classList.remove('animate-pulse');
					}
				}
			} catch (err) {
				alert(isUpdate ? 'خطا در ارتباط با سرور. لطفاً از گزینه آپدیت دستی استفاده کنید.' : 'خطا در ارتباط با سرور.');
				if (btn) {
					btn.disabled = false;
					if (!isUpdate) btn.classList.remove('animate-pulse');
				}
			}
		}
		async function restartCore() {
			await handleCoreAction('restart');
		}
		async function loadUsers(silent = false) {
			if (window.isDraggingRow) return; 
			const loadingState = document.getElementById('loading-state');
			const tableContainer = document.getElementById('users-table-container');
			const emptyState = document.getElementById('empty-state');
			if (!silent) {
				loadingState.classList.remove('hidden');
				tableContainer.classList.add('hidden');
				emptyState.classList.add('hidden');
			}
			try {
				const res = await fetch('/api/users?t=' + Date.now());
				if (!res.ok) throw new Error();
				const data = await res.json();
				renderUsersUI(data);
			} catch (err) {
				if (!silent) {
					loadingState.innerHTML = '<span class="text-red-500">خطا در دریافت اطلاعات از سرور</span>';
				}
			}
		}
		function renderUsersUI(data) {
			try {
				if (data.error) {
					let errorText = data.error;
					if (errorText.toLowerCase().includes('d1') && (errorText.toLowerCase().includes('limit') || errorText.toLowerCase().includes('exceeded'))) {
						errorText = 'سهمیه دیتابیس شما تمام شده و ساعت 3:30 درست میشه';
					}
					document.getElementById('loading-state').innerHTML = '<span class="text-red-500 font-bold px-4 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg inline-block">❌ ' + errorText + '</span>';
					document.getElementById('loading-state').classList.remove('hidden');
					document.getElementById('users-table-container').classList.add('hidden');
					document.getElementById('empty-state').classList.add('hidden');
					return;
				}
				const users = data.users || [];
				
				window.smoothCache = window.smoothCache || {};
				const nowMs = Date.now();
				users.forEach(u => {
					let cache = window.smoothCache[u.username];
					if (!cache) {
						cache = { gb: u.used_gb, req: u.used_req, onlineHistory: [] };
					}
					
					if (u.used_gb < cache.gb && (cache.gb - u.used_gb) < 2.0) {
						u.used_gb = cache.gb;
					} else {
						cache.gb = u.used_gb;
					}
					
					if (u.used_req < cache.req && (cache.req - u.used_req) < 20000) {
						u.used_req = cache.req;
					} else {
						cache.req = u.used_req;
					}
					
					cache.onlineHistory = cache.onlineHistory.filter(h => nowMs - h.time <= 10000);
					cache.onlineHistory.push({ time: nowMs, count: u.online_count || 0 });
					u.online_count = Math.max(...cache.onlineHistory.map(h => h.count));
					
					window.smoothCache[u.username] = cache;
				});

				window.allUsers = users;
				const serverTime = data.serverTime || Date.now();
				window.lastServerTime = serverTime;
				const totalUsersCount = users.length;
				const activeUsersCount = users.reduce((sum, u) => sum + (u.online_count || 0), 0);
				const deletedGb = data.deletedGb || 0;
				const totalGbUsage = deletedGb + users.reduce((sum, u) => sum + (u.lifetime_used_gb || u.used_gb || 0), 0);
				document.getElementById('stat-total-users').innerText = totalUsersCount;
				document.getElementById('stat-active-users').innerText = activeUsersCount;
				document.getElementById('stat-total-usage').innerText = totalGbUsage < 1 ? (totalGbUsage * 1024).toFixed(0) + ' MB' : totalGbUsage.toFixed(2) + ' GB';
				const d1Reads = data.d1Reads || 0;
				const d1Writes = data.d1Writes || 0;
				const d1WritesEl = document.getElementById('stat-d1-writes');
				if (d1WritesEl) d1WritesEl.innerText = d1Writes >= 1000 ? (d1Writes / 1000).toFixed(1) + 'k' : d1Writes;
				const d1ReadsEl = document.getElementById('stat-d1-reads');
				if (d1ReadsEl) d1ReadsEl.innerText = d1Reads >= 1000000 ? (d1Reads / 1000000).toFixed(2) + 'M' : (d1Reads >= 1000 ? (d1Reads / 1000).toFixed(1) + 'k' : d1Reads);
				const rawCfRequests = data.cfRequestsToday || 0;
				window.maxCfRequestsToday = Math.max(window.maxCfRequestsToday || 0, rawCfRequests);
				const cfRequests = window.maxCfRequestsToday;
				
				const reqCard = document.getElementById('card-cf-requests');
				const warningBtn = document.getElementById('cf-warning-btn');
				if (cfRequests >= 90000) {
					if (reqCard) {
						reqCard.className = "bg-red-50 dark:bg-red-950/20 border border-red-500 rounded-md p-2.5 shadow-[0_0_15px_rgb(var(--a500,239_68_68)/0.4)] flex flex-col justify-center gap-1 hover:shadow-md transition duration-300 relative overflow-hidden group min-h-[64px] animate-pulse";
					}
					if (warningBtn) {
						warningBtn.classList.remove('hidden');
					}
					if (!window.hasShownUsageWarning) {
						openUsageWarning();
						window.hasShownUsageWarning = true;
					}
				} else {
					if (reqCard) {
						reqCard.className = "bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-orange-400 dark:hover:border-orange-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]";
					}
					if (warningBtn) {
						warningBtn.classList.add('hidden');
					}
				}
				const rawCfTotal = data.cfRequestsTotal || 0;
				window.maxCfTotal = Math.max(window.maxCfTotal || 0, rawCfTotal);
				const cfTotal = window.maxCfTotal;
				
				document.getElementById('stat-cf-requests').innerText = cfRequests >= 1000 ? (cfRequests / 1000).toFixed(1) + 'k' : cfRequests;
				document.getElementById('stat-cf-total').innerText = cfTotal >= 1000000 ? (cfTotal / 1000000).toFixed(2) + 'M' : (cfTotal >= 1000 ? (cfTotal / 1000).toFixed(1) + 'k' : cfTotal);
				const progressPercent = Math.min((cfRequests / 100000) * 100, 100);
				document.getElementById('stat-cf-progress').style.width = progressPercent + '%';
				filterAndRenderUsers();
			} catch (err) {
				document.getElementById('loading-state').innerHTML = '<span class="text-red-500">خطا در پردازش اطلاعات کاربران</span>';
			}
		}
		function filterAndRenderUsers() {
			if (!window.allUsers) return;
			const searchQuery = (document.getElementById('search-input').value || '').toLowerCase().trim();
			const filterStatus = document.getElementById('filter-status').value;
			const sortVal = document.getElementById('sort-users').value;
			const serverTime = window.lastServerTime || Date.now();
			let filtered = [...window.allUsers];
			if (searchQuery) {
				filtered = filtered.filter(u => 
					(u.username || '').toLowerCase().includes(searchQuery) || 
					(u.uuid || '').toLowerCase().includes(searchQuery)
				);
			}
			if (filterStatus !== 'all') {
				filtered = filtered.filter(u => {
					const isOnline = u.is_online === 1;
					const isActive = u.is_active === 1;
					let isExpired = false;
					if (u.limit_gb && u.used_gb >= u.limit_gb) isExpired = true;
					if (u.expiry_days) {
						if (u.start_on_first_connect === 1) {
							if (u.first_connection_time) {
								const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 24 * 60 * 60 * 1000));
								if (new Date(serverTime) > expiryDate) isExpired = true;
							}
						} else if (u.created_at) {
							const created = new Date(u.created_at);
							const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
							if (new Date(serverTime) > expiryDate) isExpired = true;
						}
					}
					if (filterStatus === 'active') return isActive && !isExpired;
					if (filterStatus === 'inactive') return !isActive;
					if (filterStatus === 'online') return isOnline;
					if (filterStatus === 'offline') return !isOnline;
					if (filterStatus === 'expired') return isExpired || !isActive;
					return true;
				});
			}
			const customOrderStr = localStorage.getItem('caspian_users_custom_order');
			let customOrder = [];
			try { customOrder = JSON.parse(customOrderStr || '[]'); } catch(e) {}
			filtered.sort((a, b) => {
				if (sortVal === 'newest' && customOrder.length > 0) {
					const indexA = customOrder.indexOf(a.username);
					const indexB = customOrder.indexOf(b.username);
					if (indexA !== -1 && indexB !== -1) return indexA - indexB;
					if (indexA !== -1) return -1;
					if (indexB !== -1) return 1;
				}
				if (sortVal === 'newest') {
					return b.id - a.id;
				}
				if (sortVal === 'name') {
					return (a.username || '').localeCompare(b.username || '');
				}
				if (sortVal === 'usage-desc') {
					return (b.used_gb || 0) - (a.used_gb || 0);
				}
				if (sortVal === 'usage-asc') {
					return (a.used_gb || 0) - (b.used_gb || 0);
				}
				if (sortVal === 'expiry-asc') {
					const getRemaining = (u) => {
						if (!u.expiry_days) return Infinity;
						if (u.start_on_first_connect === 1) {
							if (!u.first_connection_time) return u.expiry_days * 86400000;
							const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 86400000));
							return expiryDate - new Date(serverTime);
						}
						if (!u.created_at) return Infinity;
						const created = new Date(u.created_at);
						const expiryDate = new Date(created.getTime() + (u.expiry_days * 86400000));
						return expiryDate - new Date(serverTime);
					};
					return getRemaining(a) - getRemaining(b);
				}
				return 0;
			});
			renderFilteredUsers(filtered, serverTime);
		}
		function renderFilteredUsers(users, serverTime) {
			const loadingState = document.getElementById('loading-state');
			const tableContainer = document.getElementById('users-table-container');
			const emptyState = document.getElementById('empty-state');
			const tbody = document.getElementById('users-tbody');
			if (users.length === 0) {
					loadingState.classList.add('hidden');
					emptyState.classList.remove('hidden');
					tableContainer.classList.add('hidden');
					
					emptyState.querySelector('p').className = 'text-red-600 dark:text-red-400 font-bold text-lg flex items-center justify-center flex-wrap gap-2 leading-loose';
					
					if (window.allUsers && window.allUsers.length > 0) {
						emptyState.querySelector('p').innerHTML = 'کاربری با مشخصات جستجو شده یافت نشد.';
					} else {
						emptyState.querySelector('p').innerHTML = '<span>کاربری وجود ندارد. برای ساخت کاربر روی</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-green-50 dark:bg-green-950/30 border border-green-600 dark:border-green-700/60 text-green-700 dark:text-green-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg></span>' +
							'<span>کلیک کنید یا از دکمه‌های</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-500 text-cyan-600 dark:text-cyan-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path><path d="M2 12h20"></path></svg></span>' +
							'<span>،</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-orange-50 dark:bg-orange-950/40 border border-orange-500 text-orange-600 dark:text-orange-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"></path></svg></span>' +
							'<span>و</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-500 text-indigo-600 dark:text-indigo-400 shadow-sm"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></span>' +
							'<span>برای ایجاد سریع استفاده کنید.</span>';
					}
			} else {
				loadingState.classList.add('hidden');
				emptyState.classList.add('hidden');
				tableContainer.classList.remove('hidden');
				let proxyFlagCache = {};
				try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
				tbody.innerHTML = users.map(user => {
					let daysRemaining = 'نامحدود';
					let daysPercent = 100;
					let isTimerPending = false;
					if (user.expiry_days) {
						if (user.start_on_first_connect === 1) {
							if (!user.first_connection_time) {
								daysRemaining = user.expiry_days;
								daysPercent = 100;
								isTimerPending = true;
							} else {
								const expiryDate = new Date(user.first_connection_time + (user.expiry_days * 24 * 60 * 60 * 1000));
								const diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
								daysRemaining = diffDays > 0 ? diffDays : 0;
								daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
							}
						} else if (user.created_at) {
							const created = new Date(user.created_at);
							const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
							const diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
							daysRemaining = diffDays > 0 ? diffDays : 0;
							daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
						} else {
							daysRemaining = user.expiry_days;
						}
					}
					const usedGb = user.used_gb || 0;
					const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
					const usedReq = user.used_req || 0;
					let reqHtml = '';
					if (user.limit_req) {
						const reqPercent = Math.min((usedReq / user.limit_req) * 100, 100);
						const reqHue = 120 - (reqPercent * 1.2);
						reqHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="ltr">' + usedReq.toLocaleString() + '</span>' +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="req" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست" class="mx-1.5 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none font-bold" dir="ltr">' + user.limit_req.toLocaleString() + '</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + reqPercent + '%; background-color: ' + __usageColor(reqHue) + '"></div>' +
							'</div>' +
						'</div>';
					} else {
						reqHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="ltr">' + usedReq.toLocaleString() + '</span>' +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="req" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست" class="mx-1.5 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none text-[12px] font-bold">∞</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="w-full h-full bg-blue-500 rounded-full transition-all duration-500"></div>' +
							'</div>' +
						'</div>';
					}
					let volumeHtml = '';
					if (user.limit_gb) {
						const limitPercent = Math.min((usedGb / user.limit_gb) * 100, 100);
						const limitHue = 120 - (limitPercent * 1.2);
						const formattedLimit = user.limit_gb < 1 ? (user.limit_gb * 1024).toFixed(0) + 'MB' : user.limit_gb + 'GB';
						const formattedUsedClean = usedGb < 1 ? (usedGb * 1024).toFixed(0) + 'MB' : usedGb.toFixed(2) + 'GB';
						volumeHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="ltr">' + formattedUsedClean + '</span>' +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="volume" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست" class="mx-1.5 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none font-bold" dir="ltr">' + formattedLimit + '</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + limitPercent + '%; background-color: ' + __usageColor(limitHue) + '"></div>' +
							'</div>' +
						'</div>';
					} else {
						const formattedUsedClean = usedGb < 1 ? (usedGb * 1024).toFixed(0) + 'MB' : usedGb.toFixed(2) + 'GB';
						volumeHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="ltr">' + formattedUsedClean + '</span>' +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="volume" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست" class="mx-1.5 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none text-[12px] font-bold">∞</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="w-full h-full bg-blue-500 rounded-full transition-all duration-500"></div>' +
							'</div>' +
						'</div>';
					}
					if (user.daily_limit_gb) {
						const dailyUsedLive = user.daily_used_gb || 0;
						const dailyStep = user.daily_lock_step || 0;
						const dailyWindowUsed = Math.max(0, dailyUsedLive - dailyStep);
						const dailyPercent = Math.min((dailyWindowUsed / user.daily_limit_gb) * 100, 100);
						const dailyHue = 120 - (dailyPercent * 1.2);
						const isDailyLockedNow = user.daily_lock_until && Date.now() < user.daily_lock_until;
						const formattedDailyUsed = dailyWindowUsed < 1 ? (dailyWindowUsed * 1024).toFixed(0) + 'MB' : dailyWindowUsed.toFixed(1) + 'GB';
						const formattedDailyLimit = user.daily_limit_gb < 1 ? (user.daily_limit_gb * 1024).toFixed(0) + 'MB' : user.daily_limit_gb + 'GB';
						volumeHtml += '<div class="flex flex-col gap-1 w-full min-w-[65px] max-w-[90px] mx-auto select-none mt-1.5 pt-1.5 border-t border-dashed border-gray-300 dark:border-zinc-700">' +
							'<div class="flex flex-row items-center justify-between text-[8px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="' + (isDailyLockedNow ? 'text-red-500' : 'text-gray-800 dark:text-zinc-200') + ' leading-none font-bold" dir="ltr">' + (isDailyLockedNow ? '🔒 ' : '') + formattedDailyUsed + '</span>' +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="daily" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست روزانه" class="mx-1 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none font-bold" dir="ltr">' + formattedDailyLimit + '/روز</span>' +
							'</div>' +
							'<div class="w-full h-1 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + dailyPercent + '%; background-color: ' + (isDailyLockedNow ? '#ef4444' : __usageColor(dailyHue)) + '"></div>' +
							'</div>' +
						'</div>';
					}
					let expiryHtml = '';
					if (user.expiry_days) {
						const expiryHue = daysPercent * 1.2;
						const remainingLabel = isTimerPending ? '<span class="text-blue-600 dark:text-blue-400 leading-none font-bold text-[8px]" dir="rtl" title="شمارش پس از اولین اتصال آغاز می‌شود">' + daysRemaining + ' روز (اولین اتصال)</span>' : '<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="rtl">' + daysRemaining + ' روز</span>';
						expiryHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								remainingLabel +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="time" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست" class="mx-1.5 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none font-bold" dir="rtl">' + user.expiry_days + ' روز</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden flex justify-end">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + daysPercent + '%; background-color: ' + (isTimerPending ? 'rgb(var(--a500, 59 130 246))' : __usageColor(expiryHue)) + '"></div>' +
							'</div>' +
						'</div>';
					} else {
						expiryHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold text-[12px]">∞</span>' +
								'<button data-user="' + encodeURIComponent(user.username) + '" data-action="time" onclick="resetUserData(this.dataset.user, this.dataset.action)" title="ریست" class="mx-1.5 w-3.5 h-3.5 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full border border-amber-200 dark:border-amber-800 transition shadow-sm cursor-pointer flex-shrink-0"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
								'<span class="leading-none text-[12px] font-bold">∞</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="w-full h-full bg-blue-500 rounded-full transition-all duration-500"></div>' +
							'</div>' +
						'</div>';
					}
					const onlineCount = user.online_count || 0;
					const limit = user.ip_limit !== undefined ? user.ip_limit : user.max_connections;
					let onlineHtml = '';
					if (limit) {
						const onlinePercent = Math.min((onlineCount / limit) * 100, 100);
						const onlineHue = 120 - (onlinePercent * 1.2);
						onlineHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="ltr">' + onlineCount + '</span>' +
								'<span class="leading-none font-bold" dir="ltr">' + limit + '</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + onlinePercent + '%; background-color: ' + __usageColor(onlineHue) + '"></div>' +
							'</div>' +
						'</div>';
					} else {
						onlineHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[65px] max-w-[90px] mx-auto select-none">' +
							'<div class="flex flex-row items-center justify-between text-[9px] text-gray-500 dark:text-gray-400 font-medium whitespace-nowrap">' +
								'<span class="text-gray-800 dark:text-zinc-200 leading-none font-bold" dir="ltr">' + onlineCount + '</span>' +
								'<span class="leading-none text-[12px] font-bold">∞</span>' +
							'</div>' +
							'<div class="w-full h-1.5 bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden">' +
								'<div class="h-full ' + (onlineCount > 0 ? 'bg-green-600' : 'bg-gray-400') + ' rounded-full transition-all duration-500" style="width: 100%"></div>' +
							'</div>' +
						'</div>';
					}
					let isExpired = false;
					if (user.limit_gb && (user.used_gb || 0) >= user.limit_gb) isExpired = true;
					if (user.limit_req && (user.used_req || 0) >= user.limit_req) isExpired = true;
					if (user.expiry_days) {
						if (user.start_on_first_connect === 1) {
							if (user.first_connection_time) {
								const expiryDate = new Date(user.first_connection_time + (user.expiry_days * 24 * 60 * 60 * 1000));
								if (new Date(serverTime) > expiryDate) isExpired = true;
							}
						} else if (user.created_at) {
							const created = new Date(user.created_at);
							const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
							if (new Date(serverTime) > expiryDate) isExpired = true;
						}
					}
					const isEffectivelyActive = user.is_active !== 0 && !isExpired;
					const statusBtnColor = user.is_active === 0 ? 'text-green-700 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/30' : 'text-amber-600 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/30';
					const statusBtnTitle = user.is_active === 0 ? 'فعال کردن کاربر' : 'قطع کردن کاربر';
					const statusBtnIcon = user.is_active === 0 
						? '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
						: '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
					const isChecked = (window.selectedUsernames && window.selectedUsernames.has(user.username)) ? 'checked' : '';
					let locBadge = '';
					if (user.user_proxy_iata) {
						const iata = user.user_proxy_iata.toUpperCase();
						const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(iata) : '🌐';
						locBadge = '<div class="flex justify-center mt-1"><span title="کشور: ' + iata + '" class="text-base leading-none drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)]">' + flag + '</span></div>';
					} else if (user.user_socks5 || user.user_proxy_ip) {
						let proxyList = [];
						try {
							if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
								proxyList = JSON.parse(user.user_socks5);
							} else {
								proxyList = [user.user_socks5 || user.user_proxy_ip];
							}
						} catch(e) {
							proxyList = [user.user_socks5 || user.user_proxy_ip];
						}
						
						let numFlags = proxyList.length;
						let layout = [];
						
						if (numFlags === 1) layout = [1];
						else if (numFlags === 2) layout = [2];
						else if (numFlags === 3) layout = [3];
						else if (numFlags === 4) layout = [2, 2];
						else if (numFlags === 5) layout = [3, 2];
						else if (numFlags === 6) layout = [3, 3];
						else if (numFlags === 7) layout = [4, 3];
						else if (numFlags === 8) layout = [4, 4];
						else if (numFlags === 9) layout = [5, 4];
						else if (numFlags === 10) layout = [4, 4, 2];
						else if (numFlags === 11) layout = [4, 4, 3];
						else if (numFlags === 12) layout = [4, 4, 4];
						else if (numFlags === 13) layout = [5, 5, 3];
						else if (numFlags === 14) layout = [5, 5, 4];
						else {
							let remaining = numFlags;
							while (remaining > 0) {
								layout.push(Math.min(remaining, 5));
								remaining -= 5;
							}
						}

						let flagSizeClass = 'text-base';
						if (numFlags > 12) flagSizeClass = 'text-[9px]';
						else if (numFlags >= 9) flagSizeClass = 'text-[10px]';
						else if (numFlags > 4) flagSizeClass = 'text-xs';
						
						const flagsHtmlArray = proxyList.map(item => {
							const targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
							const targetCountry = typeof item === 'object' && item !== null ? item.country : null;
							if (targetCountry && typeof getFlagEmoji === 'function') {
								return '<span title="کشور: ' + targetCountry + '" class="' + flagSizeClass + ' leading-none drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)] flex items-center justify-center">' + getFlagEmoji(targetCountry) + '</span>';
							}
							const cachedFlag = proxyFlagCache[targetProxy];
							if (cachedFlag && typeof cachedFlag === 'string' && /^[a-zA-Z]{2}$/.test(cachedFlag) && typeof getFlagEmoji === 'function') {
								return '<span title="پـروکـسـی اختصاصی" class="' + flagSizeClass + ' leading-none drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)] flex items-center justify-center">' + getFlagEmoji(cachedFlag) + '</span>';
							} else {
								return '<span data-proxy="' + targetProxy + '" title="پـروکـسـی اختصاصی" class="async-proxy-flag ' + flagSizeClass + ' leading-none drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)] flex items-center justify-center">⏳</span>';
							}
						});
						
						let rowsHtml = '';
						let startIndex = 0;
						for (let r = 0; r < layout.length; r++) {
							let rowCount = layout[r];
							let rowItems = flagsHtmlArray.slice(startIndex, startIndex + rowCount).join('');
							rowsHtml += '<div class="flex justify-center gap-0.5">' + rowItems + '</div>';
							startIndex += rowCount;
						}
						
						locBadge = '<div class="flex flex-col gap-0.5 justify-center items-center mt-1 w-max mx-auto" dir="ltr">' + rowsHtml + '</div>';
					}
					let proxyListConfig = [];
					try {
						if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
							proxyListConfig = JSON.parse(user.user_socks5);
						} else if (user.user_socks5 || user.user_proxy_ip) {
							proxyListConfig = [user.user_socks5 || user.user_proxy_ip];
						} else {
							proxyListConfig = [null];
						}
					} catch(e) {
						proxyListConfig = [user.user_socks5 || user.user_proxy_ip];
					}
					if (!Array.isArray(proxyListConfig) || proxyListConfig.length === 0) proxyListConfig = [];
					const allowDirectConfig = user.enable_direct !== 0;
					if (allowDirectConfig) {
						let hasDir = proxyListConfig.some(function(p) { return p === null || p === ""; });
						if (!hasDir) proxyListConfig.push(null);
					} else {
						proxyListConfig = proxyListConfig.filter(function(p) { return p !== null && p !== ""; });
					}
					if (proxyListConfig.length === 0) proxyListConfig = [null];
					let numProxies = proxyListConfig.length;
					let numIps = user.ips ? user.ips.split('\\n').filter(function(ip) { return ip.trim().length > 0; }).length : 1;
					if (numIps === 0) numIps = 1;
					let numPorts = String(user.port || '443').split(',').filter(function(p) { return p.trim().length > 0; }).length;
					if (numPorts === 0) numPorts = 1;
					const userConnType = String(user.connection_type || 'vless').toLowerCase();
					const enableVless = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan') && !userConnType.includes('shadowsocks'));
					const enableTrojan = userConnType.includes('trojan');
					const enableSS = userConnType.includes('shadowsocks');
					const protoCount = (enableVless ? 1 : 0) + (enableTrojan ? 1 : 0) + (enableSS ? 1 : 0);
					let totalConfigs = 3 + (numProxies * numIps * numPorts * (protoCount || 1));
					let configColorClass = 'text-green-800 dark:text-green-700';
					if (totalConfigs > 100) configColorClass = 'text-red-600 dark:text-red-500';
					else if (totalConfigs > 80) configColorClass = 'text-orange-500';
					else if (totalConfigs > 55) configColorClass = 'text-amber-500';
					else if (totalConfigs > 20) configColorClass = 'text-green-500';
					let configsCountHtml = '<span class="font-black text-base ' + configColorClass + '" dir="ltr">' + totalConfigs + '</span>';
					return '<tr class="group transition-all drop-shadow-sm bg-white/40 dark:bg-zinc-900/20" data-username="' + user.username + '">' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1 rounded-r-md border-y border-r border-gray-200 dark:border-zinc-800 text-center select-none">' +
									'<div class="flex items-center justify-center gap-1">' +
										'<input type="checkbox" name="select-user" value="' + encodeURIComponent(user.username) + '" onchange="onUserSelectChange(this)" ' + isChecked + ' class="w-4 h-4 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-green-600 bg-white dark:bg-zinc-900 checked:bg-green-600 checked:border-green-600 focus:ring-green-500/50 focus:ring-offset-0 transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95" style="filter: none !important; accent-color: #16a34a !important;">' +
										'<span class="drag-handle text-gray-400 hover:text-gray-600 dark:hover:text-zinc-200 cursor-grab active:cursor-grabbing font-bold text-base select-none px-1" title="جابجایی">☰</span>' +
									'</div>' +
								'</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 border-y border-gray-200 dark:border-zinc-800 text-center">' +
									'<div class="flex flex-col items-center justify-center gap-1.5 w-full max-w-[120px] mx-auto select-none">' +
										'<div class="flex flex-row items-center justify-center gap-1">' +
											(!isEffectivelyActive ? '<span class="px-1 py-0 h-3.5 inline-flex items-center justify-center leading-none text-[9px] font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 rounded">غیرفعال</span>' : '<span class="px-1 py-0 h-3.5 inline-flex items-center justify-center leading-none text-[9px] font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 rounded">فعال</span>') +
											(user.is_online === 1 ? '<span class="px-1 py-0 h-3.5 inline-flex items-center justify-center leading-none text-[9px] font-medium bg-green-600 text-white rounded animate-pulse" dir="rtl">' + user.online_count + '</span>' : '<span class="px-1 py-0 h-3.5 inline-flex items-center justify-center leading-none text-[9px] font-medium bg-gray-200 text-gray-600 dark:bg-zinc-800 dark:text-zinc-400 rounded">آفلاین</span>') +
										'</div>' +
										'<span class="px-1 py-0 h-3.5 inline-flex items-center justify-center leading-none text-[9px] font-black bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300 rounded">' + (function(){ var m = (user.traffic_multiplier !== undefined && user.traffic_multiplier !== null && user.traffic_multiplier !== '') ? parseFloat(user.traffic_multiplier) : 1; if (!isFinite(m) || m <= 0) m = 1; var s = (Math.round(m * 100) / 100).toString(); return s + 'X'; })() + '</span>' +
										'<span class="font-bold text-gray-900 dark:text-zinc-100 text-xs truncate max-w-full pt-0.5 leading-normal">' + user.username + '</span>' +
										locBadge +
									'</div>' +
								'</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 border-y border-gray-200 dark:border-zinc-800 text-center">' +
									'<div class="flex flex-col items-center gap-2 w-max mx-auto py-0.5">' +
'<div class="flex flex-row items-center justify-center gap-1 w-max mx-auto">' +
	'<button data-user="' + encodeURIComponent(user.username) + '" onclick="copyConfig(this.dataset.user)" title="کپی کانفیگ" class="w-[28px] h-[24px] p-0 flex items-center justify-center bg-blue-50 dark:bg-blue-950/40 border border-blue-300 dark:border-blue-800 hover:bg-blue-100 dark:hover:bg-blue-900/60 text-blue-600 dark:text-blue-400 rounded-md transition shadow-sm"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button>' +
	'<button data-user="' + encodeURIComponent(user.username) + '" onclick="editUser(this.dataset.user)" title="ویرایش" class="w-[28px] h-[24px] p-0 flex items-center justify-center bg-green-50 dark:bg-green-950/40 border border-green-300 dark:border-green-800 hover:bg-green-100 dark:hover:bg-green-900/60 text-green-600 dark:text-green-400 rounded-md transition shadow-sm"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg></button>' +
	'<button data-user="' + encodeURIComponent(user.username) + '" onclick="showUserIps(this.dataset.user)" title="IPهای متصل" class="w-[28px] h-[24px] p-0 flex items-center justify-center rounded-md bg-transparent border border-purple-400 dark:border-purple-500 hover:bg-purple-50 dark:hover:bg-purple-950/40 transition shadow-sm"><span class="text-purple-600 dark:text-purple-400 text-[9px] font-black leading-none">IP</span></button>' +
	'<button data-user="' + encodeURIComponent(user.username) + '" onclick="showUserOperators(this.dataset.user)" title="اپراتورهای متصل" class="w-[28px] h-[24px] p-0 flex items-center justify-center rounded-md bg-transparent border border-amber-700 dark:border-amber-600 hover:bg-amber-50 dark:hover:bg-amber-950/40 transition shadow-sm"><svg class="w-3.5 h-3.5 text-amber-800 dark:text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path></svg></button>' +
	'<button data-user="' + encodeURIComponent(user.username) + '" onclick="deleteUser(this.dataset.user)" title="حذف" class="w-[28px] h-[24px] p-0 flex items-center justify-center bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-800 hover:bg-red-100 dark:hover:bg-red-900/60 text-red-600 dark:text-red-400 rounded-md transition shadow-sm"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>' +
	'<button data-user="' + encodeURIComponent(user.username) + '" onclick="toggleUserStatus(this.dataset.user)" title="' + statusBtnTitle + '" class="w-[28px] h-[24px] p-0 flex items-center justify-center bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/60 ' + statusBtnColor + ' rounded-md transition shadow-sm">' + statusBtnIcon + '</button>' +
'</div>' +
'</div>' +
								'</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1 border-y border-gray-200 dark:border-zinc-800 text-xs text-center">' +
									'<div class="grid grid-flow-row gap-1 w-max mx-auto items-center">' +
										(enableVless ? '<span class="inline-flex items-center justify-center px-1.5 h-[18px] text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">VLESS</span>' : '') +
										(enableTrojan ? '<span class="inline-flex items-center justify-center px-1.5 h-[18px] text-[10px] font-semibold rounded bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400">Trojan</span>' : '') +
										(enableSS ? '<span class="inline-flex items-center justify-center px-1.5 h-[18px] text-[10px] font-semibold rounded bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">SS</span>' : '') +
									'</div>' +
								'</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 border-y border-gray-200 dark:border-zinc-800">' +
									'<div class="flex flex-col gap-1 w-[115px] mx-auto">' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="openStatusLink(this.dataset.user)" class="w-full h-[24px] p-0 flex items-center justify-center gap-1 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-500 hover:bg-green-100 dark:hover:bg-green-900/50 rounded-full text-[9px] font-bold transition border border-green-200 dark:border-green-800 whitespace-nowrap">' +
											'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>' +
											'وضعیت اتصال' +
										'</button>' +
										
										'<div class="flex flex-row gap-1 w-full h-[24px]">' +
											'<button data-user="' + encodeURIComponent(user.username) + '" onclick="copySubLink(this.dataset.user)" class="flex-1 h-[24px] p-0 flex items-center justify-center gap-1 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 rounded-full text-[9px] font-bold transition border border-indigo-200 dark:border-indigo-800 whitespace-nowrap">' +
												'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>' +
												'ساب متنی' +
											'</button>' +
											'<button data-user="' + encodeURIComponent(user.username) + '" onclick="showSubQr(this.dataset.user)" title="QR ساب متنی" class="w-[24px] h-[24px] flex-shrink-0 p-0 flex items-center justify-center bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-full transition border border-amber-200 dark:border-amber-800">' +
												'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg>' +
											'</button>' +
										'</div>' +

										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="copyClashLink(this.dataset.user)" class="w-full h-[24px] p-0 flex items-center justify-center gap-1 bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900/50 rounded-full text-[9px] font-bold transition border border-purple-200 dark:border-purple-800 whitespace-nowrap">' +
											'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>' +
											'ساب YAML' +
										'</button>' +
									'</div>' +
								'</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1 border-y border-gray-200 dark:border-zinc-800 text-center">' + configsCountHtml + '</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1 border-y border-gray-200 dark:border-zinc-800 text-xs">' +
									(function() {
										var pts = String(user.port || "").split(",").map(function(p){ return p.trim(); }).filter(function(p){ return p !== ""; });
										if (pts.length === 0) return "";
										var r = Math.min(pts.length, 3);
										return '<div class="grid grid-flow-col gap-1 w-max mx-auto items-center" style="grid-template-rows: repeat(' + r + ', auto);">' +
											pts.map(function(p) {
												var isTls = tlsPorts.includes(p);
												var isNonTls = nonTlsPorts.includes(p);
												var colorClass = isTls ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400' : 
																 isNonTls ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400' : 
																 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
												return '<span class="inline-flex items-center justify-center px-1.5 h-[18px] text-[10px] font-semibold rounded ' + colorClass + '">' + p + '</span>';
											}).join("") +
										'</div>';
									})() +
								'</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 border-y border-gray-200 dark:border-zinc-800">' + volumeHtml + '</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 border-y border-gray-200 dark:border-zinc-800">' + reqHtml + '</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 border-y border-gray-200 dark:border-zinc-800">' + expiryHtml + '</td>' +
								'<td class="bg-white/60 dark:bg-zinc-900/40  group-hover:bg-white/80 dark:group-hover:bg-zinc-900/60 p-1.5 rounded-l-md border-y border-l border-gray-200 dark:border-zinc-800">' + onlineHtml + '</td>' +
								'</tr>';
				}).join('');
				updateBulkActionsBar();
				if (typeof loadProxyFlags === 'function') {
					setTimeout(loadProxyFlags, 50);
				}
				if (window.usersSortable) {
					window.usersSortable.destroy();
				}
				window.usersSortable = new Sortable(document.getElementById('users-tbody'), {
					handle: '.drag-handle',
					animation: 250,
					ghostClass: "opacity-30",
					delay: 200,
					delayOnTouchOnly: true,
					touchStartThreshold: 5,
					onChoose: function () {
						window.isDraggingRow = true;
					},
					onUnchoose: function () {
						window.isDraggingRow = false;
					},
					onStart: function () {
						window.isDraggingRow = true;
					},
					onEnd: function (evt) {
						window.isDraggingRow = false;
						const newOrder = Array.from(evt.to.children).map(tr => tr.getAttribute('data-username')).filter(Boolean);
						localStorage.setItem('caspian_users_custom_order', JSON.stringify(newOrder));
					}
				});
			}
		}
		async function resetUserData(encodedUsername, actionType) {
			const username = decodeURIComponent(encodedUsername);
			let actionName = '';
			if (actionType === 'volume') actionName = 'حجم';
			else if (actionType === 'req') actionName = 'ریکوئست';
			else if (actionType === 'time') actionName = 'زمان';
			else if (actionType === 'daily') actionName = 'مصرف روزانه';
			if (await customConfirm('آیا از ریست کردن ' + actionName + ' کاربر ' + username + ' مطمئن هستید؟')) {
				try {
					const response = await fetch('/api/users/' + encodeURIComponent(username), {
						method: 'PUT',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ reset_action: actionType })
					});
					if (response.ok) {
						if (window.smoothCache && window.smoothCache[username]) {
							if (actionType === 'volume') window.smoothCache[username].gb = 0;
							if (actionType === 'req') window.smoothCache[username].req = 0;
							if (actionType === 'daily') window.smoothCache[username].daily = 0;
						}
						alert('عملیات با موفقیت انجام شد.');
						await loadUsers(true);
					} else {
						const errData = await response.json();
						alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
					}
				} catch (err) {
					alert('خطا در برقراری ارتباط با سرور');
				}
			}
		}
		async function toggleUserStatus(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			try {
				const response = await fetch('/api/users/' + encodeURIComponent(username), {
					method: 'PUT',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ toggle_only: true })
				});
				if (response.ok) {
					await loadUsers(true);
				} else {
					const errData = await response.json();
					alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			}
		}
		function handleProtocolChange(changedInput) {
			const vlessCb = document.getElementById('input-proto-vless');
			const trojanCb = document.getElementById('input-proto-trojan');
			const ssCb = document.getElementById('input-proto-ss');
			if (!vlessCb?.checked && !trojanCb?.checked && !ssCb?.checked) {
				changedInput.checked = true;
				alert('⚠️ حداقل یکی از پروتکل‌ها باید انتخاب شده باشد!');
			}
		}
		window.deferredPwaPrompt = null;
		window.addEventListener('beforeinstallprompt', (e) => {
			e.preventDefault();
			window.deferredPwaPrompt = e;
		});
		window.addEventListener('appinstalled', () => {
			window.deferredPwaPrompt = null;
			showToast('✅ اپلیکیشن کاسپین با موفقیت روی دستگاه شما نصب شد!');
		});
		function isIosDevice() {
			return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
		}
		function isPwaStandalone() {
			return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
		}
		function togglePwaModal(show) {
			setModalState('pwa-install-modal', show);
		}
		function getBrowserAndOsInfo() {
			const ua = navigator.userAgent;
			const isOpera = ua.includes('OPR') || ua.includes('Opera') || ua.includes('OPT/');
			const isEdge = ua.includes('Edg');
			const isChrome = ua.includes('Chrome') && !isEdge && !isOpera;
			const isFirefox = ua.includes('Firefox');
			const isSafari = ua.includes('Safari') && !isChrome && !isEdge && !isOpera;
			const isAndroid = /Android/i.test(ua);
			const isIos = isIosDevice();
			return { isOpera, isEdge, isChrome, isFirefox, isSafari, isAndroid, isIos };
		}
		function renderInstallGuide() {
			const info = getBrowserAndOsInfo();
			const list = document.getElementById('pwa-instructions-list');
			const title = document.getElementById('pwa-modal-title');
			if (!list) return;
			list.innerHTML = '';
			if (info.isIos) {
				if (title) title.innerText = 'نصب روی آیفون / iOS';
				list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
					'<span>در نوار پایین سافاری، دکمه <b>اشتراک‌گذاری (Share 📤)</b> را لمس کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
					'<span>گزینه <b>«Add to Home Screen» (افزودن به صفحه اصلی ➕)</b> را انتخاب کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۳</span>' +
					'<span>در گوشه بالا دکمه <b>«Add» (افزودن)</b> را بزنید تا آیکون برنامه ایجاد شود.</span>' +
				'</div>';
			} else if (info.isOpera) {
				if (title) title.innerText = 'نصب در مرورگر اپرا (Opera)';
				if (info.isAndroid) {
					list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
						'<span>در نوار پایین اپرا، روی منوی <b>سه نقطه (⋮) یا لوگوی اپرا</b> کلیک کنید.</span>' +
					'</div>' +
					'<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
						'<span>گزینه <b>«صفحه اصلی» (Home screen)</b> یا <b>«نصب برنامه»</b> را انتخاب کنید.</span>' +
					'</div>';
				} else {
					list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
						'<span>در نوار آدرس بالای اپرا (سمت راست آدرس)، روی آیکون <b>📥 (نصب)</b> کلیک کنید.</span>' +
					'</div>' +
					'<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
						'<span>یا روی منوی تنظیمات سریع (Easy Setup) یا منوی سه نقطه کلیک کرده و گزینه <b>Install</b> را انتخاب کنید.</span>' +
					'</div>';
				}
			} else if (info.isAndroid) {
				if (title) title.innerText = 'نصب روی گوشی اندروید';
				list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-green-50/50 dark:bg-green-950/20 rounded-lg border border-green-200/50 dark:border-green-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-green-600 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
					'<span>روی منوی <b>سه نقطه (⋮)</b> در بالای مرورگر کلیک کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-green-50/50 dark:bg-green-950/20 rounded-lg border border-green-200/50 dark:border-green-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-green-600 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
					'<span>گزینه <b>«نصب برنامه» (Install app)</b> یا <b>«افزودن به صفحه اصلی»</b> را انتخاب کنید.</span>' +
				'</div>';
			} else {
				if (title) title.innerText = 'نصب در مرورگر دسکتاپ';
				list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0 mt-1.5"></span>' +
					'<span>در نوار آدرس بالای مرورگر، روی آیکون <b>نصب برنامه (🖥️ یا ➕)</b> کلیک کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0 mt-1.5"></span>' +
					'<span><b>یا</b> از منوی سه نقطه (⋮) گزینه <b>«Install CASPIAN Panel»</b> را انتخاب نمایید.</span>' +
				'</div>';
			}
		}
		function gregorianToJalali(gy, gm, gd) {
			const g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
			let gy2 = (gm > 2) ? (gy + 1) : gy;
			let days = 355666 + (365 * gy) + Math.floor((gy2 + 3) / 4) - Math.floor((gy2 + 99) / 100) + Math.floor((gy2 + 399) / 400) + gd + g_d_m[gm - 1];
			let jy = -1595 + (33 * Math.floor(days / 12053));
			days %= 12053;
			jy += 4 * Math.floor(days / 1461);
			days %= 1461;
			if (days > 365) {
				jy += Math.floor((days - 1) / 365);
				days = (days - 1) % 365;
			}
			const jm = (days < 186) ? 1 + Math.floor(days / 31) : 7 + Math.floor((days - 186) / 30);
			const jd = 1 + ((days < 186) ? (days % 31) : ((days - 186) % 30));
			return [jy, jm, jd];
		}
		function dayKeyToShamsi(dayKey) {
			try {
				const parts = String(dayKey).split('-').map(Number);
				if (parts.length !== 3) return dayKey;
				const [jy, jm, jd] = gregorianToJalali(parts[0], parts[1], parts[2]);
				return jy + '/' + String(jm).padStart(2, '0') + '/' + String(jd).padStart(2, '0');
			} catch (e) { return dayKey; }
		}
		function formatGbLabel(gb) {
			if (!gb || gb <= 0) return '0';
			if (gb < 1) return (gb * 1024).toFixed(0) + 'MB';
			if (gb < 10) return gb.toFixed(2) + 'GB';
			return gb.toFixed(1) + 'GB';
		}
		function openTrafficChartModal() {
			const modal = document.getElementById('traffic-chart-modal');
			const card = document.getElementById('traffic-chart-modal-card');
			if (!modal || !card) return;
			modal.classList.remove('opacity-0', 'pointer-events-none');
			modal.classList.add('opacity-100', 'pointer-events-auto');
			card.classList.remove('opacity-0', 'scale-95');
			card.classList.add('opacity-100', 'scale-100');
			loadTrafficChart(30);
		}
		function closeTrafficChartModal() {
			const modal = document.getElementById('traffic-chart-modal');
			const card = document.getElementById('traffic-chart-modal-card');
			if (!modal || !card) return;
			modal.classList.remove('opacity-100', 'pointer-events-auto');
			modal.classList.add('opacity-0', 'pointer-events-none');
			card.classList.remove('opacity-100', 'scale-100');
			card.classList.add('opacity-0', 'scale-95');
		}
		async function loadTrafficChart(days) {
			const loading = document.getElementById('traffic-chart-loading');
			const bars = document.getElementById('traffic-chart-bars');
			const empty = document.getElementById('traffic-chart-empty');
			const totalEl = document.getElementById('traffic-chart-total');
			if (loading) loading.classList.remove('hidden');
			if (bars) { bars.classList.add('hidden'); bars.innerHTML = ''; }
			if (empty) empty.classList.add('hidden');
			document.querySelectorAll('[data-chart-days]').forEach(function(btn) {
				const d = parseInt(btn.getAttribute('data-chart-days'), 10);
				if (d === days) {
					btn.classList.add('bg-emerald-100', 'dark:bg-emerald-900/40', 'border-emerald-500');
				} else {
					btn.classList.remove('bg-emerald-100', 'dark:bg-emerald-900/40', 'border-emerald-500');
				}
			});
			try {
				const res = await fetch('/api/traffic-chart?days=' + days + '&t=' + Date.now());
				const data = await res.json();
				const list = data.days || [];
				if (loading) loading.classList.add('hidden');
				if (!list.length) {
					if (empty) empty.classList.remove('hidden');
					if (totalEl) totalEl.innerText = '';
					return;
				}
				const vals = list.map(function(x) { return Number(x.total_gb) || 0; });
				const maxGb = Math.max.apply(null, vals.concat([0.0001]));
				const sum = vals.reduce(function(a, b) { return a + b; }, 0);
				const hasAny = vals.some(function(v) { return v > 0; });
				if (!hasAny) {
					if (empty) {
						empty.classList.remove('hidden');
						empty.innerText = 'هنوز مصرفی ثبت نشده. بعد از استفاده کاربران، نمودار پر می‌شود.';
					}
					if (totalEl) totalEl.innerText = 'مجموع بازه: 0';
					return;
				}
				const W = 640, H = 240;
				const padL = 48, padR = 12, padT = 16, padB = 36;
				const plotW = W - padL - padR;
				const plotH = H - padT - padB;
				const n = list.length;
				const points = list.map(function(item, i) {
					const x = padL + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW);
					const y = padT + plotH - ((Number(item.total_gb) || 0) / maxGb) * plotH;
					return { x: x, y: y, item: item, shamsi: dayKeyToShamsi(item.day_key) };
				});
				const poly = points.map(function(p) { return p.x.toFixed(1) + ',' + p.y.toFixed(1); }).join(' ');
				const area = padL + ',' + (padT + plotH) + ' ' + poly + ' ' + (padL + plotW) + ',' + (padT + plotH);
				const yTicks = 4;
				let grid = '';
				for (let t = 0; t <= yTicks; t++) {
					const gy = padT + (plotH * t / yTicks);
					const gval = maxGb * (1 - t / yTicks);
					grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (padL + plotW) + '" y2="' + gy + '" stroke="currentColor" stroke-opacity="0.12" stroke-width="1"/>';
					grid += '<text x="' + (padL - 6) + '" y="' + (gy + 3) + '" text-anchor="end" font-size="9" fill="currentColor" opacity="0.55" font-family="ui-sans-serif,system-ui">' + formatGbLabel(gval) + '</text>';
				}
				const labelStep = n > 20 ? Math.ceil(n / 8) : (n > 10 ? 2 : 1);
				let xLabels = '';
				points.forEach(function(p, i) {
					if (i % labelStep !== 0 && i !== n - 1) return;
					xLabels += '<text x="' + p.x + '" y="' + (H - 8) + '" text-anchor="middle" font-size="8" fill="currentColor" opacity="0.65" font-family="ui-sans-serif,system-ui">' + p.shamsi.slice(5) + '</text>';
				});
				let dots = '';
				points.forEach(function(p) {
					dots += '<circle cx="' + p.x + '" cy="' + p.y + '" r="3.5" fill="#10b981" stroke="#fff" stroke-width="1.5"><title>' + p.shamsi + ' — ' + formatGbLabel(p.item.total_gb || 0) + '</title></circle>';
				});
				bars.innerHTML =
					'<svg viewBox="0 0 ' + W + ' ' + H + '" class="w-full h-full text-gray-500 dark:text-zinc-400" preserveAspectRatio="xMidYMid meet">' +
					grid +
					'<polygon points="' + area + '" fill="#10b981" fill-opacity="0.15"/>' +
					'<polyline points="' + poly + '" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>' +
					dots +
					xLabels +
					'</svg>';
				bars.classList.remove('hidden');
				if (totalEl) totalEl.innerText = 'مجموع بازه: ' + formatGbLabel(sum);
			} catch (e) {
				if (loading) loading.classList.add('hidden');
				if (empty) {
					empty.classList.remove('hidden');
					empty.innerText = 'خطا در دریافت داده نمودار';
				}
			}
		}
		window.openTrafficChartModal = openTrafficChartModal;
		window.closeTrafficChartModal = closeTrafficChartModal;
		window.loadTrafficChart = loadTrafficChart;
		async function triggerPwaInstall() {
			if (isPwaStandalone()) {
				showToast('✅ اپلیکیشن هم‌اکنون روی دستگاه شما نصب است و در حال اجرا می‌باشد.');
				return;
			}
			if (window.deferredPwaPrompt) {
				try {
					window.deferredPwaPrompt.prompt();
					const choice = await window.deferredPwaPrompt.userChoice;
					if (choice.outcome === 'accepted') {
						showToast('✅ در حال نصب اپلیکیشن...');
					}
					window.deferredPwaPrompt = null;
					return;
				} catch (err) {}
			}
			renderInstallGuide();
			togglePwaModal(true);
		}
		window.triggerPwaInstall = triggerPwaInstall;
		window.togglePwaModal = togglePwaModal;
		if ('serviceWorker' in navigator) {
			try {
				navigator.serviceWorker.register('/sw.js').catch(() => {});
			} catch(e) {}
		}
		function generateRandomUsername() {
			const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
			let randStr = '';
			for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
			const username = randStr;
			const nameInput = document.getElementById('input-name');
			if (nameInput) {
				nameInput.value = username;
			}
		}
		window.generateRandomUsername = generateRandomUsername;
		async function handleFormSubmit(event) {
			event.preventDefault();
			updateSubmitBtnState(isEditMode ? 'در حال ذخیره تغییرات...' : 'در حال ایجاد...', true);
			const vlessEnabled = document.getElementById('input-proto-vless')?.checked ?? true;
			const trojanEnabled = document.getElementById('input-proto-trojan')?.checked ?? false;
			const ssEnabled = document.getElementById('input-proto-ss')?.checked ?? false;
			if (!vlessEnabled && !trojanEnabled && !ssEnabled) {
				alert('⚠️ حداقل یکی از پروتکل‌ها باید انتخاب شود!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const selectedProtocols = [];
			if (vlessEnabled) selectedProtocols.push('vless');
			if (trojanEnabled) selectedProtocols.push('trojan');
			if (ssEnabled) selectedProtocols.push('shadowsocks');
			const connection_type = selectedProtocols.join(',');
			const username = document.getElementById('input-name').value.trim();

			if (!username) {
				if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
				alert('⚠️ وارد کردن نام کاربری الزامی است!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}

			const usernameRegex = /^[a-zA-Z0-9_-]+$/;
			if (!usernameRegex.test(username)) {
				if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
				alert('⚠️ نام کاربری فقط می‌تواند شامل حروف انگلیسی، اعداد، خط تیره (-) و آندرلاین (_) باشد!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const limit = document.getElementById('input-limit').value || null;
			const expiry = document.getElementById('input-expiry').value || null;
			const reqLimit = document.getElementById('input-req-limit').value || null;
			const ipLimit = document.getElementById('input-ip-limit').value || null;
			const dailyLimitRaw = document.getElementById('input-daily-limit') ? document.getElementById('input-daily-limit').value : '';
			const dailyLimit = (dailyLimitRaw !== '' && dailyLimitRaw !== null) ? dailyLimitRaw : null;
			const trafficMultiplierRaw = document.getElementById('input-traffic-multiplier') ? document.getElementById('input-traffic-multiplier').value : '';
			const trafficMultiplier = (trafficMultiplierRaw !== '' && trafficMultiplierRaw !== null) ? trafficMultiplierRaw : null;
			if (limit !== null && parseFloat(limit) < 0) { alert('⚠️ حجم نمی‌تواند عدد منفی باشد!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			if (dailyLimit !== null && parseFloat(dailyLimit) < 0) { alert('⚠️ محدودیت روزانه نمی‌تواند منفی باشد!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			if (expiry !== null && parseInt(expiry) < 0) { alert('⚠️ زمان (روز) نمی‌تواند عدد منفی باشد!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			if ((reqLimit !== null && parseInt(reqLimit) < 0) || (ipLimit !== null && parseInt(ipLimit) < 0)) { alert('⚠️ محدودیت‌ها نمی‌توانند منفی باشند!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			const autoResetToggle = document.getElementById('input-auto-reset-toggle').checked;
			const autoResetVolDays = document.getElementById('input-auto-reset-vol').value;
			const autoResetReqDays = document.getElementById('input-auto-reset-req').value;
			if (autoResetToggle) {
				const volDays = parseInt(autoResetVolDays) || 0;
				const reqDays = parseInt(autoResetReqDays) || 0;
				if (volDays <= 0 && reqDays <= 0) {
					alert('⚠️ وقتی تیک تمدید خودکار روشن است، باید حداقل یکی از فیلدها (زمان تمدید حجم یا ریکوئست) را پر کنید!');
					updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
					return;
				}
			}
			const announceOn = document.getElementById('input-announce-toggle') ? document.getElementById('input-announce-toggle').checked : false;
			const announceText = document.getElementById('input-announce-text') ? document.getElementById('input-announce-text').value.trim() : '';
			if (announceOn && !announceText) {
				alert('⚠️ وقتی اعلان ساب روشن است، باید متن پیام را وارد کنید!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const customPortsRaw = document.getElementById('input-custom-ports') ? document.getElementById('input-custom-ports').value : '';
			const customPortsArray = customPortsRaw.replace(/ +/g, ',').split(',').map(p => p.trim()).filter(p => p.length > 0);
			let checkedPorts = Array.from(document.querySelectorAll('input[name="ports"]:checked')).map(cb => cb.value).concat(customPortsArray);
			checkedPorts = [...new Set(checkedPorts)];
			const block_porn = document.getElementById('input-block-porn').checked ? 1 : 0;
			const block_ads = document.getElementById('input-block-ads').checked ? 1 : 0;
			const isFragOn = document.getElementById('input-frag-toggle') ? document.getElementById('input-frag-toggle').checked : true;
			const frag_len = isFragOn && document.getElementById('input-frag-len') ? document.getElementById('input-frag-len').value.trim() : "";
			const frag_int = isFragOn && document.getElementById('input-frag-int') ? document.getElementById('input-frag-int').value.trim() : "";
			const isAdvancedSettingsOn = document.getElementById('input-advanced-settings-toggle') ? document.getElementById('input-advanced-settings-toggle').checked : false;
			const advanced_frag = (isAdvancedSettingsOn && document.getElementById('input-advanced-frag')) ? document.getElementById('input-advanced-frag').value.trim() : "";
			const cipher_suites = (isAdvancedSettingsOn && document.getElementById('input-cipher-suites')) ? document.getElementById('input-cipher-suites').value.trim() : "";
			const tls_mask = (isAdvancedSettingsOn && document.getElementById('input-tls-mask')) ? document.getElementById('input-tls-mask').value.trim() : "";
			const isAutoReset = document.getElementById('input-auto-reset-toggle').checked;
			const auto_reset_vol_days = isAutoReset ? parseInt(document.getElementById('input-auto-reset-vol').value) || 0 : 0;
			const auto_reset_req_days = isAutoReset ? parseInt(document.getElementById('input-auto-reset-req').value) || 0 : 0;
			const auto_rotate_ip = document.getElementById('input-auto-rotate-ip-toggle') ? (document.getElementById('input-auto-rotate-ip-toggle').checked ? 1 : 0) : 0;
			const rotate_time = 0;
			const ip_operator = document.getElementById('hidden-ip-operator').value || 'all';
			const ip_count = parseInt(document.getElementById('hidden-ip-count').value) || 20;
			const userProxyMode = document.getElementById('user-proxy-mode-toggle') ? document.getElementById('user-proxy-mode-toggle').checked : false;
			let userSocks5 = null;
			if (userProxyMode && window.proxyFieldsData && window.proxyFieldsData.length > 0) {
				const cleanProxies = window.proxyFieldsData.map(p => p ? p.trim() : "").filter(p => p !== "");
				if (cleanProxies.length === 1) {
					userSocks5 = cleanProxies[0];
				} else if (cleanProxies.length > 1) {
					userSocks5 = JSON.stringify(cleanProxies);
				}
			}
			const auto_rotate_user_proxy = document.getElementById('input-auto-rotate-user-proxy') ? (document.getElementById('input-auto-rotate-user-proxy').checked ? 1 : 0) : 0;
			const start_on_first_connect = document.getElementById('input-start-on-first-connect') ? (document.getElementById('input-start-on-first-connect').checked ? 1 : 0) : 0;
			const enable_direct = document.getElementById('input-enable-direct') ? document.getElementById('input-enable-direct').checked : true;
			if (checkedPorts.length === 0) {
				alert('⚠️ لطفا حداقل یک پورت را برای اتصال انتخاب کنید!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const port = checkedPorts.join(',');
			const tls = checkedPorts.some(p => tlsPorts.includes(p)) ? 'on' : 'off';
			const ips = document.getElementById('input-ips').value;
			const fingerprint = document.getElementById('fingerprint-select').value;
			const url = isEditMode ? '/api/users/' + encodeURIComponent(editingUsername) : '/api/users';
			const method = isEditMode ? 'PUT' : 'POST';

			// محاسبه تعداد کانفیگ‌ها
			let numIps = ips ? ips.split('\\n').filter(p => p.trim().length > 0).length : 1;
			if (numIps === 0) numIps = 1;
			let numPorts = checkedPorts.length || 1;
			let numProto = selectedProtocols.length || 1;
			let numProxies = (userProxyMode && window.proxyFieldsData ? window.proxyFieldsData.filter(p => p.trim() !== '').length : 0);
			if (enable_direct) numProxies += 1;
			if (numProxies === 0) numProxies = 1;
			let totalConfigs = 3 + (numProxies * numIps * numPorts * numProto);

			try {
				const response = await fetch(url, {
					method: method,
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ 
						username, limit_gb: limit, expiry_days: expiry, limit_req: reqLimit, daily_limit_gb: dailyLimit, traffic_multiplier: trafficMultiplier, tls, port, ips, fingerprint, ip_limit: ipLimit, block_porn: block_porn, block_ads: block_ads, frag_len: frag_len, frag_int: frag_int,
						advanced_frag: advanced_frag || null, cipher_suites: cipher_suites || null, tls_mask: tls_mask || null,
						user_proxy_iata: null,
						user_socks5: userSocks5 || null,
						user_proxy_ip: null,
						auto_reset_vol_days: auto_reset_vol_days,
						auto_reset_req_days: auto_reset_req_days,
						announce_enabled: announceOn ? 1 : 0,
						announce_text: announceText,
						auto_rotate_ip: auto_rotate_ip,
						rotate_time: rotate_time,
						ip_operator: ip_operator,
						ip_count: ip_count,
						auto_rotate_user_proxy: auto_rotate_user_proxy,
						start_on_first_connect: start_on_first_connect,
						enable_direct: enable_direct,
						connection_type: connection_type,
						protocols: selectedProtocols
					})
				});
				if (response.ok) {
					toggleModal(false);
					if (totalConfigs > 60) {
						setTimeout(() => openConfigCountWarning(), 300);
					}
					setTimeout(() => loadUsers(true), 1500);
				} else {
					const errData = await response.json();
					alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			} finally {
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
			}
		}
window.activeProxyIndex = 0;
window.proxyFieldsData = [""];
window.clearProxyFieldUI = function(idx) {
	window.proxyFieldsData[idx] = "";
	if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
};
window.renderProxyFieldsUI = function() {
	const wrapper = document.getElementById("proxies-fields-wrapper");
	const addBtn = document.getElementById("add-proxy-field-btn");
	if (!wrapper) return;
	wrapper.innerHTML = "";
	let proxyFlagCache = {};
	try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
	window.proxyFieldsData.forEach((val, idx) => {
		const isFocused = idx === window.activeProxyIndex;
		const borderClass = isFocused ? "ring-2 ring-blue-500 border-blue-500" : "border-gray-200 dark:border-amoled-border";
		const row = document.createElement("div");
		row.className = "flex flex-col gap-0.5 w-full";
		const proxyStr = (val || "").trim();
		const pingObj = proxyStr ? (window.proxyPingMap && window.proxyPingMap[proxyStr]) : null;
		const pingClass = pingObj ? pingObj.className : "text-[10px] font-bold text-center block min-h-[18px] mt-0.5 transition-colors";
		const pingText = pingObj ? pingObj.text : "";
		let countryCode = "UN";
		if (proxyStr && proxyFlagCache[proxyStr]) {
			countryCode = proxyFlagCache[proxyStr].toUpperCase();
		}
		const isVip = proxyStr.length > 0 && (proxyStr.includes('@') || proxyStr.includes('pass=') || proxyStr.includes('t.me/'));
		let inputRow = '<div class="flex items-center gap-1 w-full">' +
			'<button type="button" onclick="swapProxyFieldUI(' + idx + ')" class="w-7 h-7 flex-shrink-0 bg-transparent border-2 border-green-500 text-green-600 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 rounded flex items-center justify-center font-bold text-xs shadow-sm transition-all" title="جا به جایی پروکسی"><svg id="swap-icon-' + idx + '" class="w-3.5 h-3.5 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path></svg></button>';
		const vipBorderClass = isFocused ? "ring-2 ring-blue-500 border-blue-500" : "border-green-400 dark:border-green-600";
		if (isVip) {
			let flagHtml = typeof getFlagEmoji === 'function' ? getFlagEmoji(countryCode) : '🌐';
			if (countryCode === "UN") flagHtml = '⏳';
			const displayCountry = countryCode !== "UN" ? countryCode : "نامشخص";
			inputRow += '<div id="proxy-field-box-' + idx + '" onclick="setActiveProxyField(' + idx + ')" class="flex-1 px-2.5 py-1.5 bg-green-50 dark:bg-slate-900 border ' + vipBorderClass + ' rounded text-xs font-bold text-green-700 dark:text-green-500 flex items-center justify-between shadow-inner select-none cursor-pointer transition" title="آدرس پروکسی برای امنیت مخفی شده است">' +
							'<div class="flex items-center gap-1.5">' +
								'<svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path fill-rule="evenodd" d="M10.788 3.21c.448-1.077 1.976-1.077 2.424 0l2.082 5.007 5.404.433c1.164.093 1.636 1.545.749 2.305l-4.117 3.527 1.257 5.273c.271 1.136-.964 2.033-1.96 1.425L12 18.354 7.373 21.18c-.996.608-2.231-.29-1.96-1.425l1.257-5.273-4.117-3.527c-.887-.76-.415-2.212.749-2.305l5.404-.433 2.082-5.006z" clip-rule="evenodd"></path></svg>' +
								'<span>پروکسی VIP (' + displayCountry + ')</span>' +
							'</div>' +
							'<div class="flex items-center gap-2">' +
								'<span class="text-base leading-none drop-shadow-sm">' + flagHtml + '</span>' +
								'<button type="button" onclick="event.stopPropagation(); window.clearProxyFieldUI(' + idx + ')" title="حذف و تغییر به پروکسی دستی" class="text-green-600/60 hover:text-red-500 transition-colors z-10 relative"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>' +
							'</div>' +
						'</div>';
		} else {
			inputRow += '<input type="text" id="proxy-field-box-' + idx + '" value="' + proxyStr + '" onfocus="setActiveProxyField(' + idx + ')" onclick="setActiveProxyField(' + idx + ')" oninput="updateProxyFieldData(' + idx + ', this.value)" placeholder="socks5:// یا http:// (کشور ' + (idx + 1) + ')" dir="ltr" class="flex-1 px-2 py-1.5 bg-gray-50 dark:bg-slate-900 border ' + borderClass + ' rounded text-xs font-mono focus:outline-none text-gray-800 dark:text-zinc-100 transition">';
		}
		if (idx > 0) {
			inputRow += '<button type="button" onclick="removeProxyFieldUI(' + idx + ')" class="w-7 h-7 flex-shrink-0 bg-transparent border-2 border-red-500 text-red-600 dark:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded flex items-center justify-center font-bold text-xs shadow-sm" title="حذف کامل فیلد"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>';
		}
		inputRow += '</div><span id="proxy-ping-label-' + idx + '" class="' + pingClass + '">' + pingText + '</span>';
		row.innerHTML = inputRow;
		wrapper.appendChild(row);
	});
	if (addBtn) {
		addBtn.style.display = window.proxyFieldsData.length >= 15 ? "none" : "flex";
	}
};
document.addEventListener('keydown', function(event) {
    if (event.key === 'F12' || event.keyCode === 123) {
        event.preventDefault(); return false;
    }
    if (event.ctrlKey && event.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(event.key)) {
        event.preventDefault(); return false;
    }
    if (event.ctrlKey && (event.key === 'U' || event.key === 'u')) {
        event.preventDefault(); return false;
    }
});
document.addEventListener('contextmenu', function(event) {
    const tag = event.target.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea') {
        return true;
    }
    event.preventDefault(); return false;
});
(function() {
    function destroyPage() {
        document.body.innerHTML = '<div style="background:#000; color:red; height:100vh; display:flex; align-items:center; justify-content:center; font-size:3rem; font-weight:bold; z-index:999999; position:fixed; inset:0;">عه کــیر شدی</div>';
    }
    setInterval(function() {
        const devToolsTrap = new Image();
        Object.defineProperty(devToolsTrap, 'id', {
            get: function() {
                destroyPage();
            }
        });
        console.log('%c', devToolsTrap);
        console.clear();
    }, 500);
})();
window.setActiveProxyField = function(idx) {
	if (window.activeProxyIndex === idx) return;
	window.activeProxyIndex = idx;
	const wrapper = document.getElementById("proxies-fields-wrapper");
	if (wrapper) {
		for (let i = 0; i < window.proxyFieldsData.length; i++) {
			const el = document.getElementById('proxy-field-box-' + i);
			if (!el) continue;
			
			const val = window.proxyFieldsData[i] || "";
			const isVip = val.length > 0 && (val.includes('@') || val.includes('pass=') || val.includes('t.me/'));
			
			if (i === idx) {
				if (isVip) {
					el.classList.remove("border-green-400", "dark:border-green-700/50");
				} else {
					el.classList.remove("border-gray-200", "dark:border-amoled-border");
				}
				el.classList.add("ring-2", "ring-blue-500", "border-blue-500");
			} else {
				el.classList.remove("ring-2", "ring-blue-500", "border-blue-500");
				if (isVip) {
					el.classList.add("border-green-400", "dark:border-green-700/50");
				} else {
					el.classList.add("border-gray-200", "dark:border-amoled-border");
				}
			}
		}
	}
};
window.updateProxyFieldData = function(idx, val) {
	window.proxyFieldsData[idx] = val;
	const span = document.getElementById('proxy-ping-label-' + idx);
	if (span) {
		span.innerText = '';
		span.className = 'text-[10px] font-bold text-center block min-h-[18px] mt-0.5 transition-colors';
	}
};
window.addProxyFieldUI = function() {
	if (window.proxyFieldsData.length < 15) {
		window.proxyFieldsData.push("");
		window.activeProxyIndex = window.proxyFieldsData.length - 1;
		window.renderProxyFieldsUI();
		setTimeout(() => {
			const newField = document.getElementById("proxy-field-box-" + window.activeProxyIndex);
			if (newField && newField.tagName.toLowerCase() === 'input') {
				newField.focus();
			}
			const addBtn = document.getElementById("add-proxy-field-btn");
			if (addBtn) addBtn.style.display = window.proxyFieldsData.length >= 15 ? "none" : "flex";
		}, 50);
	}
};
window.removeProxyFieldUI = function(idx) {
	if (window.proxyFieldsData.length > 1) {
		window.proxyFieldsData.splice(idx, 1);
		if (window.activeProxyIndex >= window.proxyFieldsData.length) {
			window.activeProxyIndex = window.proxyFieldsData.length - 1;
		}
		window.renderProxyFieldsUI();
	}
};
		window.swapProxyFieldUI = async function(idx, triggerGlobalTest = true) {
			const currentProxy = (window.proxyFieldsData[idx] || "").trim();
			if (!currentProxy) {
				if (triggerGlobalTest) alert("⚠️ ابتدا یک پروکسی در این فیلد وارد کنید!");
				return;
			}
			const icon = document.getElementById('swap-icon-' + idx);
			if (icon) icon.classList.add('animate-spin');
			let usedCountries = new Set();
			try {
				let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
				for (let i = 0; i < window.proxyFieldsData.length; i++) {
					if (i !== idx) {
						let p = (window.proxyFieldsData[i] || "").trim();
						if (p && cache[p]) {
							usedCountries.add(cache[p].toUpperCase());
						}
					}
				}
			} catch(e) {}
			let countryCode = "UN";
			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 2000);
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: currentProxy }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				if (res.ok && data.success && data.country && data.country !== "UN") {
					countryCode = data.country.toUpperCase();
				}
			} catch(e) {}
			let candidateProxies = [];
			let isRandomFallback = false;
			if (countryCode !== "UN" && !usedCountries.has(countryCode)) {
				if (cachedVipProxies[countryCode] && cachedVipProxies[countryCode].length > 0) {
					candidateProxies = candidateProxies.concat(cachedVipProxies[countryCode]);
				}
			}
			if (candidateProxies.length <= 1 || countryCode === "UN" || usedCountries.has(countryCode)) {
				isRandomFallback = true;
				let fallbackCountries = ["DE", "US", "GB", "NL", "FR", "TR"];
				if (cachedVipList && cachedVipList.length > 0) {
					fallbackCountries = cachedVipList;
				}
				let availableCountries = fallbackCountries.filter(c => !usedCountries.has(c));
				if (availableCountries.length === 0) {
					availableCountries = fallbackCountries;
				}
				const randomCountry = availableCountries[Math.floor(Math.random() * availableCountries.length)];
				if (cachedVipProxies[randomCountry] && cachedVipProxies[randomCountry].length > 0) {
					candidateProxies = candidateProxies.concat(cachedVipProxies[randomCountry]);
				}
			}
			candidateProxies = [...new Set(candidateProxies)];
			const alternatives = candidateProxies.filter(p => p !== currentProxy);
			if (alternatives.length > 0) {
				const newProxy = alternatives[Math.floor(Math.random() * alternatives.length)];
				window.proxyFieldsData[idx] = newProxy;
				if (triggerGlobalTest) {
					if (countryCode !== "UN" && !isRandomFallback) {
						showToast('✅ پروکسی اختصاصی (VIP) از کشور ' + countryCode + ' جایگزین شد.');
					} else {
						showToast('✅ یک پروکسی سالم (بدون تکرار کشور) جایگزین شد.');
					}
				}
			} else {
				window.proxyFieldsData[idx] = currentProxy;
				if (triggerGlobalTest) showToast('⚠️ هیچ پروکسی اختصاصی جایگزینی در مخزن VIP یافت نشد!');
			}
			if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
			if (triggerGlobalTest) testUserSocksProxy();
		};

		// ==================== دکمه: تست سرعت / پینگ زنده ====================
		function toggleSpeedtestModal(show) {
			setModalState('speedtest-modal', show);
		}
		let speedtestRunning = false;
		async function runSpeedTest() {
			if (speedtestRunning) { toggleSpeedtestModal(true); return; }
			speedtestRunning = true;
			toggleSpeedtestModal(true);
			const pingEl = document.getElementById('speedtest-ping');
			const dlEl = document.getElementById('speedtest-download');
			const statusEl = document.getElementById('speedtest-status');
			const iconEl = document.getElementById('speedtest-icon');
			if (pingEl) pingEl.innerText = 'در حال سنجش...';
			if (dlEl) dlEl.innerText = 'در حال سنجش...';
			if (statusEl) statusEl.innerText = 'در حال اتصال به سرور...';
			if (iconEl) iconEl.classList.add('animate-pulse');
			try {
				const samples = [];
				for (let i = 0; i < 4; i++) {
					const t0 = performance.now();
					await fetch('/icon.svg?_=' + Date.now() + '_' + i, { cache: 'no-store' });
					samples.push(performance.now() - t0);
				}
				const avgPing = samples.reduce((a, b) => a + b, 0) / samples.length;
				if (pingEl) pingEl.innerText = avgPing.toFixed(0) + ' ms';
				const t1 = performance.now();
				const res = await fetch('/icon.svg?_=' + Date.now() + '_dl', { cache: 'no-store' });
				const blob = await res.blob();
				const elapsedSec = (performance.now() - t1) / 1000;
				const sizeBits = (blob.size || 1) * 8;
				const mbps = elapsedSec > 0 ? (sizeBits / elapsedSec / 1000000) : 0;
				if (dlEl) dlEl.innerText = mbps < 0.01 ? '< 0.01 Mbps (نمونه خیلی کوچک)' : mbps.toFixed(2) + ' Mbps';
				if (statusEl) statusEl.innerText = avgPing < 150 ? '✅ اتصال شما به پنل سالم و سریع است' : (avgPing < 400 ? '🟡 اتصال قابل قبول است' : '🔴 تاخیر بالا نسبت به سرور پنل');
			} catch (e) {
				if (pingEl) pingEl.innerText = 'خطا';
				if (dlEl) dlEl.innerText = 'خطا';
				if (statusEl) statusEl.innerText = '❌ اتصال به سرور برقرار نشد';
			}
			if (iconEl) iconEl.classList.remove('animate-pulse');
			speedtestRunning = false;
		}

		// ==================== دکمه: راهنما و آموزش اتصال ====================
		function toggleHelpGuideModal(show) {
			setModalState('help-guide-modal', show);
		}

		// ==================== دکمه: یادداشت شخصی مالک ====================
		function toggleOwnerNoteModal(show) {
			setModalState('owner-note-modal', show);
			if (show) {
				try {
					const ta = document.getElementById('owner-note-textarea');
					if (ta) ta.value = localStorage.getItem('caspian_owner_note') || '';
				} catch (e) { }
			}
		}
		function saveOwnerNote() {
			try {
				const ta = document.getElementById('owner-note-textarea');
				const hint = document.getElementById('owner-note-saved-hint');
				localStorage.setItem('caspian_owner_note', ta ? ta.value : '');
				if (hint) {
					hint.innerText = '✅ ذخیره شد';
					setTimeout(() => { hint.innerText = ''; }, 2000);
				}
				if (typeof showToast === 'function') showToast('✅ یادداشت ذخیره شد');
			} catch (e) {
				if (typeof showToast === 'function') showToast('❌ ذخیره یادداشت ناموفق بود', 'error');
			}
		}

		// ==================== دکمه: حالت تمام‌صفحه ====================
		function toggleFullscreenMode() {
			const iconExpand = 'M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4';
			const iconCollapse = 'M9 4v4a1 1 0 01-1 1H4m16-5v4a1 1 0 01-1 1h-4M4 15h4a1 1 0 011 1v4m6-5h4a1 1 0 011 1v4';
			const iconPath = document.getElementById('fullscreen-icon-expand');
			if (!document.fullscreenElement) {
				const el = document.documentElement;
				const req = el.requestFullscreen || el.webkitRequestFullscreen || el.mozRequestFullScreen || el.msRequestFullscreen;
				if (req) {
					req.call(el).then(() => { if (iconPath) iconPath.setAttribute('d', iconCollapse); }).catch(() => {
						if (typeof showToast === 'function') showToast('❌ مرورگر شما از حالت تمام‌صفحه پشتیبانی نمی‌کند', 'error');
					});
				} else if (typeof showToast === 'function') {
					showToast('❌ مرورگر شما از حالت تمام‌صفحه پشتیبانی نمی‌کند', 'error');
				}
			} else {
				const exit = document.exitFullscreen || document.webkitExitFullscreen || document.mozCancelFullScreen || document.msExitFullscreen;
				if (exit) exit.call(document).then(() => { if (iconPath) iconPath.setAttribute('d', iconExpand); }).catch(() => { });
			}
		}
		document.addEventListener('fullscreenchange', function () {
			const iconExpand = 'M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4';
			const iconCollapse = 'M9 4v4a1 1 0 01-1 1H4m16-5v4a1 1 0 01-1 1h-4M4 15h4a1 1 0 011 1v4m6-5h4a1 1 0 011 1v4';
			const iconPath = document.getElementById('fullscreen-icon-expand');
			if (iconPath) iconPath.setAttribute('d', document.fullscreenElement ? iconCollapse : iconExpand);
		});

function setModalState(modalId, show) {
			const modal = document.getElementById(modalId);
			if (!modal) return;
			const card = modal.querySelector('div');
			if (show) {
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
		
		// ==================== توابع رمز مدیریت ====================
		
		/* ========== مرکز اعلان‌ها (Notification Center) ========== */
		window.__notifState = {
			messages: 0,
			donations: 0,
			update: false,
			updateVersion: null,
			d1Warn: false,
			items: []
		};
		function toggleNotifCenter(show) {
			var overlay = document.getElementById('notif-center-overlay');
			var drawer = document.getElementById('notif-center-drawer');
			if (!overlay || !drawer) return;
			if (show === undefined) show = !window.__notifOpen;
			window.__notifOpen = !!show;
			if (show) {
				overlay.classList.remove('opacity-0', 'pointer-events-none');
				overlay.classList.add('opacity-100', 'pointer-events-auto');
				drawer.style.transform = 'translateX(0)';
				refreshNotifCenter(true);
			} else {
				overlay.classList.add('opacity-0', 'pointer-events-none');
				overlay.classList.remove('opacity-100', 'pointer-events-auto');
				drawer.style.transform = 'translateX(100%)';
			}
		}
		function notifRelTime(ts) {
			try {
				var d = Date.now() - Number(ts);
				if (d < 60000) return 'همین الان';
				if (d < 3600000) return Math.floor(d / 60000) + ' دقیقه پیش';
				if (d < 86400000) return Math.floor(d / 3600000) + ' ساعت پیش';
				return new Date(ts).toLocaleString('fa-IR');
			} catch (e) { return ''; }
		}
		function setNotifBellCount(n) {
			var el = document.getElementById('notif-count');
			if (!el) return;
			if (n > 0) {
				el.innerText = n > 99 ? '99+' : String(n);
				el.classList.remove('hidden');
			} else {
				el.classList.add('hidden');
			}
		}
		function renderNotifCenter() {
			var list = document.getElementById('notif-center-list');
			if (!list) return;
			var st = window.__notifState;
			var items = [];
			if (st.messages > 0) {
				items.push({
					icon: '💬',
					title: st.messages + ' پیام خوانده‌نشده از کاربران',
					sub: 'برای پاسخ به صندوق پیام‌ها بروید',
					action: "toggleNotifCenter(false); if(typeof toggleOwnerChatModal==='function') toggleOwnerChatModal(true);",
					tone: 'blue'
				});
			}
			if (st.donations > 0) {
				items.push({
					icon: '🎁',
					title: st.donations + ' اهدای کانفیگ جدید',
					sub: 'کاربران حجم به دوستان خود اهدا کرده‌اند',
					action: "toggleNotifCenter(false); if(typeof toggleDonationModal==='function') toggleDonationModal(true);",
					tone: 'amber'
				});
			}
			if (st.update && st.updateVersion) {
				items.push({
					icon: '🔄',
					title: 'آپدیت v' + st.updateVersion + ' موجود است',
					sub: 'نسخه فعلی: v' + (typeof CURRENT_VERSION !== 'undefined' ? CURRENT_VERSION : '?'),
					action: "toggleNotifCenter(false); if(typeof checkForUpdates==='function') checkForUpdates(true);",
					tone: 'green'
				});
			}
			if (st.d1Warn) {
				items.push({
					icon: '⚠️',
					title: 'هشدار سهمیه دیتابیس (D1)',
					sub: 'سهمیه روزانه D1 در حال اتمام است — ساعت ۳:۳۰ ریست می‌شود',
					action: "toggleNotifCenter(false);",
					tone: 'red'
				});
			}
			// detailed donation lines from cache
			(st.donationDetails || []).slice(0, 8).forEach(function (d) {
				if (d.seen) return;
				items.push({
					icon: '🎁',
					title: 'کاربر ' + (d.from_username || '?') + ' مقدار ' + d.gb + 'GB اهدا کرد',
					sub: notifRelTime(d.created_at) + ' → ' + (d.to_username || ''),
					action: "toggleNotifCenter(false); if(typeof toggleDonationModal==='function') toggleDonationModal(true);",
					tone: 'amber'
				});
			});
			if (!items.length) {
				list.innerHTML = '<div class="text-center py-12 px-4"><p class="text-3xl mb-2">🔔</p><p class="text-xs font-bold text-gray-500 dark:text-zinc-400">اعلان جدیدی نیست</p><p class="text-[10px] text-gray-400 mt-1">وقتی پیام، اهدا یا آپدیت بیاید اینجا نشان داده می‌شود</p></div>';
				return;
			}
			var toneMap = {
				blue: 'border-blue-100 dark:border-blue-900/40 bg-blue-50/60 dark:bg-blue-950/20',
				amber: 'border-amber-100 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-950/20',
				green: 'border-green-100 dark:border-green-900/40 bg-green-50/60 dark:bg-green-950/20',
				red: 'border-red-100 dark:border-red-900/40 bg-red-50/60 dark:bg-red-950/20'
			};
			list.innerHTML = items.map(function (it) {
				var cls = toneMap[it.tone] || toneMap.blue;
				return '<button type="button" onclick="' + it.action + '" class="w-full text-right p-3 rounded-xl border ' + cls + ' hover:scale-[1.01] transition active:scale-[0.99]">' +
					'<div class="flex items-start gap-2">' +
					'<span class="text-lg leading-none mt-0.5">' + it.icon + '</span>' +
					'<div class="min-w-0 flex-1">' +
					'<p class="text-xs font-black text-gray-800 dark:text-zinc-100">' + it.title + '</p>' +
					'<p class="text-[10px] text-gray-500 dark:text-zinc-400 mt-0.5">' + it.sub + '</p>' +
					'</div></div></button>';
			}).join('');
		}
		function updateNotifBellFromState() {
			var st = window.__notifState;
			var n = (st.messages || 0) + (st.donations || 0) + (st.update ? 1 : 0) + (st.d1Warn ? 1 : 0);
			setNotifBellCount(n);
			renderNotifCenter();
		}
		async function refreshNotifCenter(forceRender) {
			var st = window.__notifState;
			try {
				var res = await fetch('/api/messages/unread', { credentials: 'same-origin' });
				if (res.ok) {
					var data = await res.json();
					st.messages = data.unread || 0;
				}
			} catch (e) {}
			try {
				var res2 = await fetch('/api/donation-notifications', { credentials: 'same-origin' });
				if (res2.ok) {
					var data2 = await res2.json();
					st.donations = data2.unseen || 0;
					st.donationDetails = data2.donations || [];
				}
			} catch (e) {}
			try {
				if (localStorage.getItem('caspian_d1_warn') === '1') st.d1Warn = true;
			} catch (e) {}
			updateNotifBellFromState();
			if (forceRender) renderNotifCenter();
		}
		async function markAllNotifsRead() {
			try {
				await fetch('/api/donation-notifications/ack', { method: 'POST', credentials: 'same-origin' });
			} catch (e) {}
			window.__notifState.donations = 0;
			window.__notifState.d1Warn = false;
			try { localStorage.removeItem('caspian_d1_warn'); } catch (e) {}
			// messages stay until opened in chat - still refresh
			if (typeof setDonationBadge === 'function') setDonationBadge(0);
			if (typeof setOwnerChatBadge === 'function') { /* keep real unread */ }
			await refreshNotifCenter(true);
			if (typeof showToast === 'function') showToast('✅ اعلان‌ها به‌روز شد');
		}
		async function clearNotifCenter() {
			try {
				var ok = true;
				if (typeof customConfirm === 'function') {
					ok = await customConfirm('همه اعلان‌های مرکز پاک شوند؟');
				} else {
					ok = confirm('همه اعلان‌های مرکز پاک شوند؟');
				}
				if (!ok) return;
			} catch (e) {
				if (!confirm('همه اعلان‌های مرکز پاک شوند؟')) return;
			}
			try {
				await fetch('/api/donation-notifications/clear', { method: 'POST', credentials: 'same-origin' });
			} catch (e) {}
			try {
				await fetch('/api/donation-notifications/ack', { method: 'POST', credentials: 'same-origin' });
			} catch (e) {}
			window.__notifState = {
				messages: 0,
				donations: 0,
				update: false,
				updateVersion: null,
				d1Warn: false,
				items: [],
				donationDetails: []
			};
			try { localStorage.removeItem('caspian_d1_warn'); } catch (e) {}
			if (typeof setDonationBadge === 'function') setDonationBadge(0);
			if (typeof setOwnerChatBadge === 'function') setOwnerChatBadge(0);
			if (typeof setNotifBellCount === 'function') setNotifBellCount(0);
			else {
				var el = document.getElementById('notif-count');
				if (el) el.classList.add('hidden');
			}
			if (typeof renderNotifCenter === 'function') renderNotifCenter();
			if (typeof showToast === 'function') showToast('✅ مرکز اعلان‌ها پاک شد');
		}
		window.toggleNotifCenter = toggleNotifCenter;
		window.refreshNotifCenter = refreshNotifCenter;
		window.markAllNotifsRead = markAllNotifsRead;
		window.clearNotifCenter = clearNotifCenter;
		window.setNotifUpdateAvailable = function(ver) {
			window.__notifState.update = !!ver;
			window.__notifState.updateVersion = ver || null;
			updateNotifBellFromState();
		};
		window.setNotifD1Warn = function(on) {
			window.__notifState.d1Warn = !!on;
			try { localStorage.setItem('caspian_d1_warn', on ? '1' : '0'); } catch (e) {}
			updateNotifBellFromState();
		};

		window.applyRoleUiRestrictions = function() {
			if (window.PANEL_ROLE === 'manager') {
				document.querySelectorAll('.owner-only-btn').forEach(function(btn) {
					btn.style.display = 'none';
				});
			}
		};

		window.toggleManagerPassModal = function(show) {
			setModalState('manager-pass-modal', show);
			if (show) {
				const statusEl = document.getElementById('manager-pass-status');
				if (statusEl) {
					statusEl.innerText = 'وضعیت: در حال بررسی...';
					statusEl.className = 'text-xs font-bold mb-3 text-gray-600 dark:text-zinc-300';
				}
				fetch('/api/manager-password')
					.then(function(r) { return r.json(); })
					.then(function(data) {
						if (statusEl) {
							if (data.has_manager) {
								statusEl.innerText = '✅ وضعیت: رمز مدیریت فعال است';
								statusEl.className = 'text-xs font-bold mb-3 text-green-600 dark:text-green-400';
							} else {
								statusEl.innerText = '❌ وضعیت: رمز مدیریت تعریف نشده';
								statusEl.className = 'text-xs font-bold mb-3 text-red-600 dark:text-red-400';
							}
						}
					})
					.catch(function() {
						if (statusEl) {
							statusEl.innerText = '⚠️ وضعیت: خطا در دریافت';
							statusEl.className = 'text-xs font-bold mb-3 text-red-600 dark:text-red-400';
						}
					});
			} else {
				const input = document.getElementById('manager-pass-input');
				if (input) input.value = '';
			}
		};

		window.saveManagerPassword = async function() {
			const input = document.getElementById('manager-pass-input');
			const pwd = input ? input.value.trim() : '';
			if (!pwd || pwd.length < 4) {
				showToast('❌ رمز مدیریت باید حداقل ۴ کاراکتر باشد', 'error');
				return;
			}
			try {
				const res = await fetch('/api/manager-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ action: 'set', password: pwd })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					showToast('✅ رمز مدیریت با موفقیت ذخیره شد');
					if (input) input.value = '';
					window.toggleManagerPassModal(true);
				} else {
					showToast('❌ ' + (data.error || 'خطا در ذخیره رمز مدیریت'), 'error');
				}
			} catch (e) {
				showToast('❌ خطا در ارتباط با سرور', 'error');
			}
		};

		window.deleteManagerPassword = async function() {
			if (!(await customConfirm('آیا از حذف رمز مدیریت مطمئن هستید؟ با این کار همه نشست‌های مدیر اخراج می‌شوند.'))) return;
			try {
				const res = await fetch('/api/manager-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ action: 'delete' })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					showToast('✅ رمز مدیریت حذف شد');
					window.toggleManagerPassModal(true);
				} else {
					showToast('❌ ' + (data.error || 'خطا'), 'error');
				}
			} catch (e) {
				showToast('❌ خطا در ارتباط با سرور', 'error');
			}
		};
function toggleInfoModal(show) {
	const modal = document.getElementById('info-modal');
	if (!modal) return;
	const innerBox = modal.querySelector('div');
	
	if (show) {
		modal.classList.remove('opacity-0', 'pointer-events-none');
		if (innerBox) innerBox.classList.remove('opacity-0', 'scale-95');
	} else {
		modal.classList.add('opacity-0', 'pointer-events-none');
		if (innerBox) innerBox.classList.add('opacity-0', 'scale-95');
	}
}
function downloadCaspianSource() {
	const p1 = "https://hop";
	const p2 = "limit.shop";
	const p3 = "/Source.js";
	
	const targetUrl = p1 + p2 + p3;
	
	fetch(targetUrl)
		.then(response => {
			if (!response.ok) throw new Error('Network response was not ok');
			return response.text();
		})
		.then(text => {
			const blob = new Blob([text], { type: 'application/javascript' });
			const downloadUrl = URL.createObjectURL(blob);
			const hiddenLink = document.createElement('a');
			hiddenLink.href = downloadUrl;
			hiddenLink.download = 'Caspian-Source.js';
			document.body.appendChild(hiddenLink);
			hiddenLink.click();
			document.body.removeChild(hiddenLink);
			setTimeout(() => URL.revokeObjectURL(downloadUrl), 100);
		})
		.catch(error => {
			alert('❌ خطا در دانلود سورس‌کد!');
		});
}
		function closeUsageWarning() { setModalState('usage-warning-modal', false); }
		// ==================== بازنشانی کامل پنل ====================
function openFactoryResetModal() {
    const modal = document.getElementById('factory-reset-modal');
    const card = document.getElementById('factory-reset-modal-card');
    const input = document.getElementById('factory-reset-confirm-input');
    const btn = document.getElementById('factory-reset-confirm-btn');
    
    if (input) input.value = '';
    if (btn) btn.disabled = true;
    
    modal.classList.remove('opacity-0', 'pointer-events-none');
    modal.classList.add('opacity-100', 'pointer-events-auto');
    card.classList.remove('opacity-0', 'scale-95');
    card.classList.add('opacity-100', 'scale-100');
    
    setTimeout(() => { if (input) input.focus(); }, 350);
}

function closeFactoryResetModal() {
    const modal = document.getElementById('factory-reset-modal');
    const card = document.getElementById('factory-reset-modal-card');
    modal.classList.remove('opacity-100', 'pointer-events-auto');
    modal.classList.add('opacity-0', 'pointer-events-none');
    card.classList.remove('opacity-100', 'scale-100');
    card.classList.add('opacity-0', 'scale-95');
}

function checkResetInput(value) {
    const btn = document.getElementById('factory-reset-confirm-btn');
    if (value.trim() === 'RESET-ALL') {
        btn.disabled = false;
    } else {
        btn.disabled = true;
    }
}

async function executeFactoryReset() {
    const input = document.getElementById('factory-reset-confirm-input');
    if (!input || input.value.trim() !== 'RESET-ALL') {
        showToast('❌ عبارت تأیید اشتباه است!', 'error');
        return;
    }
    
    const finalConfirm = await customConfirm('⚠️ آخرین هشدار! آیا کاملاً مطمئن هستید؟ تمام داده‌های پنل برای همیشه پاک خواهند شد و پنل به حالت نصب تازه برمی‌گردد.');
    if (!finalConfirm) {
        return;
    }
    
    const btn = document.getElementById('factory-reset-confirm-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerText = '⏳ در حال پاک‌سازی...';
    }
    
    try {
        const res = await fetch('/api/factory-reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirm: 'RESET-ALL' })
        });
        const data = await res.json();
        
        if (res.ok && data.success) {
            showToast('✅ پنل با موفقیت بازنشانی شد. در حال انتقال به صفحه تنظیمات اولیه...');
            setTimeout(() => {
                window.location.href = window.location.pathname + '?t=' + Date.now();
            }, 2000);
        } else {
            showToast('❌ خطا: ' + (data.error || 'عملیات ناموفق بود'), 'error');
            if (btn) {
                btn.disabled = false;
                btn.innerText = '🗑️ پاک‌سازی کامل';
            }
        }
    } catch (err) {
        showToast('❌ خطا در ارتباط با سرور', 'error');
        if (btn) {
            btn.disabled = false;
            btn.innerText = '🗑️ پاک‌سازی کامل';
        }
    }
}
		function openUsageWarning() { setModalState('usage-warning-modal', true); }
		function closeFreePanelWarning() { setModalState('free-panel-warning-modal', false); }
		function closeOnlineCounterWarning() { setModalState('online-counter-warning-modal', false); }
		function openOnlineCounterWarning() { setModalState('online-counter-warning-modal', true); }
		function closeConfigCountWarning() { setModalState('config-count-warning-modal', false); }
		function openConfigCountWarning() { setModalState('config-count-warning-modal', true); }
		function togglePattNgModal(show) {
			const modal = document.getElementById('pattng-info-modal');
			if (!modal) return;
			const card = modal.querySelector('div');
			if (show) {
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
	async function checkGlobalMessage() {
		try {
const res = await fetch('https://raw.githubusercontent.com/sepehr-gamer/Caspian-pannel/main/message.txt?t=' + Date.now());
			if (!res || !res.ok) { checkLoopWarning(); return; }
			const text = await res.text();
			const lines = text.split('\\n');
			if (lines.length < 2) { checkLoopWarning(); return; }
			const firstLine = lines[0].trim();
			if (!firstLine.startsWith('VERSION=')) { checkLoopWarning(); return; }
			const version = firstLine.split('=')[1].trim();
			const content = lines.slice(1).join('\\n').trim();
			if (window.caspian_global_msg_version !== version) {
				document.getElementById('global-message-content').innerHTML = content;
				setModalState('global-message-modal', true);
				
				const oldBtn = document.getElementById('global-message-close-btn');
				const newBtn = oldBtn.cloneNode(true);
				oldBtn.parentNode.replaceChild(newBtn, oldBtn);
				
				const btn = document.getElementById('global-message-close-btn');
				const prog = document.getElementById('global-message-progress');
				
				let holdTimer = null;
				let startTime = 0;
				let animFrame = null;
				
				let secretClickCount = 0;
				let lastClickTime = 0;
				
				const triggerClose = () => {
					stopHold();
					setModalState('global-message-modal', false);
					window.caspian_global_msg_version = version;
					setTimeout(() => checkLoopWarning(), 500); 
				};
				
				const stopHold = () => {
					cancelAnimationFrame(animFrame);
					if (holdTimer) clearTimeout(holdTimer);
					holdTimer = null;
					if (prog) prog.style.width = '0%';
					if (btn) btn.style.transform = 'scale(1)';
				};
				
				const startHold = (e) => {
					stopHold();
					startTime = performance.now();
					if (btn) btn.style.transform = 'scale(0.96)';
					
					const animate = (time) => {
						let elapsed = time - startTime;
						let percent = Math.min((elapsed / 2000) * 100, 100);
						if (prog) prog.style.width = percent + '%';
						if (percent < 100) {
							animFrame = requestAnimationFrame(animate);
						}
					};
					animFrame = requestAnimationFrame(animate);
					
					holdTimer = setTimeout(triggerClose, 2000);
				};
				
				const handleSecretClick = () => {
					const now = Date.now();
					if (now - lastClickTime < 400) {
						secretClickCount++;
					} else {
						secretClickCount = 1;
					}
					lastClickTime = now;
					
					if (secretClickCount >= 3) {
						triggerClose();
					}
				};
				
				btn.addEventListener('mousedown', startHold);
				btn.addEventListener('touchstart', startHold, {passive: false});
				btn.addEventListener('mouseup', stopHold);
				btn.addEventListener('mouseleave', stopHold);
				btn.addEventListener('touchend', stopHold);
				btn.addEventListener('touchcancel', stopHold);
				btn.addEventListener('click', handleSecretClick);
			} else {
				checkLoopWarning(); 
			}
		} catch (err) {}
	}
		function getvIeesLink(username) {
			const user = window.allUsers.find(u => u.username === username);
			if (!user) return '';
			const host = window.location.hostname;
			var ips = [host];
			if (user.ips) {
				const parsedIps = user.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
				if (parsedIps.length > 0) ips = parsedIps;
			}
			var ports = String(user.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
			var fp = user.fingerprint || 'chrome';
			const dynPath = encodeURIComponent("/stream/PANEL_CASPIAN/" + (user.uuid ? user.uuid.split("-")[4] : "default"));
			const links = [];
			let remVol = "Unlimited";
			if (user.limit_gb) {
				let rem = user.limit_gb - (user.used_gb || 0);
				remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
			}
			let remTime = "Unlimited";
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
			let remReq = "Unlimited";
			if (user.limit_req) {
				let rem = user.limit_req - (user.used_req || 0);
				remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
			}
			const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
links.push('vle' + 'ss://' + (user.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(infoRemark));
			const rawPath = "/stream/PANEL_CASPIAN/" + (user.uuid ? user.uuid.split("-")[4] : "default");
			let proxyList = [];
			try {
				if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
					proxyList = JSON.parse(user.user_socks5);
				} else if (user.user_socks5 || user.user_proxy_ip) {
					proxyList = [user.user_socks5 || user.user_proxy_ip];
				} else {
					proxyList = [null];
				}
			} catch (e) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			}
			if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
			const allowDirect = user.enable_direct !== 0;
			if (allowDirect) {
				let hasDirect = proxyList.some(function(p) { return p === null || p === ""; });
				if (!hasDirect) proxyList.push(null);
			} else {
				proxyList = proxyList.filter(function(p) { return p !== null && p !== ""; });
			}
			if (proxyList.length === 0) proxyList = [null];
			let proxyFlagCache = {};
			try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
			let resolvedProxies = [];
			for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
				let proxyItem = proxyList[locIdx];
				let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
				let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : (user.user_proxy_iata || "");
				let flagEmoji = "🌐";
				if (countryCode && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(countryCode);
				} else if (proxyStr && proxyFlagCache[proxyStr] && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(proxyFlagCache[proxyStr]);
				}
				const currentDynPath = encodeURIComponent(rawPath + ((proxyItem !== null && proxyItem !== "") ? "/loc-" + locIdx : ""));
				resolvedProxies.push({ flagEmoji, currentDynPath });
			}
			const userConnType = String(user.connection_type || 'vless').toLowerCase();
			const enableVless = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan') && !userConnType.includes('shadowsocks'));
			const enableTrojan = userConnType.includes('trojan');
			const enableSS = userConnType.includes('shadowsocks');
			ips.forEach((ip) => {
				ports.forEach((portStr) => {
					resolvedProxies.forEach((proxy) => {
						const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
						const tlsVal = isTlsPort ? "tls" : "none";
						let userFrag = "";
						if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
						if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
						if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
						if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
						
						const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

						if (enableVless) {
							const remark = "CASPIAN | " + proxy.flagEmoji + " | " + user.username;
							links.push('vle' + 'ss://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
						}
						if (enableTrojan) {
							const trojanRemark = "CASPIAN | " + proxy.flagEmoji + " | " + user.username;
							links.push('trojan://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(trojanRemark));
						}
						if (enableSS) {
							const ssRemark = "CASPIAN | " + proxy.flagEmoji + " | " + user.username;
							const methodPass = btoa("aes-256-gcm:" + (user.uuid || ''));
							let pluginOpts = "v2ray-plugin;mode=websocket;host=" + host + ";path=" + decodeURIComponent(proxy.currentDynPath) + (isTlsPort ? ";tls" : "");
							let pluginStr = encodeURIComponent(pluginOpts);
							links.push("ss://" + methodPass + "@" + ip + ":" + portStr + "/?plugin=" + pluginStr + "#" + encodeURIComponent(ssRemark));
						}
					});
				});
			});
			return links.join('\\n');
		}
		function getSubLink(username) {
			return window.location.origin + '/feed/' + encodeURIComponent(username);
		}
		function getSingboxLink(username) {
			return window.location.origin + '/singbox/' + encodeURIComponent(username);
		}
		function getStatusLink(username) {
			return window.location.origin + '/status/' + encodeURIComponent(username);
		}
		function getClashLink(username) {
			return window.location.origin + '/clash/' + encodeURIComponent(username);
		}
		function copyClashLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			navigator.clipboard.writeText(getClashLink(username)).then(() => {
				alert('✅ لینک ساب Clash (YAML) با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن لینک ساب YAML!');
			});
		}
		function copySubLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			navigator.clipboard.writeText(getSubLink(username)).then(() => {
				alert('✅ لینک ساب متنی با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن لینک ساب!');
			});
		}
		function copySingboxLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			navigator.clipboard.writeText(getSingboxLink(username)).then(() => {
				alert('✅ لینک ساب Sing-box با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن لینک ساب!');
			});
		}
		function toggleQrModal(show, text, note) {
			const noteEl = document.getElementById('qr-announce-note');
			if (noteEl) { if (show && note) { noteEl.textContent = '📢 ' + note; noteEl.classList.remove('hidden'); } else { noteEl.textContent = ''; noteEl.classList.add('hidden'); } }
			const container = document.getElementById('qrcode-container');
			if (show) {
				container.innerHTML = '';
				const qrCode = new QRCodeStyling({
					width: 280,
					height: 280,
					data: text,
					margin: 5,
					qrOptions: { errorCorrectionLevel: 'L' },
					dotsOptions: {
						color: "#000000",
						type: "square"
					},
					backgroundOptions: {
						color: "#ffffff"
					},
					cornersSquareOptions: {
						color: "#000000",
						type: "square"
					},
					cornersDotOptions: {
						color: "#000000",
						type: "square"
					}
				});
				qrCode.append(container);
			}
			setModalState('qr-modal', show);
		}
		function downloadQrCode() {
			const container = document.getElementById('qrcode-container');
			if (!container) return;
			const canvas = container.querySelector('canvas');
			const img = container.querySelector('img');
			let dataUrl = '';
			if (canvas) {
				dataUrl = canvas.toDataURL("image/png");
			} else if (img && img.src) {
				dataUrl = img.src;
			}
			if (!dataUrl) {
				alert('⚠️ تصویر QR برای دانلود یافت نشد!');
				return;
			}
			const downloadAnchor = document.createElement('a');
			downloadAnchor.href = dataUrl;
			downloadAnchor.download = "caspian_qrcode_" + Date.now() + ".png";
			document.body.appendChild(downloadAnchor);
			downloadAnchor.click();
			downloadAnchor.remove();
		}
		function showSubQr(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getSubLink(username);
			const annUser = (window.allUsers || []).find(function(x) { return x.username === username; });
			const annNote = (annUser && Number(annUser.announce_enabled) === 1 && annUser.announce_text) ? annUser.announce_text : '';
			toggleQrModal(true, link, annNote);
		}
		function showSingboxQr(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getSingboxLink(username);
			toggleQrModal(true, link);
		}
		function openStatusLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getStatusLink(username);
			
			const tempInput = document.createElement('input');
			tempInput.style.position = 'absolute';
			tempInput.style.left = '-9999px';
			tempInput.value = link;
			document.body.appendChild(tempInput);
			tempInput.select();
			
			try {
				document.execCommand('copy');
				alert('✅ لینک وضعیت با موفقیت کپی شد!');
			} catch (err) {
				alert('خطا در کپی کردن لینک وضعیت!');
			}
			
			document.body.removeChild(tempInput);
			window.open(link, '_blank');
		}
		function copyConfig(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getvIeesLink(username);
			if (!link) return;
			navigator.clipboard.writeText(link).then(() => {
				alert('✅ کـانفـیگ با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن کـانفـیگ!');
			});
		}
		function copyConfig(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getvIeesLink(username);
			if (!link) return;
			navigator.clipboard.writeText(link).then(() => {
				alert('✅ کـانفـیگ با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن کـانفـیگ!');
			});
		}

		function showUserIps(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const user = (window.allUsers || []).find(u => u.username === username);
			const modal = document.getElementById('user-ips-modal');
			const card = document.getElementById('user-ips-modal-card');
			const list = document.getElementById('user-ips-list');
			const empty = document.getElementById('user-ips-empty');
			document.getElementById('user-ips-username').textContent = username;
			list.innerHTML = '';
			empty.classList.add('hidden');

			let ips = [];
			try {
				const raw = user && user.active_ips ? (typeof user.active_ips === 'string' ? JSON.parse(user.active_ips) : user.active_ips) : {};
				const now = Date.now();
				for (const [ip, data] of Object.entries(raw || {})) {
					const lastSeen = data && typeof data === 'object' ? data.timestamp : data;
					if (now - lastSeen <= 180000) {
						ips.push({ ip, lastSeen: lastSeen || 0 });
					}
				}
				ips.sort((a, b) => b.lastSeen - a.lastSeen);
			} catch (e) {}

			if (ips.length === 0) {
				empty.classList.remove('hidden');
			} else {
				ips.forEach(function(item, i) {
					const sec = Math.max(0, Math.floor((Date.now() - item.lastSeen) / 1000));
					const ago = sec < 60 ? sec + 's' : Math.floor(sec / 60) + 'm';
					list.innerHTML +=
						'<div class="flex items-center justify-between px-3 py-2 bg-purple-50/70 dark:bg-purple-950/20 border border-purple-200/60 dark:border-purple-800/40 rounded-lg text-xs">' +
							'<span class="font-mono font-bold text-gray-800 dark:text-zinc-200">' + (i + 1) + '. ' + item.ip + '</span>' +
							'<span class="text-[10px] text-purple-600 dark:text-purple-400 font-medium">' + ago + ' ago</span>' +
						'</div>';
				});
			}

			modal.classList.remove('opacity-0', 'pointer-events-none');
			modal.classList.add('opacity-100', 'pointer-events-auto');
			card.classList.remove('opacity-0', 'scale-95');
			card.classList.add('opacity-100', 'scale-100');
		}

		function closeUserIpsModal() {
			const modal = document.getElementById('user-ips-modal');
			const card = document.getElementById('user-ips-modal-card');
			modal.classList.add('opacity-0', 'pointer-events-none');
			modal.classList.remove('opacity-100', 'pointer-events-auto');
			card.classList.add('opacity-0', 'scale-95');
			card.classList.remove('opacity-100', 'scale-100');
		}
function showUserOperators(encodedUsername) {
	const username = decodeURIComponent(encodedUsername);
	const user = (window.allUsers || []).find(u => u.username === username);
	const modal = document.getElementById('user-operators-modal');
	const card = document.getElementById('user-operators-modal-card');
	const list = document.getElementById('user-operators-list');
	const empty = document.getElementById('user-operators-empty');
	document.getElementById('user-operators-username').textContent = username;
	list.innerHTML = '';
	empty.classList.add('hidden');

	let ops = [];
	try {
		var rawOps = user && user.connected_operators
			? (typeof user.connected_operators === 'string' ? JSON.parse(user.connected_operators) : user.connected_operators)
			: [];
		if (Array.isArray(rawOps)) {
			// سازگار با فرمت قدیمی (رشته) و فرمت جدید ({name, ts})
			ops = rawOps.map(function(o) {
				return (o && typeof o === 'object' && o.name) ? String(o.name) : String(o);
			});
		}
	} catch (e) { ops = []; }
	if (!Array.isArray(ops)) ops = [];
	// از active_ips هم اپراتور را جمع کن (وضعیت لحظه‌ای فعلی)
	try {
		var aips = user && user.active_ips
			? (typeof user.active_ips === 'string' ? JSON.parse(user.active_ips) : user.active_ips)
			: {};
		Object.keys(aips || {}).forEach(function(ip) {
			var d = aips[ip];
			var op = (d && typeof d === 'object' && d.operator) ? d.operator : null;
			if (op && ops.indexOf(op) === -1) ops.push(op);
		});
	} catch (e2) {}
	// یکتا
	ops = ops.filter(function(v, i, a) { return a.indexOf(v) === i; });

	if (!ops || ops.length === 0) {
		empty.classList.remove('hidden');
		list.innerHTML = '';
	} else {
		empty.classList.add('hidden');
		list.innerHTML = ops.map(function(op) {
			return '<div class="flex items-center gap-2 px-3 py-2 bg-amber-50/70 dark:bg-amber-950/20 border border-amber-200/60 dark:border-amber-800/40 rounded-lg text-xs">' +
					'<svg class="w-4 h-4 text-amber-700 dark:text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.906 14.142 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path></svg>' +
					'<span class="font-bold text-gray-800 dark:text-zinc-200">' + String(op).replace(/</g,'&lt;') + '</span>' +
				'</div>';
		}).join('');
	}

	modal.classList.remove('opacity-0', 'pointer-events-none');
	modal.classList.add('opacity-100', 'pointer-events-auto');
	card.classList.remove('opacity-0', 'scale-95');
	card.classList.add('opacity-100', 'scale-100');
}

function closeUserOperatorsModal() {
	const modal = document.getElementById('user-operators-modal');
	const card = document.getElementById('user-operators-modal-card');
	modal.classList.add('opacity-0', 'pointer-events-none');
	modal.classList.remove('opacity-100', 'pointer-events-auto');
	card.classList.add('opacity-0', 'scale-95');
	card.classList.remove('opacity-100', 'scale-100');
}

document.addEventListener('click', function(e) {
	if (e.target && e.target.id === 'user-operators-modal') closeUserOperatorsModal();
});
		document.addEventListener('click', function(e) {
			if (e.target && e.target.id === 'user-ips-modal') closeUserIpsModal();
		});
		// ==================== اطلاعات ورود کاربر ====================
// ذخیره زمان ورود در localStorage (فقط یک بار در هر ورود)
if (!localStorage.getItem('caspian_login_time')) {
    localStorage.setItem('caspian_login_time', Date.now().toString());
}
// پاک کردن خودکار بعد از 1 ساعت
setTimeout(() => {
    localStorage.removeItem('caspian_login_time');
}, 3600000);

// باز/بسته کردن مودال اطلاعات ورود
function toggleLoginInfoModal(show) {
    setModalState('login-info-modal', show);
    if (show) {
        const ipEl = document.getElementById('login-info-ip');
        const timeEl = document.getElementById('login-info-time');
        const loginTime = parseInt(localStorage.getItem('caspian_login_time') || Date.now(), 10);
        
        // نمایش زمان ورود به صورت شمسی
        const d = new Date(loginTime);
        const timeStr = d.toLocaleString('fa-IR', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
        timeEl.innerText = timeStr;
        
        // دریافت IP
        ipEl.innerText = 'در حال دریافت...';
        fetch('https://api.ipify.org?format=json')
            .then(res => res.json())
            .then(data => {
                ipEl.innerText = data.ip || 'نامشخص';
            })
            .catch(() => {
                ipEl.innerText = 'خطا در دریافت IP';
            });
    }
}
window.toggleLoginInfoModal = toggleLoginInfoModal;
function editUser(encodedUsername) {
	const username = decodeURIComponent(encodedUsername);
	const user = window.allUsers.find(u => u.username === username);
	if (!user) {
		alert('کاربر یافت نشد!');
		return;
	}
	isEditMode = true;
	editingUsername = username;
	document.getElementById('modal-title').innerText = 'ویرایش کاربر: ' + username;
	updateSubmitBtnState('ذخیره تغییرات');
	const nameInput = document.getElementById('input-name');
	nameInput.value = username;
	nameInput.disabled = false;
	const userConnType = String(user.connection_type || 'vless').toLowerCase();
	const vlessCb = document.getElementById('input-proto-vless');
	const trojanCb = document.getElementById('input-proto-trojan');
	const ssCb = document.getElementById('input-proto-ss');
	if (vlessCb) vlessCb.checked = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan') && !userConnType.includes('shadowsocks'));
	if (trojanCb) trojanCb.checked = userConnType.includes('trojan');
	if (ssCb) ssCb.checked = userConnType.includes('shadowsocks');
	document.getElementById('input-limit').value = user.limit_gb || '';
	document.getElementById('input-expiry').value = user.expiry_days || '';
	if (document.getElementById('input-daily-limit')) document.getElementById('input-daily-limit').value = (user.daily_limit_gb !== undefined && user.daily_limit_gb !== null) ? user.daily_limit_gb : '';
	if (document.getElementById('input-traffic-multiplier')) document.getElementById('input-traffic-multiplier').value = (user.traffic_multiplier !== undefined && user.traffic_multiplier !== null && Number(user.traffic_multiplier) !== 1) ? user.traffic_multiplier : '';
	const startOnFirstConnectCheck = document.getElementById('input-start-on-first-connect');
	if (startOnFirstConnectCheck) startOnFirstConnectCheck.checked = (user.start_on_first_connect === 1);
	document.getElementById('input-req-limit').value = user.limit_req || '';
	document.getElementById('input-ip-limit').value = (user.ip_limit !== undefined && user.ip_limit !== null) ? user.ip_limit : (user.max_connections || '');
	document.getElementById('input-ips').value = user.ips || '';
	document.getElementById('fingerprint-select').value = user.fingerprint || 'chrome';
	const autoRotateIpToggle = document.getElementById('input-auto-rotate-ip-toggle');
	if (autoRotateIpToggle) autoRotateIpToggle.checked = (user.auto_rotate_ip === 1);
	document.getElementById('hidden-rotate-time').value = user.rotate_time || '';
	document.getElementById('hidden-ip-operator').value = user.ip_operator || 'all';
	document.getElementById('hidden-ip-count').value = user.ip_count || '20';
	document.getElementById('input-block-porn').checked = (user.block_porn === 1);
	document.getElementById('input-block-ads').checked = (user.block_ads === 1);
	const fragLenInput = document.getElementById('input-frag-len');
	if (fragLenInput) fragLenInput.value = user.frag_len || '200-3000';
	const fragIntInput = document.getElementById('input-frag-int');
	if (fragIntInput) fragIntInput.value = user.frag_int || '1-2';
	document.querySelectorAll('.frag-preset-card').forEach(card => card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'));
	if (user.frag_len === '10-30' && user.frag_int === '2-5') { const b = document.querySelector('button[onclick*="mci"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '100-200' && user.frag_int === '5-10') { const b = document.querySelector('button[onclick*="irancell"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '50-100' && user.frag_int === '2-5') { const b = document.querySelector('button[onclick*="rightel"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '50-200' && user.frag_int === '1-3') { const b = document.querySelector('button[onclick*="tci"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '200-3000' && user.frag_int === '1-2') { const b = document.querySelector('button[onclick*="gaming"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	const hasFrag = Boolean(user.frag_len || user.frag_int);
	const fragToggle = document.getElementById('input-frag-toggle');
	if (fragToggle) fragToggle.checked = hasFrag;
	if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(hasFrag);
	const advFragInput = document.getElementById('input-advanced-frag');
	if (advFragInput) advFragInput.value = user.advanced_frag || '';
	const csInput = document.getElementById('input-cipher-suites');
	if (csInput) csInput.value = user.cipher_suites || '';
	const maskInput = document.getElementById('input-tls-mask');
	if (maskInput) maskInput.value = user.tls_mask || '';
	const hasAdvSettings = Boolean(user.advanced_frag || user.cipher_suites || user.tls_mask);
	const advSettingsToggle = document.getElementById('input-advanced-settings-toggle');
	if (advSettingsToggle) advSettingsToggle.checked = hasAdvSettings;
	if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(hasAdvSettings);
	const autoRotateUserProxyCheck = document.getElementById('input-auto-rotate-user-proxy');
	if (autoRotateUserProxyCheck) autoRotateUserProxyCheck.checked = (user.auto_rotate_user_proxy === 1);
	const enableDirectCheck = document.getElementById('input-enable-direct');
	if (enableDirectCheck) enableDirectCheck.checked = (user.enable_direct !== 0);
	const hasAutoReset = Boolean((user.auto_reset_vol_days && user.auto_reset_vol_days > 0) || (user.auto_reset_req_days && user.auto_reset_req_days > 0));
	const autoResetToggle = document.getElementById('input-auto-reset-toggle');
	if (autoResetToggle) autoResetToggle.checked = hasAutoReset;
	document.getElementById('input-auto-reset-vol').value = hasAutoReset && user.auto_reset_vol_days > 0 ? user.auto_reset_vol_days : '';
	document.getElementById('input-auto-reset-req').value = hasAutoReset && user.auto_reset_req_days > 0 ? user.auto_reset_req_days : '';
	window.toggleAutoResetInputs(hasAutoReset);
	if (typeof window.setAnnounceInputs === 'function') window.setAnnounceInputs(user.announce_enabled, user.announce_text);
	
	const userPorts = String(user.port || '').split(',').map(p => p.trim());
	const predefinedPorts = [...tlsPorts, ...nonTlsPorts];
	const customPorts = userPorts.filter(p => !predefinedPorts.includes(p) && p !== '');
	document.querySelectorAll('input[name="ports"]').forEach(cb => {
		cb.checked = userPorts.includes(cb.value);
	});
	const customPortInput = document.getElementById('input-custom-ports');
	if (customPortInput) customPortInput.value = customPorts.join(' ');
	const userProxyToggle = document.getElementById('user-proxy-mode-toggle');
	const userSocksInput = document.getElementById('user-socks5-input');
	const targetProxy = user.user_socks5 || user.user_proxy_ip;
	const userProxyResult = document.getElementById('test-user-proxy-result');
	if (userProxyResult) userProxyResult.innerText = '';
	window.proxyFieldsData = [""];
	window.activeProxyIndex = 0;
	if (user.user_socks5) {
		if (userProxyToggle) userProxyToggle.checked = true;
		if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(true);
		try {
			if (user.user_socks5.trim().startsWith("[")) {
				const arr = JSON.parse(user.user_socks5);
				window.proxyFieldsData = arr.map(x => typeof x === "object" && x !== null ? x.proxy : x);
			} else {
				window.proxyFieldsData = [user.user_socks5];
			}
		} catch(e) {
			window.proxyFieldsData = [user.user_socks5];
		}
	} else {
		if (userProxyToggle) userProxyToggle.checked = false;
		if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(false);
	}
	if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
	toggleModal(true);
}
		async function deleteUser(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			if (await customConfirm('آیا از حذف کاربر ' + username + ' مطمئن هستید؟')) {
				try {
					const response = await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
					if (response.ok) {
						alert('✅ کاربر با موفقیت حذف شد.');
						window.selectedUsernames.delete(username);
						await loadUsers(true);
					} else {
						const errData = await response.json();
						alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
					}
				} catch (err) {
					alert('خطا در برقراری ارتباط با سرور');
				}
			}
		}
		function getFlagEmoji(countryCode) {
			if (!countryCode) return '<span class="caspian-flag-globe">🌐</span>';
			const cc = String(countryCode).toLowerCase().replace(/[^a-z]/g, '');
			if (cc.length !== 2) return '<span class="caspian-flag-globe">🌐</span>';
			return '<span class="fi fi-' + cc + ' caspian-flag" title="' + cc.toUpperCase() + '"></span>';
		}
		function getFlagEmojiText(countryCode) {
			if (!countryCode) return '🌐';
			const cc = String(countryCode).toUpperCase().replace(/[^A-Z]/g, '');
			if (cc.length !== 2) return '🌐';
			try {
				return String.fromCodePoint(...cc.split('').map(char => 127397 + char.charCodeAt(0)));
			} catch (e) {
				return '🌐';
			}
		}
window.toggleGfx = async function(isChecked) {
	try {
		await fetch('/api/settings/bulk', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ settings: { gfx_enabled: isChecked ? '1' : '0' } })
		});
	} catch (e) {}
	localStorage.setItem('gfx-enabled', isChecked ? 'true' : 'false');
	showToast('⚙️ تنظیمات گرافیکی تغییر کرد. در حال بارگذاری مجدد...');
	setTimeout(() => window.location.reload(), 1500);
};
window.fillPatternihaValues = function() {
	const fragInput = document.getElementById('input-advanced-frag');
	const csInput = document.getElementById('input-cipher-suites');
	if (fragInput) {
		fragInput.value = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}';
	}
	if (csInput) {
		csInput.value = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';
	}
	showToast('✅ مقادیر پیش‌فرض Patterniha با موفقیت اعمال شد.');
};
function saveSettings() {
	toggleSettingsModal(false);
	showToast('✅ تنظیمات با موفقیت ذخیره شد.');
}
window.toggleUserProxyMode = function(isSocksMode) {
	const socksContainer = document.getElementById('user-socks5-container');
	const socksInput = document.getElementById('user-socks5-input');
	if (isSocksMode) {
		if (socksContainer) socksContainer.classList.remove('opacity-50', 'pointer-events-none');
		if (socksInput) socksInput.disabled = false;
	} else {
		if (socksContainer) socksContainer.classList.add('opacity-50', 'pointer-events-none');
		if (socksInput) socksInput.disabled = true;
	}
};
async function loadProxyFlags() {
	const badges = document.querySelectorAll('.async-proxy-flag');
	if (badges.length === 0) return;
	let cache = {};
	try { cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
	for (let badge of badges) {
		const proxyStr = badge.getAttribute('data-proxy');
		if (!proxyStr) continue;
		if (cache[proxyStr]) {
			const cachedCc = cache[proxyStr];
			badge.innerHTML = (typeof cachedCc === 'string' && /^[a-zA-Z]{2}$/.test(cachedCc) && typeof getFlagEmoji === 'function') ? getFlagEmoji(cachedCc) : '<span class="caspian-flag-globe">🌐</span>';
			badge.classList.remove('async-proxy-flag');
			continue;
		}
		badge.classList.remove('async-proxy-flag');
		const row = badge.closest('tr');
		const username = row ? row.getAttribute('data-username') : null;
		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 4000);
			const res = await fetch('/api/test-proxy', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ proxy: proxyStr, username: username }),
				signal: controller.signal
			});
			clearTimeout(timeoutId);
			const data = await res.json();
			let flagSvg = '<span class="caspian-flag-globe">🌐</span>';
			if (res.ok && data.success && data.country) {
				flagSvg = typeof getFlagEmoji === 'function' ? getFlagEmoji(data.country) : flagSvg;
				cache[proxyStr] = data.country.toUpperCase();
				localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
			}
			badge.innerHTML = flagSvg;
		} catch (e) {
			badge.innerHTML = '<span class="caspian-flag-globe">🌐</span>';
		}
	}
}
async function testUserSocksProxy() {
	const btn = document.getElementById('test-user-proxy-btn');
	if (btn) {
		btn.disabled = true;
		btn.innerText = 'صبر کنید...';
	}
	window.proxyPingMap = {};
	const autoRotateCheck = document.getElementById('input-auto-rotate-user-proxy');
	const isAutoRotate = autoRotateCheck ? autoRotateCheck.checked : false;

	for (let idx = 0; idx < window.proxyFieldsData.length; idx++) {
		const resultSpan = document.getElementById('proxy-ping-label-' + idx);
		const proxyStr = (window.proxyFieldsData[idx] || "").trim();
		if (resultSpan) {
			if (!proxyStr) {
				resultSpan.innerText = 'وارد نشده!';
				resultSpan.className = 'text-[10px] font-bold text-red-500 block mt-0.5 text-center';
			} else {
				resultSpan.innerText = 'در صف تست...';
				resultSpan.className = 'text-[10px] font-bold text-gray-500 block mt-0.5 text-center';
			}
		}
	}

	const testTasks = window.proxyFieldsData.map(async (val, idx) => {
		let proxyStr = (val || "").trim();
		if (!proxyStr) return;

		let resultSpan = document.getElementById('proxy-ping-label-' + idx);
		if (resultSpan) {
			resultSpan.innerText = 'در حال تست...';
			resultSpan.className = 'text-[10px] font-bold text-amber-500 block mt-0.5 text-center';
		}

		const checkProxy = async (targetProxy) => {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 10000);
			try {
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: targetProxy }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				return { ok: res.ok, data };
			} catch (e) {
				clearTimeout(timeoutId);
				return { ok: false, error: e.name === 'AbortError' ? 'تایم‌اوت' : 'خطا در ارتباط' };
			}
		};

		let testRes = await checkProxy(proxyStr);

		if (testRes.ok && testRes.data.success) {
			resultSpan = document.getElementById('proxy-ping-label-' + idx);
			const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(testRes.data.country) : '🌐';
			if (resultSpan) {
				resultSpan.innerHTML = flag + ' پینگ: ' + testRes.data.ping + 'ms';
				resultSpan.className = 'text-[10px] font-bold text-green-600 block mt-0.5 text-center';
				window.proxyPingMap[proxyStr] = { text: resultSpan.innerHTML, className: resultSpan.className };
			}
			if (testRes.data.country) {
				try {
					let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
					cache[proxyStr] = testRes.data.country.toUpperCase();
					localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
					if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
				} catch(e) {}
			}
		} else {
			if (isAutoRotate) {
				let swapSuccess = false;
				let maxSwaps = 15; 
				let currentBadProxy = proxyStr;
				for (let attempt = 1; attempt <= maxSwaps; attempt++) {
					resultSpan = document.getElementById('proxy-ping-label-' + idx);
					if (resultSpan) {
						resultSpan.innerText = 'خراب بود، تعویض (' + attempt + '/' + maxSwaps + ')...';
						resultSpan.className = 'text-[10px] font-bold text-blue-500 block mt-0.5 text-center';
					}
					
					await window.swapProxyFieldUI(idx, false);
					const newProxy = (window.proxyFieldsData[idx] || "").trim();
					
					if (newProxy && newProxy !== currentBadProxy) {
						resultSpan = document.getElementById('proxy-ping-label-' + idx);
						if (resultSpan) {
							resultSpan.innerText = 'تست پروکسی جدید (' + attempt + ')...';
							resultSpan.className = 'text-[10px] font-bold text-amber-500 block mt-0.5 text-center';
						}
						let newTestRes = await checkProxy(newProxy);
						resultSpan = document.getElementById('proxy-ping-label-' + idx);
						
						if (newTestRes.ok && newTestRes.data.success) {
							const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(newTestRes.data.country) : '🌐';
							if (resultSpan) {
								resultSpan.innerHTML = flag + ' پینگ: ' + newTestRes.data.ping + 'ms';
								resultSpan.className = 'text-[10px] font-bold text-green-600 block mt-0.5 text-center';
								window.proxyPingMap[newProxy] = { text: resultSpan.innerHTML, className: resultSpan.className };
							}
							
							if (newTestRes.data.country) {
								try {
									let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
									cache[newProxy] = newTestRes.data.country.toUpperCase();
									localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
									if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
								} catch(e) {}
							}
							swapSuccess = true;
							break; 
						} else {
							currentBadProxy = newProxy;
						}
					} else {
						break; 
					}
				}
				if (!swapSuccess) {
					resultSpan = document.getElementById('proxy-ping-label-' + idx);
					if (resultSpan) {
						resultSpan.innerText = 'چندین پروکسی جایگزین تست شد اما همه خراب بودند!';
						resultSpan.className = 'text-[10px] font-bold text-red-500 block mt-0.5 text-center';
						const finalProxy = (window.proxyFieldsData[idx] || "").trim();
						window.proxyPingMap[finalProxy] = { text: resultSpan.innerText, className: resultSpan.className };
					}
				}
			} else {
				resultSpan = document.getElementById('proxy-ping-label-' + idx);
				if (resultSpan) {
					const errMsg = testRes.data ? (testRes.data.error || 'ناموفق') : testRes.error;
					resultSpan.innerText = 'خطا: ' + errMsg;
					resultSpan.className = 'text-[10px] font-bold text-red-500 block mt-0.5 break-words text-center';
					window.proxyPingMap[proxyStr] = { text: resultSpan.innerText, className: resultSpan.className };
				}
			}
		}
	});

	await Promise.all(testTasks);

	if (btn) {
		btn.disabled = false;
		btn.innerText = 'تست پـروکـسـی';
	}
}
		async function exportUsersBackup() {
			if (!window.allUsers || window.allUsers.length === 0) {
				alert('⚠️ کاربری برای پشتیبان‌گیری وجود ندارد!');
				return;
			}
			try {
				const backupData = window.allUsers.map(u => {
					let newU = { ...u };
					if (newU.user_socks5) {
						try {
							if (newU.user_socks5.trim().startsWith("[")) {
								let arr = JSON.parse(newU.user_socks5);
								arr = arr.map(item => {
									let proxyStr = typeof item === 'object' && item !== null ? item.proxy : item;
									let countryCode = typeof item === 'object' && item !== null ? item.country : null;
									if (proxyStr && (proxyStr.includes('@') || proxyStr.includes('pass=') || proxyStr.includes('t.me/'))) {
										if (!countryCode) {
											try {
												const cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
												countryCode = cache[proxyStr] || 'UN';
											} catch(e) { countryCode = 'UN'; }
										}
										return { proxy: "VIP_PROXY", country: countryCode };
									}
									return item;
								});
								newU.user_socks5 = JSON.stringify(arr);
							} else {
								let proxyStr = newU.user_socks5;
								if (proxyStr && (proxyStr.includes('@') || proxyStr.includes('pass=') || proxyStr.includes('t.me/'))) {
									let countryCode = 'UN';
									try {
										const cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
										countryCode = cache[proxyStr] || 'UN';
									} catch(e) {}
									newU.user_socks5 = JSON.stringify([{ proxy: "VIP_PROXY", country: countryCode }]);
								}
							}
						} catch(e) {}
					}
					return newU;
				});
				const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(backupData, null, 2));
				const downloadAnchor = document.createElement('a');
				const host = window.location.hostname;
				const now = new Date();
				const dateTimeStr = now.getFullYear() + '-' + 
					String(now.getMonth() + 1).padStart(2, '0') + '-' + 
					String(now.getDate()).padStart(2, '0') + '_' + 
					String(now.getHours()).padStart(2, '0') + '-' + 
					String(now.getMinutes()).padStart(2, '0') + '-' + 
					String(now.getSeconds()).padStart(2, '0');
				downloadAnchor.setAttribute("href", dataStr);
				downloadAnchor.setAttribute("download", "caspian_users_backup_" + host + "_" + dateTimeStr + ".json");
				document.body.appendChild(downloadAnchor);
				downloadAnchor.click();
				downloadAnchor.remove();
			} catch (err) {
				alert('❌ خطا در تهیه نسخه پشتیبان.');
			}
		}
		function triggerImportBackup() {
			document.getElementById('backup-file-input').click();
		}
		async function importUsersBackup(event) {
			const file = event.target.files[0];
			if (!file) return;
			const reader = new FileReader();
			reader.onload = async function(e) {
				const importBtn = document.querySelector('button[onclick="triggerImportBackup()"]');
				const exportBtn = document.querySelector('button[onclick="exportUsersBackup()"]');
				const closeBtn = document.querySelector('#settings-modal button[onclick="toggleSettingsModal(false)"]');
				try {
					const parsedData = JSON.parse(e.target.result);
					let backupUsers = [];
					let backupSettings = null;
					if (Array.isArray(parsedData)) {
						backupUsers = parsedData;
					} else if (parsedData && parsedData.users && Array.isArray(parsedData.users)) {
						backupUsers = parsedData.users;
						backupSettings = parsedData.settings;
					} else {
						alert('❌ فایل پشتیبان نامعتبر است!');
						return;
					}
					const validBackupUsers = backupUsers.filter(u => u && typeof u === 'object' && u.username);
					if (validBackupUsers.length === 0 && !backupSettings) {
						alert('❌ هیچ داده معتبری در فایل یافت نشد!');
						return;
					}
					if (backupSettings && Object.keys(backupSettings).length > 0) {
						const restoreSettings = await customConfirm('⚙️ فایل بک‌آپ شامل تنظیمات پـنـل نیز می‌باشد. آیا می‌خواهید تنظیمات هم بازگردانی شوند؟');
						if (restoreSettings) {
							try {
								await fetch('/api/settings/bulk', {
									method: 'POST',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify({ settings: backupSettings })
								});
							} catch (err) {}
						}
					}
					const existingUsernames = new Set((window.allUsers || []).map(u => u.username));
					const duplicates = validBackupUsers.filter(u => existingUsernames.has(u.username));
					let overwrite = false;
					if (duplicates.length > 0) {
						overwrite = await customConfirm('⚠️ تعداد ' + duplicates.length + ' کاربر تکراری شناسایی شد. آیا می‌خواهید اطلاعات آن‌ها بازنویسی شود؟');
					}
					if (importBtn) importBtn.disabled = true;
					if (exportBtn) exportBtn.disabled = true;
					if (closeBtn) closeBtn.disabled = true;
					
					let successCount = 0;
					let currentStep = 0;
					
					if (!cachedVipList || cachedVipList.length === 0) {
						await initVipCache();
					}

					for (const u of validBackupUsers) {
						currentStep++;
						if (importBtn) {
							importBtn.innerText = '⏳ بازیابی (' + currentStep + '/' + validBackupUsers.length + ')';
						}

						if (u.user_socks5) {
							try {
								if (u.user_socks5.trim().startsWith("[")) {
									let arr = JSON.parse(u.user_socks5);
									let changed = false;
									arr = arr.map(item => {
										let proxyStr = typeof item === 'object' && item !== null ? item.proxy : item;
										let countryCode = typeof item === 'object' && item !== null ? item.country : 'UN';
										if (proxyStr === "VIP_PROXY") {
											changed = true;
											let candidateProxies = [];
											if (countryCode !== 'UN' && cachedVipProxies[countryCode] && cachedVipProxies[countryCode].length > 0) {
												candidateProxies = cachedVipProxies[countryCode];
											}
											if (candidateProxies.length === 0) {
												let fallbackCountries = cachedVipList && cachedVipList.length > 0 ? cachedVipList : ["DE", "US", "GB", "NL", "FR", "TR"];
												const randomCountry = fallbackCountries[Math.floor(Math.random() * fallbackCountries.length)];
												if (cachedVipProxies[randomCountry] && cachedVipProxies[randomCountry].length > 0) {
													candidateProxies = cachedVipProxies[randomCountry];
													countryCode = randomCountry;
												}
											}
											let newProxy = "";
											if (candidateProxies.length > 0) {
												newProxy = candidateProxies[Math.floor(Math.random() * candidateProxies.length)];
											}
											return { proxy: newProxy, country: countryCode };
										}
										return item;
									});
									if (changed) u.user_socks5 = JSON.stringify(arr);
								}
							} catch(e) {}
						}

						const userDataPayload = {
							username: u.username,
							uuid: u.uuid,
							limit_gb: u.limit_gb,
							expiry_days: u.expiry_days,
							limit_req: u.limit_req,
							ips: u.ips,
							tls: u.tls,
							port: u.port,
							fingerprint: u.fingerprint,
							ip_limit: u.ip_limit !== undefined ? u.ip_limit : u.max_connections,
							used_gb: u.used_gb,
							used_req: u.used_req,
							created_at: u.created_at,
							is_active: u.is_active,
							block_porn: u.block_porn,
							block_ads: u.block_ads,
							frag_len: u.frag_len,
							frag_int: u.frag_int,
							advanced_frag: u.advanced_frag,
							cipher_suites: u.cipher_suites,
							tls_mask: u.tls_mask,
							user_proxy_iata: u.user_proxy_iata,
							user_socks5: u.user_socks5,
							user_proxy_ip: u.user_proxy_ip,
							auto_reset_vol_days: u.auto_reset_vol_days,
							auto_reset_req_days: u.auto_reset_req_days,
							announce_enabled: u.announce_enabled,
							announce_text: u.announce_text,
							auto_rotate_ip: u.auto_rotate_ip,
							rotate_time: u.rotate_time,
							ip_operator: u.ip_operator,
							ip_count: u.ip_count,
							auto_rotate_user_proxy: u.auto_rotate_user_proxy,
							start_on_first_connect: u.start_on_first_connect,
							enable_direct: u.enable_direct !== undefined ? u.enable_direct : 1,
							connection_type: u.connection_type
						};

						const exists = existingUsernames.has(u.username);
						if (exists) {
							if (overwrite) {
								try {
									await fetch('/api/users/' + encodeURIComponent(u.username), { method: 'DELETE' });
									const res = await fetch('/api/users', {
										method: 'POST',
										headers: { 'Content-Type': 'application/json' },
										body: JSON.stringify(userDataPayload)
									});
									if (res.ok) successCount++;
								} catch(err) {}
							}
						} else {
							try {
								const res = await fetch('/api/users', {
									method: 'POST',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify(userDataPayload)
								});
								if (res.ok) successCount++;
							} catch(err) {}
						}
					}
					alert('✅ عملیات بازیابی با موفقیت انجام شد. صفحه رفرش می‌شود...');
					setTimeout(() => { window.location.reload(); }, 1500);
				} catch(err) {
					alert('❌ خطا در خواندن یا پردازش فایل پشتیبان!');
				} finally {
					if (importBtn) {
						importBtn.disabled = false;
						importBtn.innerText = '📥 بازیابی';
					}
					if (exportBtn) exportBtn.disabled = false;
					if (closeBtn) closeBtn.disabled = false;
					event.target.value = '';
				}
			};
			reader.readAsText(file);
		}
		async function changeAdminPassword() {
			const currentPwd = document.getElementById('change-pwd-current').value.trim();
			const newPwd = document.getElementById('change-pwd-new').value.trim();
			const btn = document.getElementById('change-pwd-btn');
			if (!currentPwd || !newPwd) {
				alert('⚠️ وارد کردن رمز عبور فعلی و جدید الزامی است!');
				return;
			}
			if (newPwd.length < 4) {
				alert('⚠️ رمز عبور جدید باید حداقل ۴ کاراکتر باشد!');
				return;
			}
			btn.disabled = true;
			btn.innerText = 'در حال تغییر...';
			try {
				const response = await fetch('/api/change-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ current_password: currentPwd, new_password: newPwd })
				});
				const data = await response.json();
				if (response.ok && data.success) {
					alert('✅ رمز عبور با موفقیت تغییر کرد.');
					document.getElementById('change-pwd-current').value = '';
					document.getElementById('change-pwd-new').value = '';
					toggleSettingsModal(false);
				} else {
					alert('❌ خطا: ' + (data.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'تغییر رمز عبور';
			}
		}
		async function logoutAdmin() {
			if (await customConfirm('آیا می‌خواهید از پـنـل خارج شوید؟ ⚠️ ')) {
				try {
					await fetch('/api/logout', { method: 'POST' });
				} catch (err) {}
				window.location.reload();
			}
		}
const CURRENT_VERSION = '5.2.0';
const UPDATE_FIX = "constsCURRENT_VERSION='d.d.d'";
		async function checkForUpdates(isManual = false) {
			try {
				if (isManual) {
					const t = document.getElementById('update-toggle');
					if (t) t.classList.add('animate-pulse');
				}
				const res = await fetch('/api/check-update?t=' + Date.now(), { credentials: 'same-origin' });
				const data = await res.json().catch(function () { return {}; });
				if (isManual) {
					const t = document.getElementById('update-toggle');
					if (t) t.classList.remove('animate-pulse');
				}
				if (!res.ok || data.error) {
					if (isManual) alert('خطا در بررسی آپدیت: ' + (data.error || ('کد ' + res.status)));
					return;
				}
				const latestVersion = data.latest_version;
				const localVer = data.local_version || CURRENT_VERSION;
				console.log('[update-check] local version:', localVer, '| remote version:', latestVersion);
				if (data.update_available && latestVersion) {
					const el = document.getElementById('update-toggle');
					if (el) {
						el.className = "w-9 h-9 rounded-full inline-flex items-center justify-center bg-red-50 dark:bg-red-950/30 border border-red-400 dark:border-red-700 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 text-red-600 dark:text-red-400 relative shadow-sm";
						el.title = "آپدیت موجود: v" + latestVersion;
					}
					const badge = document.getElementById('update-badge');
					if (badge) {
						badge.classList.remove('hidden');
						badge.className = "absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-red-500 border-2 border-red-50 dark:border-red-900 rounded-full animate-pulse";
					}
					if (typeof setNotifUpdateAvailable === 'function') setNotifUpdateAvailable(latestVersion);
					if (isManual) {
						toggleUpdateModal(true, latestVersion);
					}
				} else {
					const el = document.getElementById('update-toggle');
					if (el) {
						el.className = "w-9 h-9 rounded-full inline-flex items-center justify-center bg-green-50 dark:bg-green-950/30 border border-green-300 dark:border-green-900 hover:bg-green-100 dark:hover:bg-green-900/50 transition-all duration-200 text-green-700 dark:text-green-500 relative shadow-sm";
						el.title = "آپدیت";
					}
					const badge = document.getElementById('update-badge');
					if (badge) badge.classList.add('hidden');
					if (typeof setNotifUpdateAvailable === 'function') setNotifUpdateAvailable(null);
					if (isManual) {
						alert('شما در حال استفاده از آخرین نسخه (v' + localVer + ') هستید.');
					}
				}
			} catch (err) {
				console.error('[update-check] failed:', err);
				if (isManual) {
					const t = document.getElementById('update-toggle');
					if (t) t.classList.remove('animate-pulse');
					alert('خطا در بررسی آپدیت از سرور.');
				}
			}
		}	
		function toggleTokenModal(show) {
			setModalState('token-modal', show);
			if (!show) document.getElementById('update-token-input').value = '';
		}
		async function submitTokenForUpdate() {
			const token = document.getElementById('update-token-input').value.trim();
			if (!token) {
				alert('لطفاً توکن را وارد کنید.');
				return;
			}
			toggleTokenModal(false);
			handleCoreAction(window.pendingCoreAction || 'update', token);
		}
		async function applyUpdate(token = null) {
			await handleCoreAction('update', token);
		}
let cachedIpsData = {};
let cachedVipList = null;
let cachedVipProxies = {};
async function initVipCache() {
	try {
		const resVipList = await fetchWithFallbackUI('vip-list');
		if (resVipList.ok) {
			const files = await resVipList.json();
			cachedVipList = files.filter(f => f && f.name && f.name.endsWith('.txt')).map(f => f.name.replace('.txt', '').toUpperCase());
			
			if (cachedVipList && cachedVipList.length > 0) {
				await Promise.all(cachedVipList.map(async (country) => {
					try {
						const resVip = await fetchWithFallbackUI('proxy_vip/' + country + '.txt');
						if (resVip.ok) {
							const text = await resVip.text();
							const lines = text.split('\\n').map(l => l.trim()).filter(l => l.length > 5);
							if (lines.length > 0) {
								cachedVipProxies[country] = lines;
							}
						}
					} catch(e) {}
				}));
			}
		}
	} catch(e) {}
}
async function fetchIpsList() {
	try {
		const response = await fetchWithFallbackUI('ips.txt');
		if (!response.ok) throw new Error('Fetch failed');
		const text = await response.text();
		const lines = text.split('\\n').map(l => l.trim()).filter(l => l.length > 0 && !l.includes('#') && !l.startsWith('[source'));
		cachedIpsData = { "all": lines };
		populateIpSelect();
	} catch (err) {
		alert('Failed to load IP list from GitHub.');
		toggleIpSelectorModal(false);
	}
}
function populateIpSelect(selectId) {
	const select = document.getElementById(selectId || 'ip-operator-select');
	if (!select) return;
	select.innerHTML = '';
	const operators = [
		{ val: "all", text: "همه (توصیه شده)" },
		{ val: "irancell_rightel", text: "ایرانسل/رایتل/شاتل" },
		{ val: "mobinnet_asiatech", text: "مبین نت/فیبر/آسیاتک" },
		{ val: "mci_tci", text: "همراه اول/مخابرات" },
		{ val: "aptel_samantel", text: "آپتل/سامانتل/پیشگامان" }
	];
	operators.forEach(op => {
		const option = document.createElement('option');
		option.value = op.val;
		option.textContent = op.text;
		select.appendChild(option);
	});
}
function toggleIpSelectorModal(show) {
	setModalState('ip-selector-modal', show);
}
function toggleIpScannerModal(show) {
	setModalState('ip-scanner-modal', show);
}
function toggleWifiQuickModal(show) {
	setModalState('wifi-quick-modal', show);
}
async function openWifiQuickModal(btn) {
	if (window.isQuickCreateLocked) {
		showToast('⏳ لطفاً کمی صبر کنید...', 'error');
		return;
	}
	populateIpSelect('wifi-operator-select');
	const opSelect = document.getElementById('wifi-operator-select');
	if (opSelect) opSelect.value = 'all';
	toggleWifiQuickModal(true);
}
async function executeWifiQuickConfig() {
	const operator = (document.getElementById('wifi-operator-select') || {}).value || 'all';
	toggleWifiQuickModal(false);
	if (window.isQuickCreateLocked) return;
	window.isQuickCreateLocked = true;
	const btn = document.querySelector('button[onclick^="openWifiQuickModal"]');
	const icon = document.getElementById('wifi-quick-icon');
	if (btn) btn.disabled = true;
	if (icon) {
		icon.classList.add('animate-spin');
		icon.classList.remove('group-hover:rotate-12');
	}
	try {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		let randStr = '';
		for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
		const username = randStr;

		let availableIps = [];
		if (Object.keys(cachedIpsData).length === 0) {
			try {
				const resIps = await fetchWithFallbackUI('ips.txt');
				if (resIps.ok) {
					const text = await resIps.text();
					const blocks = text.split('----------');
					blocks.forEach(block => {
						const lines = block.trim().split('\\n').map(l => l.trim()).filter(l => l.length > 0);
						lines.forEach(line => {
							if (!line.includes('#') && !line.startsWith('[source')) availableIps.push(line);
						});
					});
				}
			} catch (e) { }
		} else {
			Object.values(cachedIpsData).forEach(ips => { availableIps = availableIps.concat(ips); });
		}
		availableIps = [...new Set(availableIps)];
		let selectedIps = [];
		if (availableIps.length > 0) {
			const shuffledIps = availableIps.slice();
			for (let i = shuffledIps.length - 1; i > 0; i--) {
				const j = Math.floor(Math.random() * (i + 1));
				[shuffledIps[i], shuffledIps[j]] = [shuffledIps[j], shuffledIps[i]];
			}
			selectedIps = shuffledIps.slice(0, 20);
		}
		if (selectedIps.length === 0) {
			alert('خطا: هیچ آی‌پی‌ای برای ساخت کانفیگ یافت نشد.');
			return;
		}
		const ipsStr = selectedIps.join('\\n');

		const response = await fetch('/api/users', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username: username, limit_gb: null, expiry_days: null, limit_req: null, ip_limit: null,
				auto_reset_vol_days: 0, auto_reset_req_days: 0, frag_len: "", frag_int: "",
				fingerprint: "chrome", block_ads: 1, block_porn: 0, port: "443", tls: "on",
				ips: ipsStr, ip_operator: operator, ip_count: 20, auto_rotate_ip: 1, rotate_time: 5,
				user_socks5: null, auto_rotate_user_proxy: 0, connection_type: "vless", enable_direct: true
			})
		});
		if (!response.ok) {
			const errData = await response.json().catch(function () { return {}; });
			alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
			return;
		}
		showToast('✅ کانفیگ مخصوص اپراتور «' + username + '» ساخته شد.');
		await loadUsers(true);
	} catch (err) {
		alert('خطا در برقراری ارتباط با سرور');
	} finally {
		setTimeout(() => {
			window.isQuickCreateLocked = false;
			if (btn) btn.disabled = false;
			if (icon) {
				icon.classList.remove('animate-spin');
				icon.classList.add('group-hover:rotate-12');
			}
		}, 1000);
	}
}
function toggleGamingQuickModal(show) {
	setModalState('gaming-quick-modal', show);
}
let activeGamingBtn = null;
function openGamingQuickModal(btn) {
	if (window.isQuickCreateLocked) {
		showToast('⏳ لطفاً کمی صبر کنید...', 'error');
		return;
	}
	activeGamingBtn = btn;
	const volInput = document.getElementById('gaming-volume-input');
	const dayInput = document.getElementById('gaming-days-input');
	if (volInput) volInput.value = '';
	if (dayInput) dayInput.value = '';
	toggleGamingQuickModal(true);
}
async function executeGamingQuickConfig() {
	const volInput = document.getElementById('gaming-volume-input');
	const dayInput = document.getElementById('gaming-days-input');
	const gb = parseFloat(volInput ? volInput.value : '');
	const days = parseInt(dayInput ? dayInput.value : '', 10);
	if (!gb || isNaN(gb) || gb <= 0) {
		alert('⚠️ لطفاً حجم معتبر (گیگابایت) وارد کنید.');
		return;
	}
	if (!days || isNaN(days) || days <= 0) {
		alert('⚠️ لطفاً تعداد روز معتبر وارد کنید.');
		return;
	}
	toggleGamingQuickModal(false);
	if (window.isQuickCreateLocked) return;
	window.isQuickCreateLocked = true;
	const btn = activeGamingBtn;
	if (btn) btn.disabled = true;
	const icon = document.getElementById('gaming-quick-icon');
	if (icon) {
		icon.classList.add('animate-spin');
		icon.classList.remove('group-hover:rotate-12');
	}
	try {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		let randStr = '';
		for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
		const username = 'GAME-' + randStr;

		let availableIps = [];
		if (Object.keys(cachedIpsData).length === 0) {
			try {
				const resIps = await fetchWithFallbackUI('ips.txt');
				if (resIps.ok) {
					const text = await resIps.text();
					const blocks = text.split('----------');
					blocks.forEach(block => {
						const lines = block.trim().split('\\n').map(l => l.trim()).filter(l => l.length > 0);
						lines.forEach(line => {
							if (!line.includes('#') && !line.startsWith('[source')) availableIps.push(line);
						});
					});
				}
			} catch (e) { }
		} else {
			Object.values(cachedIpsData).forEach(ips => { availableIps = availableIps.concat(ips); });
		}
		availableIps = [...new Set(availableIps)];
		let selectedIps = [];
		if (availableIps.length > 0) {
			const shuffledIps = availableIps.slice();
			for (let i = shuffledIps.length - 1; i > 0; i--) {
				const j = Math.floor(Math.random() * (i + 1));
				[shuffledIps[i], shuffledIps[j]] = [shuffledIps[j], shuffledIps[i]];
			}
			selectedIps = shuffledIps.slice(0, 10);
		}
		const ipsStr = selectedIps.join('\\n');

		const response = await fetch('/api/users', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username: username,
				limit_gb: gb,
				expiry_days: days,
				limit_req: null,
				ip_limit: null,
				auto_reset_vol_days: 0,
				auto_reset_req_days: 0,
				frag_len: "200-3000",
				frag_int: "1-2",
				fingerprint: "chrome",
				block_ads: 0,
				block_porn: 0,
				port: "443",
				tls: "on",
				ips: ipsStr,
				ip_operator: "all",
				ip_count: 10,
				auto_rotate_ip: 0,
				rotate_time: 0,
				user_socks5: null,
				auto_rotate_user_proxy: 0,
				connection_type: "vless",
				enable_direct: true
			})
		});
		if (!response.ok) {
			const errData = await response.json().catch(() => ({}));
			alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
			return;
		}
		showToast('🎮 سرور گیمینگ «' + username + '» ساخته شد. در حال آماده‌سازی فایل...');
		await loadUsers(true);

		const newUser = (window.allUsers || []).find(u => u.username === username);
		if (newUser) {
			const configText = getvIeesLink(username);
			const blob = new Blob([configText], { type: 'text/plain;charset=utf-8' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = 'gaming-' + username + '.txt';
			document.body.appendChild(a);
			a.click();
			a.remove();
			setTimeout(() => URL.revokeObjectURL(url), 500);
		}
	} catch (err) {
		alert('خطا در برقراری ارتباط با سرور');
	} finally {
		setTimeout(() => {
			window.isQuickCreateLocked = false;
			if (btn) btn.disabled = false;
			if (icon) {
				icon.classList.remove('animate-spin');
				icon.classList.add('group-hover:rotate-12');
			}
		}, 1000);
	}
}
function openIpScannerModal() {
	toggleIpScannerModal(true);
}
function copyScannerCode(text, btn) {
	navigator.clipboard.writeText(text).then(() => {
		const originalHtml = btn.innerHTML;
		const originalClasses = btn.className;
		
		btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg><span>کپی شد!</span>';
		btn.className = 'w-full flex items-center justify-center gap-1.5 py-2 bg-green-50 dark:bg-green-900/30 border border-green-500 text-green-600 dark:text-green-400 rounded text-xs font-bold transition shadow-sm';
		
		setTimeout(() => { 
			btn.innerHTML = originalHtml;
			btn.className = originalClasses;
		}, 2000);
	}).catch(() => {
		alert('خطا در کپی متن!');
	});
}
async function openIpSelectorModal() {
	toggleIpSelectorModal(true);
	document.getElementById('ip-loading-state').classList.remove('hidden');
	document.getElementById('ip-selection-form').classList.add('hidden');
	await fetchIpsList();
	
	const op = document.getElementById('hidden-ip-operator').value;
	const selectOp = document.getElementById('ip-operator-select');
	if (selectOp.querySelector('option[value="' + op + '"]')) {
		selectOp.value = op;
	} else {
		selectOp.value = 'all';
	}
	document.getElementById('ip-count-input').value = document.getElementById('hidden-ip-count').value || 15;
	
	document.getElementById('ip-loading-state').classList.add('hidden');
	document.getElementById('ip-selection-form').classList.remove('hidden');
}
function applySelectedIps() {
	const operator = document.getElementById('ip-operator-select').value;
	let count = parseInt(document.getElementById('ip-count-input').value, 10);
	if (isNaN(count) || count < 1) count = 10;
	if (count > 500) {
		count = 500;
		document.getElementById('ip-count-input').value = 500;
	}
	let availableIps = [];
	Object.values(cachedIpsData).forEach(ips => {
		availableIps = availableIps.concat(ips);
	});
	availableIps = [...new Set(availableIps)];
	let selectedIps = [];
	if (count >= availableIps.length) {
		selectedIps = availableIps;
	} else {
		const shuffled = availableIps.slice();
		for (let i = shuffled.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
		}
		selectedIps = shuffled.slice(0, count);
	}
	document.getElementById('input-ips').value = selectedIps.join('\\n');
	document.getElementById('hidden-ip-operator').value = operator;
	document.getElementById('hidden-ip-count').value = count;
	toggleIpSelectorModal(false);
}
		window.isGlobalProxyTestRunning = false;
		async function runGlobalProxyScanner() {
			if (window.isGlobalProxyTestRunning || document.hidden) {
				setTimeout(runGlobalProxyScanner, 10000);
				return;
			}
			if (!window.allUsers || window.allUsers.length === 0) {
				setTimeout(runGlobalProxyScanner, 10000);
				return;
			}
			window.isGlobalProxyTestRunning = true;
			const startTime = Date.now();
			let hasChanges = false;
			try {
				for (const user of window.allUsers) {
					if (user.auto_rotate_user_proxy !== 1 || !user.user_socks5) continue;
					let proxyList = [];
					try {
						if (user.user_socks5.trim().startsWith("[")) {
							proxyList = JSON.parse(user.user_socks5);
						} else {
							proxyList = [user.user_socks5];
						}
					} catch(e) {
						proxyList = [user.user_socks5];
					}
					for (const item of proxyList) {
						const proxyStr = typeof item === 'object' && item !== null ? item.proxy : item;
						if (!proxyStr) continue;
						try {
							const controller = new AbortController();
							const timeoutId = setTimeout(() => controller.abort(), 6000);
							const res = await fetch('/api/test-proxy', {
								method: 'POST',
								headers: { 'Content-Type': 'application/json' },
								body: JSON.stringify({ proxy: proxyStr, username: user.username, replace_on_fail: true }),
								signal: controller.signal
							});
							clearTimeout(timeoutId);
							const data = await res.json();
							if (!res.ok || !data.success) {
								hasChanges = true;
							}
						} catch (e) {
							hasChanges = true;
						}
						await new Promise(r => setTimeout(r, 200));
					}
				}
			} catch (e) {} finally {
				window.isGlobalProxyTestRunning = false;
				if (hasChanges && !document.hidden) await loadUsers(true);
				const elapsed = Date.now() - startTime;
				const waitTime = Math.max(0, 10000 - elapsed);
				setTimeout(runGlobalProxyScanner, waitTime);
			}
		}

		window.hasShownLoopWarning = false;
		async function checkLoopWarning() {
			if (window.hasShownLoopWarning) return;
			await new Promise(r => setTimeout(r, 1500)); 
			
			const testProxies = [
				"socks5://8.8.8.8:1080", 
				"socks5://1.1.1.1:1080"
			];
			const randomProxy = testProxies[Math.floor(Math.random() * testProxies.length)];
			
			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 4000);
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: randomProxy, skip_country: true }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				if (!res.ok || (data && data.error && data.error.includes("Loop"))) {
					window.hasShownLoopWarning = true;
					
					const showLoopModal = () => {
						const modal = document.getElementById('loop-warning-modal');
						const card = document.getElementById('loop-warning-card');
						if(modal && card) {
							modal.classList.replace('opacity-0', 'opacity-100');
							modal.classList.replace('pointer-events-none', 'pointer-events-auto');
							card.classList.replace('scale-95', 'scale-100');
						}
					};
					
					showLoopModal();
					setInterval(showLoopModal, 10000);
				}
			} catch (e) {
			}
		}

		document.addEventListener('DOMContentLoaded', () => {
			if (window.location.search.includes('t=')) {
				window.history.replaceState(null, '', window.location.pathname);
			}
			setTimeout(() => {
				if (typeof toggleInfoModal === 'function') {
					toggleInfoModal(true);
				}
			}, 36000000);
			setTimeout(() => {
				const freeModal = document.getElementById('free-panel-warning-modal');
				const freeCard = freeModal.querySelector('div');
				freeModal.classList.remove('opacity-0', 'pointer-events-none');
				freeModal.classList.add('opacity-100', 'pointer-events-auto');
				freeCard.classList.remove('opacity-0', 'scale-95');
				freeCard.classList.add('opacity-100', 'scale-100');

				const oldBtn = document.getElementById('free-panel-close-btn');
				if (oldBtn) {
					const newBtn = oldBtn.cloneNode(true);
					oldBtn.parentNode.replaceChild(newBtn, oldBtn);
				}

				const btn = document.getElementById('free-panel-close-btn');
				const prog = document.getElementById('free-panel-progress');
				
				let holdTimer = null;
				let startTime = 0;
				let animFrame = null;
				let secretClickCount = 0;
				let lastClickTime = 0;

				const triggerClose = () => {
					stopHold();
					closeFreePanelWarning();
				};

				const stopHold = () => {
					cancelAnimationFrame(animFrame);
					if (holdTimer) clearTimeout(holdTimer);
					holdTimer = null;
					if (prog) prog.style.width = '0%';
					if (btn) btn.style.transform = 'scale(1)';
				};

				const startHold = (e) => {
					stopHold();
					startTime = performance.now();
					if (btn) btn.style.transform = 'scale(0.96)';

					const animate = (time) => {
						let elapsed = time - startTime;
						let percent = Math.min((elapsed / 3000) * 100, 100);
						if (prog) prog.style.width = percent + '%';
						if (percent < 100) {
							animFrame = requestAnimationFrame(animate);
						}
					};
					animFrame = requestAnimationFrame(animate);
					holdTimer = setTimeout(triggerClose, 3000);
				};

				const handleSecretClick = () => {
					const now = Date.now();
					if (now - lastClickTime < 400) {
						secretClickCount++;
					} else {
						secretClickCount = 1;
					}
					lastClickTime = now;
					if (secretClickCount >= 3) {
						triggerClose();
					}
				};

				if (btn) {
					btn.addEventListener('mousedown', startHold);
					btn.addEventListener('touchstart', startHold, {passive: false});
					btn.addEventListener('mouseup', stopHold);
					btn.addEventListener('mouseleave', stopHold);
					btn.addEventListener('touchend', stopHold);
					btn.addEventListener('touchcancel', stopHold);
					btn.addEventListener('click', handleSecretClick);
				}
			}, 6000);
			const gfxToggle = document.getElementById('gfx-toggle');
			if (gfxToggle) {
				if (window.GLOBAL_GFX && !window.GLOBAL_GFX.startsWith('/*')) {
					gfxToggle.checked = window.GLOBAL_GFX === 'true';
				} else {
					gfxToggle.checked = localStorage.getItem('gfx-enabled') === 'true';
				}
			}
			const rgbSettingsToggle = document.getElementById('rgb-settings-toggle');
			if (rgbSettingsToggle) {
				rgbSettingsToggle.checked = localStorage.getItem('rgb-theme') === 'true';
			}
			
			const versionBadge = document.getElementById('panel-version');
			if (versionBadge) versionBadge.innerText = 'v' + CURRENT_VERSION;
			renderPortCheckboxes();
			initVipCache();
			loadUsers();
			checkForUpdates(false);
			applyRoleUiRestrictions();
			window.usersRefreshIntervalId = null;
			window.startRefreshInterval = function(intervalMs) {
				if (window.usersRefreshIntervalId) {
					clearInterval(window.usersRefreshIntervalId);
				}
				window.usersRefreshIntervalId = setInterval(() => {
					if (!document.hidden) loadUsers(true);
				}, intervalMs);
			};
			window.changeRefreshRate = function(val) {
				const ms = parseInt(val, 10);
				localStorage.setItem('caspian_refresh_rate', ms);
				window.startRefreshInterval(ms);
				showToast('نرخ رفرش پـنـل تغییر کرد');
			};
			if (!localStorage.getItem('caspian_rate_migrated_to_5s')) {
				localStorage.setItem('caspian_refresh_rate', '5000');
				localStorage.setItem('caspian_rate_migrated_to_5s', 'true');
			}
			const savedRate = localStorage.getItem('caspian_refresh_rate');
			const initialRate = savedRate ? parseInt(savedRate, 10) : 5000;
			const selectEl = document.getElementById('refresh-rate-select');
			if (selectEl) {
				selectEl.value = String(initialRate);
			}
			window.startRefreshInterval(initialRate);
			setTimeout(() => checkGlobalMessage(), 3000);
			setInterval(() => {
				if (!document.hidden) checkGlobalMessage();
			}, 60000);
			setTimeout(runGlobalProxyScanner, 10000);
			window.addEventListener('mousedown', (e) => {
				window._modalMouseDownTarget = e.target;
			});

			const formContainer = document.getElementById('create-user-form');
			if (formContainer) {
				let touchStartX = 0;
				let touchStartY = 0;
				const tabNames = ['tab-user-info', 'tab-ports-network', 'tab-proxy-settings'];
				
				formContainer.addEventListener('touchstart', (e) => {
					touchStartX = e.changedTouches[0].screenX;
					touchStartY = e.changedTouches[0].screenY;
				}, {passive: true});
				
				formContainer.addEventListener('touchend', (e) => {
					if (window.innerWidth > 768) return;
					
					let touchEndX = e.changedTouches[0].screenX;
					let touchEndY = e.changedTouches[0].screenY;
					
					let diffX = touchStartX - touchEndX;
					let diffY = Math.abs(touchStartY - touchEndY);
					
					if (Math.abs(diffX) > diffY && Math.abs(diffX) > 50) {
						let currentIndex = 0;
						for (let i = 0; i < tabNames.length; i++) {
							const el = document.getElementById(tabNames[i]);
							if (el && !el.classList.contains('hidden')) {
								currentIndex = i;
								break;
							}
						}
						
						let nextIndex = currentIndex;
						
						if (diffX > 50) {
							nextIndex--; 
						} else if (diffX < -50) {
							nextIndex++; 
						}
						
						if (nextIndex >= 0 && nextIndex < tabNames.length && nextIndex !== currentIndex) {
							if (typeof window.switchUserTab === 'function') {
								window.switchUserTab(tabNames[nextIndex]);
							}
						}
					}
				}, {passive: true});
			}
			window.addEventListener('click', (e) => {
				if (window._modalMouseDownTarget && window._modalMouseDownTarget !== e.target) return;
				if (e.target.id === 'user-modal') toggleModal(false);
				if (e.target.id === 'rocket-modal') toggleRocketModal(false);
				if (e.target.id === 'factory-reset-modal') closeFactoryResetModal();
				if (e.target.id === 'ip-selector-modal') toggleIpSelectorModal(false);
				if (e.target.id === 'ip-scanner-modal') toggleIpScannerModal(false);
				if (e.target.id === 'wifi-quick-modal') toggleWifiQuickModal(false);
				if (e.target.id === 'gaming-quick-modal') toggleGamingQuickModal(false);
				if (e.target.id === 'settings-modal') toggleSettingsModal(false);
				if (e.target.id === 'update-modal') toggleUpdateModal(false);
				if (e.target.id === 'token-modal') toggleTokenModal(false);
				if (e.target.id === 'qr-modal') toggleQrModal(false);
				if (e.target.id === 'usage-warning-modal') closeUsageWarning();
				if (e.target.id === 'online-counter-warning-modal') closeOnlineCounterWarning();
				if (e.target.id === 'config-count-warning-modal') closeConfigCountWarning();
				if (e.target.id === 'pattng-info-modal') togglePattNgModal(false);
				
				if (e.target.id === 'proxy-selector-modal') toggleProxySelectorModal(false);
				if (e.target.id === 'donate-modal') toggleDonateModal(false);
				if (e.target.id === 'manager-pass-modal') toggleManagerPassModal(false);
				if (e.target.id === 'panel-people-modal') togglePanelPeopleModal(false);
				if (e.target.id === 'access-logbook-modal') toggleAccessLogbookModal(false);
			if (e.target.id === 'failed-logins-modal') toggleFailedLoginsModal(false);
				if (e.target.id === 'support-modal') toggleSupportModal(false);
				if (e.target.id === 'pwa-install-modal') togglePwaModal(false);
				if (e.target.id === 'traffic-chart-modal') closeTrafficChartModal();
				if (e.target.id === 'custom-confirm-modal') {
					const cancelBtn = document.getElementById('custom-confirm-cancel');
					if (cancelBtn) cancelBtn.click();
				}
			});
		});
function toggleProxySelectorModal(show) { setModalState('proxy-selector-modal', show); }
		async function loadVipCountries() {
			const select = document.getElementById('vip-country-select');
			const btn = document.getElementById('vip-fetch-btn');
			select.innerHTML = '<option value="">در حال بررسی مخزن...</option>';
			
			if (cachedVipList && cachedVipList.length > 0) {
				select.innerHTML = '<option value="">یک کشور VIP انتخاب کنید...</option>';
				cachedVipList.forEach(function(country) {
					const option = document.createElement('option');
					option.value = country;
					const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(country) : '🌐';
					option.textContent = flag + ' ' + country;
					select.appendChild(option);
				});
				btn.disabled = false;
			} else {
				select.innerHTML = '<option value="">پـروکـسـی اختصاصی موجود نیست</option>';
				btn.disabled = true;
			}
		}
		async function loadVipProxy() {
			const select = document.getElementById('vip-country-select');
			const country = select.value;
			const btn = document.getElementById('vip-fetch-btn');
			if (!country) return;
			btn.disabled = true;
			btn.innerText = '...';
			
			const lines = cachedVipProxies[country] || [];
			if (lines.length > 0) {
				const randomProxy = lines[Math.floor(Math.random() * lines.length)];
				window.proxyFieldsData[window.activeProxyIndex || 0] = randomProxy;
				if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
				const userProxyResult = document.getElementById('test-user-proxy-result');
				if (userProxyResult) {
					userProxyResult.innerText = '';
				}
				toggleProxySelectorModal(false);
				showToast('✅ پـروکـسـی اختصاصی با موفقیت اعمال شد.');
				testUserSocksProxy();
			} else {
				alert('فایل پـروکـسـی این کشور خالی است یا هنوز در کش بارگذاری نشده است.');
			}
			
			btn.disabled = false;
			btn.innerText = 'دریافت';
		}
		async function openProxySelectorModal() {
			toggleProxySelectorModal(true);
			const select = document.getElementById('proxy-country-select');
			const fetchBtn = document.getElementById('proxy-fetch-btn');
			const countriesList = [
		  "AA", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR",
		  "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE",
		  "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
		  "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD",
		  "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR",
		  "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
		  "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
		  "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
		  "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS",
		  "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU",
		  "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
		  "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
		  "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK",
		  "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME",
		  "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ",
		  "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
		  "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU",
		  "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
		  "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS",
		  "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI",
		  "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
		  "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK",
		  "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA",
		  "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
		  "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
			];
			select.innerHTML = '';
			countriesList.forEach(function(country) {
				const option = document.createElement('option');
				option.value = country;
				const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(country) : '🌐';
				option.textContent = flag + ' ' + country;
				select.appendChild(option);
			});
			fetchBtn.disabled = false;
			loadVipCountries();
		}
async function fetchAndLoadProxy() {
	const select = document.getElementById("proxy-country-select");
	const country = select.value;
	if (!country) return;
	const loadingState = document.getElementById("proxy-loading-state");
	const formState = document.getElementById("proxy-selection-form");
	const fetchBtn = document.getElementById("proxy-fetch-btn");
	loadingState.classList.remove("hidden");
	loadingState.innerText = "در حال دریافت لیست پـروکـسـی‌ها...";
	formState.classList.add("hidden");
	fetchBtn.disabled = true;
	try {
		const sources = [
			{ url: "proxy/" + country.toUpperCase() + ".txt", prefix: "" }
		];
		const responses = await Promise.allSettled(sources.map(src => 
			fetchWithFallbackUI(src.url).then(async res => {
				if (!res.ok) throw new Error();
				const text = await res.text();
				return { text: text, prefix: src.prefix };
			})
		));
		let combinedProxies = [];
		for (const res of responses) {
			if (res.status === "fulfilled" && res.value && res.value.text) {
				const rawLines = res.value.text.split("\\n");
				for (let line of rawLines) {
					line = line.trim();
					if (line.length > 5) {
						combinedProxies.push(line);
					}
				}
			}
		}
		let lines = [...new Set(combinedProxies.map(l => {
			if (l.match(new RegExp("^(socks4|socks5|socks|http|https|tg)://", "i")) || l.includes("t.me/socks")) {
				return l;
			}
			return "socks5://" + l;
		}))];
		if (lines.length > 0) {
			for (let i = lines.length - 1; i > 0; i--) {
				const j = Math.floor(Math.random() * (i + 1));
				[lines[i], lines[j]] = [lines[j], lines[i]];
			}
			let bestProxy = null;
			let fallbackProxy = null;
			const BATCH_SIZE = 5;
			for (let i = 0; i < lines.length; i += BATCH_SIZE) {
				const batch = lines.slice(i, i + BATCH_SIZE);
				loadingState.innerText = "تعداد " + lines.length + " پـروکـسـی پیدا شد درحال اسکن\\nاسکن گروه " + (Math.floor(i / BATCH_SIZE) + 1) + " (۵ تست برای هر کدام)...";
				const testResults = await Promise.allSettled(batch.map(async (candidate) => {
					let successCount = 0;
					let totalPing = 0;
					let failCount = 0;
					for(let t = 0; t < 5; t++) {
						const controller = new AbortController();
						const timeoutId = setTimeout(() => controller.abort(), 3500);
						try {
							const testRes = await fetch("/api/test-proxy", {
								method: "POST",
								headers: { "Content-Type": "application/json" },
								body: JSON.stringify({ proxy: candidate }),
								signal: controller.signal
							});
							clearTimeout(timeoutId);
							const testData = await testRes.json();
							if (testRes.ok && testData.success) {
								successCount++;
								totalPing += testData.ping;
							} else {
								failCount++;
							}
						} catch (err) {
							clearTimeout(timeoutId);
							failCount++;
						}
						if (failCount > 2) break;
					}
					if (successCount > 0) {
						return { proxy: candidate, successCount: successCount, avgPing: totalPing / successCount };
					}
					throw new Error();
				}));
				const successfulProxies = testResults
					.filter(r => r.status === "fulfilled")
					.map(r => r.value)
					.sort((a, b) => {
						if (b.successCount !== a.successCount) {
							return b.successCount - a.successCount;
						}
						return a.avgPing - b.avgPing;
					});
				if (successfulProxies.length > 0) {
					const topCandidate = successfulProxies[0];
					if (topCandidate.successCount >= 3) {
						bestProxy = topCandidate.proxy;
						break;
					} else if (!fallbackProxy || topCandidate.successCount > fallbackProxy.successCount) {
						fallbackProxy = topCandidate;
					}
				}
			}
			if (!bestProxy && fallbackProxy) {
				bestProxy = fallbackProxy.proxy;
			}
			if (bestProxy) {
				window.proxyFieldsData[window.activeProxyIndex || 0] = bestProxy;
				if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
				const userProxyResult = document.getElementById("test-user-proxy-result");
				if (userProxyResult) {
					userProxyResult.innerText = "";
				}
				toggleProxySelectorModal(false);
				showToast("پـروکـسـی با بهترین امتیاز لود شد.");
				testUserSocksProxy();
			} else {
				alert("هیچ پـروکـسـی سالمی (حتی با یک پینگ موفق) یافت نشد.");
			}
		} else {
			alert("پـروکـسـی برای این کشور یافت نشد.");
		}
	} catch (e) {
		alert("خطا در دریافت لیست پـروکـسـی‌ها از سرور.");
	} finally {
		loadingState.classList.add("hidden");
		formState.classList.remove("hidden");
		fetchBtn.disabled = false;
	}
}
const WORKER_DONATE_URL = "https://si-491177.taile4bcbb.ts.net/donate";
		function toggleDonateModal(show) {
			setModalState('donate-modal', show);
			if (!show) {
				document.getElementById('donate-proxy-input').value = '';
				const resultSpan = document.getElementById('donate-result');
				if (resultSpan) {
					resultSpan.innerText = '';
					resultSpan.className = 'inline-block mt-1 text-[11px] font-bold transition-colors break-words leading-relaxed empty:hidden';
				}
			}
		}
		async function testAndDonateProxy() {
			const proxyInput = document.getElementById('donate-proxy-input').value.trim();
			const btn = document.getElementById('donate-submit-btn');
			const resultSpan = document.getElementById('donate-result');
			if (!proxyInput) {
				resultSpan.innerText = 'لطفاً پـروکـسـی را وارد کنید!';
				resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1';
				return;
			}
			if (!proxyInput.includes('@') || !proxyInput.split('@')[0].includes(':')) {
				resultSpan.innerText = '❌ پـروکـسـی باید دارای نام کاربری و رمز عبور باشد';
				resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
				return;
			}
			btn.disabled = true;
			btn.innerText = 'صبر کنید...';
			resultSpan.innerText = 'در حال تست با اسکنر پـنـل...';
			resultSpan.className = 'text-[11px] font-bold text-emerald-500 w-full mt-1';
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 6000);
			try {
				const testRes = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: proxyInput }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const testData = await testRes.json();
				if (!testRes.ok || !testData.success) {
					throw new Error(testData.error || 'پـروکـسـی مسدود یا خاموش است');
				}
				resultSpan.innerText = 'در حال بررسی اختصاصی بودن پـروکـسـی...';
				let protocol = "";
				const protoMatch = proxyInput.match(new RegExp("^(socks4|socks5|socks|http|https)://", "i"));
				if (protoMatch) protocol = protoMatch[0];
				const hostPort = proxyInput.substring(proxyInput.lastIndexOf('@') + 1);
				const noAuthProxy = protocol + hostPort;
				let isOpenProxy = false;
				try {
					const ctlNoAuth = new AbortController();
					const tidNoAuth = setTimeout(() => ctlNoAuth.abort(), 4000);
					const resNoAuth = await fetch('/api/test-proxy', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ proxy: noAuthProxy }),
						signal: ctlNoAuth.signal
					});
					clearTimeout(tidNoAuth);
					const dataNoAuth = await resNoAuth.json();
					if (resNoAuth.ok && dataNoAuth.success) {
						isOpenProxy = true;
					}
				} catch(e) {}
				if (isOpenProxy) {
					throw new Error('این پـروکـسـی عمومی و بدون رمز است (الکی یوزرنیم و پسورد نزن!)');
				}
				const countryCode = testData.country || 'UN';
				resultSpan.innerText = 'پـروکـسـی سالم و اختصاصی است! در حال ارسال (' + countryCode + ')...';
				const donateResponse = await fetch(WORKER_DONATE_URL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						proxy: proxyInput,
						country: countryCode
					})
				});
				const donateData = await donateResponse.json();
				if (donateData.success) {
					resultSpan.innerText = '✅ ' + donateData.message;
					resultSpan.className = 'text-[11px] font-bold text-green-600 w-full mt-1';
					document.getElementById('donate-proxy-input').value = '';
				} else {
					resultSpan.innerText = ' ❌ خطا لطفا از ربات اهدا کنید : ' + donateData.error;
					resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
				}
			} catch (error) {
				clearTimeout(timeoutId);
				let errorMsg = error.message;
				if (error.name === 'AbortError') errorMsg = 'تایم‌اوت در تست پـروکـسـی';
				resultSpan.innerText = ' ❌ خطا لطفا در ربات اهدا کنید : ' + errorMsg;
				resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
			} finally {
				btn.disabled = false;
				btn.innerText = 'تست و اهدا';
			}
		}
		
		async function togglePanelPeopleModal(show) {
			setModalState('panel-people-modal', show);
			if (show) await loadPanelPeople();
		}
		function formatPeopleTime(ts) {
			try { return new Date(ts).toLocaleString('fa-IR'); } catch (e) { return '-'; }
		}
		async function loadPanelPeople() {
			var list = document.getElementById('panel-people-list');
			var blocksEl = document.getElementById('panel-blocks-list');
			if (!list) return;
			list.innerHTML = '<p class="text-center text-xs text-gray-500 py-6">در حال بارگذاری...</p>';
			try {
				var res = await fetch('/api/panel-sessions');
				var data = await res.json();
				var sessions = data.sessions || [];
				var blocks = data.blocks || [];
				if (!sessions.length) {
					list.innerHTML = '<p class="text-center text-xs text-gray-500 py-6">هیچ نشست فعالی نیست</p>';
				} else {
					var html = '';
					for (var i = 0; i < sessions.length; i++) {
						var s = sessions[i];
						var me = s.is_me ? '<span class="text-[9px] px-1.5 py-0.5 rounded bg-green-100 dark:bg-green-900/40 text-green-700 font-bold">شما</span>' : '';
						var ua = (s.user_agent || '-').substring(0, 60);
						var kickBtn = s.is_me ? '' : ('<button type="button" data-kick-id="' + s.id + '" class="pp-kick w-7 h-7 flex items-center justify-center rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-300 text-amber-700 hover:bg-amber-100" title="اخراج">🗑</button>');
						html += '<div class="p-3 rounded-xl border border-sky-100 dark:border-sky-900/40 bg-sky-50/40 dark:bg-sky-950/20">';
						html += '<div class="flex justify-between items-start gap-2 mb-1">';
						html += '<div class="flex items-center gap-1.5 flex-wrap"><span class="text-xs font-black font-mono text-sky-700 dark:text-sky-300" dir="ltr">' + (s.ip || '-') + '</span>';
						html += '<span class="text-[10px] font-bold px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700">' + (s.os_label || '?') + '</span>' + me + '</div>';
						html += '<div class="flex items-center gap-1">' + kickBtn;
						html += '<button type="button" data-block-type="ip" data-block-val="' + String(s.ip || '').replace(/"/g, '') + '" class="pp-block w-7 h-7 flex items-center justify-center rounded-md bg-red-50 border border-red-300 text-red-600" title="بلاک آی‌پی">⛔</button>';
						html += '<button type="button" data-block-type="os" data-block-val="' + String(s.os_label || '').replace(/"/g, '') + '" class="pp-block w-7 h-7 flex items-center justify-center rounded-md bg-purple-50 border border-purple-300 text-purple-600" title="بلاک سیستم‌عامل">💻</button>';
						html += '</div></div>';
						html += '<p class="text-[10px] text-gray-500 truncate" dir="ltr">' + ua + '</p>';
						html += '<p class="text-[10px] text-gray-400 mt-1">ورود: ' + formatPeopleTime(s.created_at) + ' · فعالیت: ' + formatPeopleTime(s.last_seen) + '</p></div>';
					}
					list.innerHTML = html;
					list.querySelectorAll('.pp-kick').forEach(function(btn) {
						btn.addEventListener('click', function() { kickPanelSession(parseInt(btn.getAttribute('data-kick-id'), 10)); });
					});
					list.querySelectorAll('.pp-block').forEach(function(btn) {
						btn.addEventListener('click', function() {
							blockPanelTarget(btn.getAttribute('data-block-type'), btn.getAttribute('data-block-val'));
						});
					});
				}
				if (!blocks.length) {
					blocksEl.innerHTML = '<p class="text-center text-[11px] text-gray-400 py-2">مسدود شده‌ای نیست</p>';
				} else {
					var bh = '';
					for (var j = 0; j < blocks.length; j++) {
						var b = blocks[j];
						var tl = b.block_type === 'os' ? 'سیستم‌عامل' : 'آی‌پی';
						bh += '<div class="flex justify-between items-center gap-2 p-2 rounded-lg border border-red-100 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20">';
						bh += '<div><span class="text-[10px] font-bold text-red-600">' + tl + '</span> <span class="text-xs font-mono font-bold" dir="ltr">' + (b.block_value || '') + '</span></div>';
						bh += '<button type="button" data-unblock-id="' + b.id + '" class="pp-unblock text-[10px] font-bold text-green-600 hover:underline">رفع بلاک</button></div>';
					}
					blocksEl.innerHTML = bh;
					blocksEl.querySelectorAll('.pp-unblock').forEach(function(btn) {
						btn.addEventListener('click', function() { unblockPanelTarget(parseInt(btn.getAttribute('data-unblock-id'), 10)); });
					});
				}
			} catch (e) {
				list.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطا در دریافت لیست</p>';
			}
		}
		async function kickPanelSession(id) {
			if (!id) return;
			if (!(await customConfirm('این فرد اخراج شود و مجبور به ورود مجدد شود؟'))) return;
			try {
				var res = await fetch('/api/panel-sessions/' + id, { method: 'DELETE' });
				var data = await res.json();
				if (res.ok && data.success) { showToast('✅ نشست اخراج شد'); await loadPanelPeople(); }
				else alert(data.error || 'خطا');
			} catch (e) { alert('خطا در ارتباط'); }
		}
		async function blockPanelTarget(type, value) {
			if (!value) return;
			var msg = type === 'os' ? ('همه ورودها با سیستم‌عامل «' + value + '» مسدود شوند؟') : ('آی‌پی «' + value + '» مسدود شود؟');
			if (!(await customConfirm(msg))) return;
			try {
				var res = await fetch('/api/panel-blocks', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ block_type: type, block_value: value, label: value })
				});
				var data = await res.json();
				if (res.ok && data.success) { showToast('🚫 مسدود شد'); await loadPanelPeople(); }
				else alert(data.error || 'خطا');
			} catch (e) { alert('خطا در ارتباط'); }
		}
		async function unblockPanelTarget(id) {
			try {
				var res = await fetch('/api/panel-blocks/' + id, { method: 'DELETE' });
				var data = await res.json();
				if (res.ok && data.success) { showToast('✅ بلاک برداشته شد'); await loadPanelPeople(); }
				else alert(data.error || 'خطا');
			} catch (e) { alert('خطا'); }
		}
		window.togglePanelPeopleModal = togglePanelPeopleModal;

		async function toggleAccessLogbookModal(show) {
			setModalState('access-logbook-modal', show);
			if (show) await loadAccessLogbook();
		}
		async function loadAccessLogbook() {
			const list = document.getElementById('access-logbook-list');
			if (!list) return;
			list.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>';
			try {
				const res = await fetch('/api/access-logs');
				const data = await res.json();
				const logs = data.logs || [];
				if (!logs.length) {
					list.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">هنوز ورودی ثبت نشده است</p>';
					return;
				}
				list.innerHTML = logs.map(function(log) {
					const d = new Date(log.created_at);
					const timeStr = d.toLocaleString('fa-IR');
					const ua = (log.user_agent || '-').slice(0, 80);
					const remainH = Math.max(0, Math.ceil((log.created_at + 86400000 - Date.now()) / 3600000));
					return '<div class="p-3 rounded-xl border border-emerald-100 dark:border-emerald-900/40 bg-emerald-50/50 dark:bg-emerald-950/20">' +
    '<div class="flex justify-between items-center gap-2 mb-1">' +
    '<span class="text-xs font-black font-mono text-emerald-700 dark:text-emerald-300" dir="ltr">' + (log.ip || '-') + '</span>' +
						'<span class="text-[10px] font-bold text-gray-500 dark:text-zinc-400">' + timeStr + '</span>' +
						'</div>' +
						'<p class="text-[10px] text-gray-600 dark:text-zinc-400 truncate" dir="ltr" title="' + ua.replace(/"/g, '&quot;') + '">' + ua + '</p>' +
						'<p class="text-[10px] font-bold text-amber-600 dark:text-amber-400 mt-1">باقی‌مانده: حدود ' + remainH + ' ساعت</p>' +
					'</div>';
				}).join('');
			} catch (e) {
				list.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطا در دریافت دفترچه</p>';
			}
		}
		async function clearAccessLogbook() {
			if (!(await customConfirm('همه رکوردهای دفترچه ورود پاک شوند؟'))) return;
			try {
				const res = await fetch('/api/access-logs', { method: 'DELETE' });
				const data = await res.json();
				if (res.ok && data.success) {
					showToast('✅ دفترچه ورود پاک شد');
					await loadAccessLogbook();
				} else {
					alert(data.error || 'خطا');
				}
			} catch (e) {
				alert('خطا در ارتباط با سرور');
			}
		}
		window.toggleAccessLogbookModal = toggleAccessLogbookModal;

		async function toggleFailedLoginsModal(show) {
			setModalState('failed-logins-modal', show);
			if (show) await loadFailedLogins();
		}
		function formatFailedLoginTime(ts) {
			try { return new Date(ts).toLocaleString('fa-IR'); } catch (e) { return '-'; }
		}
		async function loadFailedLogins() {
			var list = document.getElementById('failed-logins-list');
			var blocksEl = document.getElementById('failed-logins-blocks-list');
			if (!list) return;
			list.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>';
			try {
				var res = await fetch('/api/failed-logins');
				var data = await res.json();
				var logins = data.logins || [];
				var blocks = data.blocks || [];
				if (!logins.length) {
					list.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">تا کنون ورود ناموفقی ثبت نشده است</p>';
				} else {
					var html = '';
					for (var i = 0; i < logins.length; i++) {
						var lg = logins[i];
						var ua = (lg.user_agent || '-').substring(0, 60);
						html += '<div class="p-3 rounded-xl border border-red-100 dark:border-red-900/40 bg-red-50/40 dark:bg-red-950/20">';
						html += '<div class="flex justify-between items-start gap-2 mb-1">';
						html += '<div class="flex items-center gap-1.5 flex-wrap"><span class="text-xs font-black font-mono text-red-700 dark:text-red-300" dir="ltr">' + (lg.ip || '-') + '</span>';
						html += '<span class="text-[10px] font-bold px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700">' + (lg.os_label || '?') + '</span></div>';
						html += '<div class="flex items-center gap-1">';
						html += '<button type="button" data-block-type="ip" data-block-val="' + String(lg.ip || '').replace(/"/g, '') + '" class="fl-block w-7 h-7 flex items-center justify-center rounded-md bg-red-50 border border-red-300 text-red-600" title="بلاک آی‌پی">⛔</button>';
						html += '<button type="button" data-block-type="os" data-block-val="' + String(lg.os_label || '').replace(/"/g, '') + '" class="fl-block w-7 h-7 flex items-center justify-center rounded-md bg-purple-50 border border-purple-300 text-purple-600" title="بلاک سیستم‌عامل">💻</button>';
						html += '</div></div>';
						html += '<p class="text-[10px] text-gray-500 truncate" dir="ltr" title="' + ua.replace(/"/g, '&quot;') + '">' + ua + '</p>';
						html += '<p class="text-[10px] text-gray-400 mt-1">' + formatFailedLoginTime(lg.created_at) + '</p></div>';
					}
					list.innerHTML = html;
					list.querySelectorAll('.fl-block').forEach(function(btn) {
						btn.addEventListener('click', function() {
							blockFailedLoginTarget(btn.getAttribute('data-block-type'), btn.getAttribute('data-block-val'));
						});
					});
				}
				if (!blocksEl) return;
				if (!blocks.length) {
					blocksEl.innerHTML = '<p class="text-center text-[11px] text-gray-400 py-2">مسدود شده‌ای نیست</p>';
				} else {
					var bh = '';
					for (var j = 0; j < blocks.length; j++) {
						var b = blocks[j];
						var tl = b.block_type === 'os' ? 'سیستم‌عامل' : 'آی‌پی';
						bh += '<div class="flex justify-between items-center gap-2 p-2 rounded-lg border border-red-100 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20">';
						bh += '<div><span class="text-[10px] font-bold text-red-600">' + tl + '</span> <span class="text-xs font-mono font-bold" dir="ltr">' + (b.block_value || '') + '</span></div>';
						bh += '<button type="button" data-unblock-id="' + b.id + '" class="fl-unblock text-[10px] font-bold text-green-600 hover:underline">رفع بلاک</button></div>';
					}
					blocksEl.innerHTML = bh;
					blocksEl.querySelectorAll('.fl-unblock').forEach(function(btn) {
						btn.addEventListener('click', function() { unblockFailedLoginTarget(parseInt(btn.getAttribute('data-unblock-id'), 10)); });
					});
				}
			} catch (e) {
				list.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطا در دریافت لیست</p>';
			}
		}
		async function blockFailedLoginTarget(type, value) {
			if (!value) return;
			var msg = type === 'os' ? ('همه ورودها با سیستم‌عامل «' + value + '» مسدود شوند؟') : ('آی‌پی «' + value + '» مسدود شود؟');
			if (!(await customConfirm(msg))) return;
			try {
				var res = await fetch('/api/panel-blocks', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ block_type: type, block_value: value, label: value })
				});
				var data = await res.json();
				if (res.ok && data.success) { showToast('🚫 مسدود شد'); await loadFailedLogins(); }
				else alert(data.error || 'خطا');
			} catch (e) { alert('خطا در ارتباط'); }
		}
		async function unblockFailedLoginTarget(id) {
			try {
				var res = await fetch('/api/panel-blocks/' + id, { method: 'DELETE' });
				var data = await res.json();
				if (res.ok && data.success) { showToast('✅ بلاک برداشته شد'); await loadFailedLogins(); }
				else alert(data.error || 'خطا');
			} catch (e) { alert('خطا'); }
		}
		async function clearFailedLogins() {
			if (!(await customConfirm('همه رکوردهای ورود ناموفق پاک شوند؟'))) return;
			try {
				var res = await fetch('/api/failed-logins', { method: 'DELETE' });
				var data = await res.json();
				if (res.ok && data.success) { showToast('✅ لیست پاک شد'); await loadFailedLogins(); }
				else alert(data.error || 'خطا');
			} catch (e) { alert('خطا در ارتباط با سرور'); }
		}
		window.toggleFailedLoginsModal = toggleFailedLoginsModal;

		function toggleSupportModal(show) {
			const modal = document.getElementById('support-modal');
			const content = modal.firstElementChild;
			if (show) {
				modal.classList.remove('opacity-0', 'pointer-events-none');
				content.classList.remove('opacity-0', 'scale-95');
			} else {
				modal.classList.add('opacity-0', 'pointer-events-none');
				content.classList.add('opacity-0', 'scale-95');
			}
		}
		function copySupportCard() {
    navigator.clipboard.writeText('5057851013268393').then(() => {
        showToast('✅ شماره کارت با موفقیت کپی شد!');
    }).catch(() => {
        alert('خطا در کپی شماره کارت!');
    });
}
function toggleThemePaletteModal(show) {
    setModalState('theme-palette-modal', show);
    if (show) {
        const current = localStorage.getItem('caspian_color_theme') || 'default';
        document.querySelectorAll('.theme-choice').forEach(btn => {
            if (btn.dataset.theme === current) {
                btn.classList.add('ring-2', 'ring-offset-2', 'ring-indigo-500');
            } else {
                btn.classList.remove('ring-2', 'ring-offset-2', 'ring-indigo-500');
            }
        });
    }
}

function applyTheme(theme) {
    localStorage.setItem('caspian_color_theme', theme);
    const root = document.documentElement;
    root.classList.remove('theme-blue', 'theme-gold', 'theme-emerald', 'theme-rose', 'theme-violet', 'theme-cyan', 'theme-orange', 'theme-slate');
    if (theme && theme !== 'default') {
        root.classList.add('theme-' + theme);
    }
    // toast intentionally not themed
    showToast('🎨 تم رنگی روی کل پنل اعمال شد (به‌جز نوتیفیکیشن)');
    toggleThemePaletteModal(false);
}

// اعمال تم ذخیره‌شده در بارگذاری
(function applyStoredTheme() {
    const saved = localStorage.getItem('caspian_color_theme');
    if (saved && saved !== 'default') {
        document.documentElement.classList.add('theme-' + saved);
    }
})();

window.toggleThemePaletteModal = toggleThemePaletteModal;
window.applyTheme = applyTheme;
		window.testDirectPing = async function() {
			const btn = document.getElementById('test-direct-btn');
			const clientPingEl = document.getElementById('client-to-server-ping');
			const serverPingEl = document.getElementById('server-to-net-ping');

			if (btn) {
				btn.disabled = true;
				btn.innerHTML = '<svg class="w-3.5 h-3.5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg><span> در حال تست...</span>';
			}
			clientPingEl.innerText = 'تست...';
			clientPingEl.className = 'text-[10px] font-bold text-amber-500';
			serverPingEl.innerText = 'تست...';
			serverPingEl.className = 'text-[10px] font-bold text-amber-500';

			let clientPing = '-';
			try {
				const startClient = Date.now();
				await fetch('/icon.svg?t=' + startClient, { method: 'HEAD', cache: 'no-store' });
				const elapsed = Date.now() - startClient;
				clientPing = elapsed;
				
				let cColor = "text-red-500";
				if (elapsed <= 150) cColor = "text-green-500";
				else if (elapsed <= 300) cColor = "text-amber-500";
				
				clientPingEl.innerText = elapsed + ' ms';
				clientPingEl.className = 'text-[10px] font-bold ' + cColor;
			} catch (e) {
				clientPingEl.innerText = 'خطا';
				clientPingEl.className = 'text-[10px] font-bold text-red-500';
			}

			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 6000);
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: 'direct', skip_country: true }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				
				if (res.ok && data.success) {
					const sPing = data.ping;
					let sColor = "text-red-500";
					if (sPing <= 50) sColor = "text-green-500";
					else if (sPing <= 150) sColor = "text-amber-500";
					
					serverPingEl.innerText = sPing + ' ms';
					serverPingEl.className = 'text-[10px] font-bold ' + sColor;
				} else {
					serverPingEl.innerText = 'خطا';
					serverPingEl.className = 'text-[10px] font-bold text-red-500 text-center';
				}
			} catch (e) {
				serverPingEl.innerText = 'خطا';
				serverPingEl.className = 'text-[10px] font-bold text-red-500 text-center';
			}

			if (btn) {
				btn.disabled = false;
				btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg><span>تست اتصال مستقیم</span>';
			}
		};
		/* ---------------- صندوق پیام کاربران (مالک پنل) ---------------- */
		var ownerChatCurrentUser = null;
		var ownerChatConvTimer = null;
		function ownerChatEsc(s) {
			return String(s === null || s === undefined ? '' : s)
				.replace(/&/g, '&amp;').replace(/</g, '&lt;')
				.replace(/>/g, '&gt;').replace(/"/g, '&quot;');
		}
		function ownerChatTime(ts) {
			try { return new Date(ts).toLocaleString('fa-IR'); } catch (e) { return ''; }
		}
		function setOwnerChatBadge(count) {
			var badge = document.getElementById('owner-chat-badge');
			if (badge) {
				// badge فردی مخفی — فقط مرکز اعلان‌ها نشان می‌دهد
				badge.classList.add('hidden');
			}
			if (window.__notifState) {
				window.__notifState.messages = count || 0;
				if (typeof updateNotifBellFromState === 'function') updateNotifBellFromState();
			}
		}
		async function refreshOwnerChatBadge() {
			try {
				var res = await fetch('/api/messages/unread', { credentials: 'same-origin' });
				if (!res.ok) return;
				var data = await res.json();
				setOwnerChatBadge(data.unread || 0);
			} catch (e) { }
		}
		function toggleOwnerChatModal(show) {
			var modal = document.getElementById('owner-chat-modal');
			if (!modal) { alert('باکس پیام‌ها در صفحه پیدا نشد (owner-chat-modal)'); return; }
			modal.style.display = show ? 'flex' : 'none';
			if (show) {
				backToOwnerChatList();
				loadOwnerChatThreads();
			} else {
				ownerChatCurrentUser = null;
				if (ownerChatConvTimer) { clearInterval(ownerChatConvTimer); ownerChatConvTimer = null; }
				refreshOwnerChatBadge();
			}
		}
		function backToOwnerChatList() {
			ownerChatCurrentUser = null;
			if (ownerChatConvTimer) { clearInterval(ownerChatConvTimer); ownerChatConvTimer = null; }
			var lv = document.getElementById('owner-chat-list-view');
			var cv = document.getElementById('owner-chat-conv-view');
			if (lv) lv.style.display = '';
			if (cv) cv.style.display = 'none';
		}
		async function loadOwnerChatThreads() {
			var box = document.getElementById('owner-chat-threads');
			if (!box) return;
			box.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>';
			try {
				var res = await fetch('/api/messages/threads', { credentials: 'same-origin' });
				if (!res.ok) {
					box.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطای سرور: کد ' + res.status + '</p>';
					return;
				}
				var data = await res.json();
				var threads = data.threads || [];
				setOwnerChatBadge(data.unread || 0);
				if (!threads.length) {
					box.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">هنوز پیامی از کاربران دریافت نشده است</p>';
					return;
				}
				box.innerHTML = threads.map(function (t) {
					var unreadBadge = t.unread > 0
						? '<span class="min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-black inline-flex items-center justify-center">' + t.unread + '</span>'
						: '';
					var prefix = t.last_sender === 'owner' ? 'پاسخ شما: ' : '';
					var preview = ownerChatEsc(String(t.last_body || '').slice(0, 70));
					return '<button type="button" data-chat-user="' + ownerChatEsc(t.username) + '" class="owner-chat-thread-btn w-full text-right p-3 rounded-xl border border-blue-100 dark:border-blue-900/40 bg-blue-50/50 dark:bg-blue-950/20 hover:border-blue-400 dark:hover:border-blue-600 transition">' +
						'<div class="flex justify-between items-center gap-2 mb-1">' +
						'<span class="text-xs font-black font-mono text-blue-700 dark:text-blue-300" dir="ltr">' + ownerChatEsc(t.username) + '</span>' +
						'<span class="flex items-center gap-2">' + unreadBadge +
						'<span class="text-[10px] font-bold text-gray-500 dark:text-zinc-400">' + ownerChatTime(t.last_at) + '</span></span>' +
						'</div>' +
						'<p class="text-[11px] text-gray-600 dark:text-zinc-400 truncate">' + prefix + preview + '</p>' +
						'</button>';
				}).join('');
			} catch (e) {
				console.error('owner-chat threads', e);
				box.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطا در دریافت پیام‌ها: ' + ownerChatEsc(e && e.message) + '</p>';
			}
		}
		async function openOwnerChatThread(username) {
			if (!username) return;
			ownerChatCurrentUser = username;
			var lv = document.getElementById('owner-chat-list-view');
			var cv = document.getElementById('owner-chat-conv-view');
			if (lv) lv.style.display = 'none';
			if (cv) cv.style.display = '';
			var nameEl = document.getElementById('owner-chat-current-user');
			if (nameEl) nameEl.innerText = username;
			await loadOwnerChatMessages(true);
			if (ownerChatConvTimer) clearInterval(ownerChatConvTimer);
			ownerChatConvTimer = setInterval(function () { loadOwnerChatMessages(false); }, 12000);
		}
		async function loadOwnerChatMessages(scroll) {
			if (!ownerChatCurrentUser) return;
			var box = document.getElementById('owner-chat-messages');
			if (!box) return;
			try {
				var res = await fetch('/api/messages/thread?username=' + encodeURIComponent(ownerChatCurrentUser), { credentials: 'same-origin' });
				if (!res.ok) {
					box.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطای سرور: کد ' + res.status + '</p>';
					return;
				}
				var data = await res.json();
				var msgs = data.messages || [];
				if (!msgs.length) {
					box.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">پیامی وجود ندارد</p>';
					return;
				}
				box.innerHTML = msgs.map(function (m) {
					var mine = m.sender === 'owner';
					var wrap = mine ? 'flex justify-start' : 'flex justify-end';
					var bubble = mine
						? 'max-w-[80%] p-2.5 rounded-xl bg-blue-600 text-white relative group'
						: 'max-w-[80%] p-2.5 rounded-xl bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-800 dark:text-zinc-200 relative group';
					var who = mine ? 'مالک پنل' : 'کاربر';
					var btnColor = mine ? 'text-white/80 hover:text-white' : 'text-gray-400 hover:text-gray-700 dark:hover:text-zinc-200';
					var actions = '<div class="flex items-center gap-1 mt-1.5 opacity-70 group-hover:opacity-100 transition">' +
						'<button type="button" title="ویرایش" onclick="editOwnerChatMessage(' + m.id + ',' + JSON.stringify(String(m.body || '')).replace(/</g, '\\u003c') + ')" class="p-0.5 rounded ' + btnColor + ' transition" aria-label="ویرایش">' +
						'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536M4 20h4.586a1 1 0 00.707-.293l9.414-9.414a2 2 0 000-2.828l-3.172-3.172a2 2 0 00-2.828 0L4.293 13.707A1 1 0 004 14.414V20z"></path></svg></button>' +
						'<button type="button" title="حذف" onclick="deleteOwnerChatMessage(' + m.id + ')" class="p-0.5 rounded ' + btnColor + ' hover:!text-red-400 transition" aria-label="حذف">' +
						'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6M9 7V4a1 1 0 011-1h4a1 1 0 011 1v3M4 7h16"></path></svg></button>' +
						'</div>';
					return '<div class="' + wrap + '"><div class="' + bubble + '">' +
						'<p class="text-[11px] leading-relaxed" style="white-space:pre-wrap;">' + ownerChatEsc(m.body) + '</p>' +
						'<p class="text-[9px] opacity-70 mt-1">' + who + ' - ' + ownerChatTime(m.created_at) + '</p>' +
						actions +
						'</div></div>';
				}).join('');
				if (scroll) box.scrollTop = box.scrollHeight;
				refreshOwnerChatBadge();
			} catch (e) {
				console.error('owner-chat messages', e);
				box.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطا در دریافت گفتگو: ' + ownerChatEsc(e && e.message) + '</p>';
			}
		}
		async function sendOwnerChatReply() {
			if (!ownerChatCurrentUser) return;
			var input = document.getElementById('owner-chat-input');
			var btn = document.getElementById('owner-chat-send-btn');
			if (!input) return;
			var text = (input.value || '').trim();
			if (!text) { showToast('❌ متن پاسخ خالی است', 'error'); return; }
			if (btn) { btn.disabled = true; btn.innerText = '...'; }
			try {
				var res = await fetch('/api/messages/reply', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: ownerChatCurrentUser, text: text })
				});
				var data = await res.json();
				if (res.ok && data.success) {
					input.value = '';
					await loadOwnerChatMessages(true);
					showToast('✅ پاسخ ارسال شد');
				} else {
					showToast('❌ ' + (data.error || 'خطا در ارسال پاسخ'), 'error');
				}
			} catch (e) {
				showToast('❌ خطا در ارتباط با سرور', 'error');
			}
			if (btn) { btn.disabled = false; btn.innerText = 'ارسال'; }
		}
		async function deleteOwnerChatThread() {
			if (!ownerChatCurrentUser) return;
			if (!(await customConfirm('کل گفتگو با این کاربر حذف شود؟'))) return;
			try {
				var res = await fetch('/api/messages/thread?username=' + encodeURIComponent(ownerChatCurrentUser), { method: 'DELETE' });
				var data = await res.json();
				if (res.ok && data.success) {
					showToast('✅ گفتگو حذف شد');
					backToOwnerChatList();
					await loadOwnerChatThreads();
				} else {
					showToast('❌ ' + (data.error || 'خطا در حذف'), 'error');
				}
			} catch (e) { showToast('❌ خطا در ارتباط با سرور', 'error'); }
		}
		window.toggleOwnerChatModal = toggleOwnerChatModal;
		window.openOwnerChatThread = openOwnerChatThread;
		document.addEventListener('click', function (e) {
			var t = e.target;
			while (t && t !== document) {
				if (t.classList && t.classList.contains('owner-chat-thread-btn')) {
					openOwnerChatThread(t.getAttribute('data-chat-user'));
					return;
				}
				t = t.parentElement;
			}
		});
		window.backToOwnerChatList = backToOwnerChatList;
		window.loadOwnerChatThreads = loadOwnerChatThreads;
		window.sendOwnerChatReply = sendOwnerChatReply;
		
		async function deleteOwnerChatMessage(id) {
			if (!id) return;
			if (!(await customConfirm('این پیام حذف شود؟'))) return;
			try {
				var res = await fetch('/api/messages/message?id=' + encodeURIComponent(id), { method: 'DELETE', credentials: 'same-origin' });
				var data = await res.json().catch(function () { return {}; });
				if (res.ok && data.success) {
					showToast('✅ پیام حذف شد');
					await loadOwnerChatMessages(false);
				} else {
					showToast('❌ ' + (data.error || 'خطا در حذف پیام'), 'error');
				}
			} catch (e) { showToast('❌ خطا در ارتباط با سرور', 'error'); }
		}
		async function editOwnerChatMessage(id, currentText) {
			if (!id) return;
			var next = prompt('ویرایش پیام:', currentText == null ? '' : String(currentText));
			if (next === null) return;
			next = String(next).trim();
			if (!next) { showToast('❌ متن پیام خالی است', 'error'); return; }
			if (next.length > 1000) next = next.slice(0, 1000);
			try {
				var res = await fetch('/api/messages/message', {
					method: 'PUT',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ id: id, text: next })
				});
				var data = await res.json().catch(function () { return {}; });
				if (res.ok && data.success) {
					showToast('✅ پیام ویرایش شد');
					await loadOwnerChatMessages(false);
				} else {
					showToast('❌ ' + (data.error || 'خطا در ویرایش پیام'), 'error');
				}
			} catch (e) { showToast('❌ خطا در ارتباط با سرور', 'error'); }
		}
		window.deleteOwnerChatMessage = deleteOwnerChatMessage;
		window.editOwnerChatMessage = editOwnerChatMessage;

		window.deleteOwnerChatThread = deleteOwnerChatThread;
		window.addEventListener('click', function (e) {
			if (e.target && e.target.id === 'owner-chat-modal') toggleOwnerChatModal(false);
		});
		function donationEsc(s) {
			return String(s === null || s === undefined ? '' : s)
				.replace(/&/g, '&amp;').replace(/</g, '&lt;')
				.replace(/>/g, '&gt;').replace(/"/g, '&quot;');
		}
		function donationTime(ts) {
			try { return new Date(ts).toLocaleString('fa-IR'); } catch (e) { return ''; }
		}
		function setDonationBadge(count) {
			var badge = document.getElementById('donation-notif-badge');
			if (badge) {
				badge.classList.add('hidden');
			}
			if (window.__notifState) {
				window.__notifState.donations = count || 0;
				if (typeof updateNotifBellFromState === 'function') updateNotifBellFromState();
			}
		}
		async function refreshDonationBadge() {
			try {
				var res = await fetch('/api/donation-notifications', { credentials: 'same-origin' });
				if (!res.ok) return;
				var data = await res.json();
				setDonationBadge(data.unseen || 0);
			} catch (e) { }
		}
		function toggleDonationModal(show) {
			var modal = document.getElementById('donation-modal');
			if (!modal) return;
			modal.style.display = show ? 'flex' : 'none';
			if (show) loadDonationNotifications();
			else refreshDonationBadge();
		}
		async function loadDonationNotifications() {
			var box = document.getElementById('donation-list');
			if (!box) return;
			box.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>';
			try {
				var res = await fetch('/api/donation-notifications', { credentials: 'same-origin' });
				if (!res.ok) {
					box.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطای سرور: کد ' + res.status + '</p>';
					return;
				}
				var data = await res.json();
				var rows = data.donations || [];
				setDonationBadge(data.unseen || 0);
				if (!rows.length) {
					box.innerHTML = '<p class="text-center text-xs text-gray-500 dark:text-zinc-400 py-6">هنوز اهدایی ثبت نشده است</p>';
					return;
				}
				box.innerHTML = rows.map(function (d) {
					var newBadge = !d.seen ? '<span class="min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-black inline-flex items-center justify-center">جدید</span>' : '';
					return '<div class="w-full text-right p-3 rounded-xl border border-amber-100 dark:border-amber-900/40 bg-amber-50/50 dark:bg-amber-950/20">' +
						'<div class="flex justify-between items-center gap-2 mb-1">' +
						'<span class="text-xs font-black font-mono text-amber-700 dark:text-amber-300" dir="ltr">' + donationEsc(d.from_username) + ' ← ' + donationEsc(d.to_username) + '</span>' +
						'<span class="flex items-center gap-2">' + newBadge +
						'<span class="text-[10px] font-bold text-gray-500 dark:text-zinc-400">' + donationTime(d.created_at) + '</span></span>' +
						'</div>' +
						'<p class="text-[11px] text-gray-600 dark:text-zinc-400">اهدای ' + d.gb + ' گیگابایت</p>' +
						'</div>';
				}).join('');
			} catch (e) {
				box.innerHTML = '<p class="text-center text-xs text-red-500 py-6">خطا در دریافت اطلاعات: ' + donationEsc(e && e.message) + '</p>';
			}
		}
		async function ackDonationNotifications() {
			try {
				await fetch('/api/donation-notifications/ack', { method: 'POST', credentials: 'same-origin' });
				setDonationBadge(0);
				loadDonationNotifications();
			} catch (e) { }
		}
		async function clearDonationNotifications() {
			if (!await customConfirm('⚠️ آیا از پاک کردن کامل لیست اهدای کانفیگ‌ها مطمئن هستید؟ این عمل غیرقابل بازگشت است.')) return;
			try {
				const res = await fetch('/api/donation-notifications/clear', { method: 'POST', credentials: 'same-origin' });
				const data = await res.json().catch(function () { return {}; });
				if (res.ok && data.success) {
					showToast('✅ لیست اهدا پاک شد');
					setDonationBadge(0);
					loadDonationNotifications();
				} else {
					showToast('❌ ' + (data.error || 'خطا در پاک کردن لیست'), 'error');
				}
			} catch (e) {
				showToast('❌ خطا در ارتباط با سرور', 'error');
			}
		}
		window.toggleDonationModal = toggleDonationModal;
		window.loadDonationNotifications = loadDonationNotifications;
		window.ackDonationNotifications = ackDonationNotifications;
		window.clearDonationNotifications = clearDonationNotifications;
		window.addEventListener('click', function (e) {
			if (e.target && e.target.id === 'donation-modal') toggleDonationModal(false);
		});
		document.addEventListener('DOMContentLoaded', function () {
			var inp = document.getElementById('owner-chat-input');
			if (inp) {
				inp.addEventListener('keydown', function (ev) {
					if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); sendOwnerChatReply(); }
				});
			}
			refreshOwnerChatBadge();
			setInterval(refreshOwnerChatBadge, 25000);
			refreshDonationBadge();
			setInterval(refreshDonationBadge, 25000);
			if (typeof refreshNotifCenter === 'function') {
				refreshNotifCenter(false);
				setInterval(function () { refreshNotifCenter(false); }, 30000);
			}
		});
	</script>
	${COMMON_WAVES_SCRIPT}
	  </body>
</html>`,
	status: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>وضعیت اشتراک کاربر</title>
	${COMMON_HEAD}
	<style>
		body { font-family: 'Vazirmatn', sans-serif; }
		.glass {
			background: rgba(10, 10, 10, 0.6);
			border: 1px solid rgba(255, 255, 255, 0.05);
		}
		.caspian-flag {
			display: inline-block;
			width: 1.35em;
			height: 1em;
			vertical-align: -0.15em;
			border-radius: 2px;
			background-size: cover;
			background-position: 50%;
			background-repeat: no-repeat;
		}
		.caspian-flag-globe {
			font-size: 1.1em;
			line-height: 1;
			vertical-align: -0.05em;
		}
	</style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center py-12 px-4 overflow-x-hidden">
	<div class="w-full max-w-xl glass rounded-md shadow-2xl p-6 md:p-8 relative overflow-hidden z-10">
		<div class="absolute -left-12 -top-12 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
		<div class="absolute -right-12 -bottom-12 w-40 h-40 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>
		<div class="text-center mb-8 relative z-10">
			<div class="inline-flex items-center justify-center p-3 bg-blue-950/60 border border-blue-500 text-blue-400 rounded-md mb-4 shadow-[0_0_15px_rgb(var(--a500,59_130_246)/0.4)]">
				<svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
			</div>
			<h1 class="text-xl font-bold tracking-tight text-gray-900 dark:text-white mb-1">پـنـل کاسپین - وضعیت اشتراک</h1>
			<p id="display-username" class="text-sm font-bold text-blue-500 tracking-wide font-mono mb-2"></p>
			<p id="display-flag" class="text-2xl font-bold tracking-wide mb-3" style="display:none;"></p>
			<div id="live-connections-badge" style="display: none !important;">
				<span class="w-2 h-2 rounded-full bg-green-600 animate-pulse"></span>
				<span id="live-connections-text" dir="rtl">۰ دستگاه متصل</span>
			</div>
		</div>
		<div id="announce-banner" class="mb-6 rounded-md p-4 text-center border border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs font-bold leading-relaxed relative z-10" style="display:none; white-space:pre-wrap;"></div>
		<div id="status-card" class="mb-6 rounded-md p-4 text-center border font-bold relative z-10 transition duration-300">
			<span id="status-text" class="text-sm">در حال بارگذاری وضعیت...</span>
		</div>
		<div class="grid grid-cols-2 gap-3 mb-8 relative z-10">
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
						حجم مصرفی
					</span>
					<span id="volume-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="volume-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="used-vol" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
					<span id="limit-vol" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
						زمان باقی‌مانده
					</span>
					<span id="expiry-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2 flex justify-end">
					<div id="expiry-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="days-remaining" class="font-bold text-gray-800 dark:text-zinc-200" dir="rtl">-</span>
					<span id="total-days" class="font-bold text-gray-800 dark:text-zinc-200" dir="rtl">-</span>
				</div>
			</div>
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
						ریکوئست‌ها
					</span>
					<span id="req-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="req-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="used-req" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
					<span id="limit-req" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
						دستگاه متصل
					</span>
					<span id="online-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="online-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="online-count" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">۰</span>
					<span id="limit-online" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
		</div>
		<div id="daily-limit-card" class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm mb-8 relative z-10" style="display:none;">
			<div class="flex justify-between items-center mb-2">
				<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
					<svg class="w-3.5 h-3.5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
					مصرف روزانه (ریست ۰۳:۳۰)
				</span>
				<span id="daily-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
			</div>
			<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
				<div id="daily-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
			</div>
			<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
				<span id="daily-used" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				<span id="daily-limit-text" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
			</div>
			<p id="daily-lock-note" class="text-[10px] font-bold text-amber-600 dark:text-amber-400 mt-2" style="display:none;"></p>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 relative z-10">
			<h2 class="text-sm font-bold mb-4 flex items-center gap-2">
				<svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
				دریافت کـانفـیگ و اشتراک‌ها
			</h2>
			<div class="space-y-3">
				<button onclick="copyTextSub()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-indigo-500 dark:hover:border-indigo-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg> کپی لینک ساب‌اسکریپشن متنی</span>
					<span class="text-indigo-500">کپی</span>
				</button>
				<button onclick="showSubQr()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-amber-500 dark:hover:border-amber-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg> دریافت کیوآر کد ساب</span>
					<span class="text-amber-500">نمایش</span>
				</button>
				<button onclick="copyvIeesConfig()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-blue-500 dark:hover:border-blue-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> کپی کـانفـیگ‌های اتصال (مستقیم)</span>
					<span class="text-blue-500">کپی</span>
				</button>
				<button onclick="copyClashSub()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-purple-500 dark:hover:border-purple-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2">
						<svg class="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
						کپی لینک ساب YAML (Clash)
					</span>
					<span class="text-purple-500">کپی</span>
				</button>
			</div>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 mt-6 relative z-10 w-full">
			<button onclick="document.getElementById('software-downloads-content').classList.toggle('hidden'); document.getElementById('software-downloads-icon').classList.toggle('rotate-180');" class="w-full flex items-center justify-between text-sm font-bold mb-4 cursor-pointer focus:outline-none">
				<div class="flex items-center gap-2">
					<svg class="w-4 h-4 text-pink-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					<span>دانلود نرم افزار ها</span>
				</div>
				<svg id="software-downloads-icon" class="w-4 h-4 text-gray-500 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
			</button>
			<div id="software-downloads-content" class="hidden grid grid-cols-1 sm:grid-cols-3 gap-3">
				<div class="bg-green-50/50 dark:bg-green-950/20 border border-green-200/50 dark:border-green-800/30 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-green-700 dark:text-green-500 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993.0004.5511-.4482.9997-.9993.9997m-11.046 0c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993 0 .5511-.4482.9997-.9993.9997m11.4045-6.02L19.695 6.183c.1568-.2716.0637-.6182-.2079-.7754-.2716-.1564-.6183-.0633-.775.2082l-1.8584 3.2185c-1.3853-.6328-2.9697-.9881-4.6644-.9881-1.6946 0-3.279.3553-4.664.9881L5.6664 5.6158c-.1567-.2715-.5038-.3646-.775-.2082-.2716.1572-.3647.5038-.2079.7754l1.8136 3.1385C2.963 11.2384 1.1571 14.5422 1 18.4234h22c-.1572-3.8812-1.963-7.185-5.4955-9.102"/></svg>
						اندروید
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://github.com/patterniha/PattNG/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-green-300 dark:border-green-800 px-2 py-1.5 rounded text-[10px] font-bold text-green-700 dark:text-green-400 hover:border-green-500 dark:hover:border-green-500 transition shadow-sm"><span>PattNG (پیشنهادی)</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>v2rayNG</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>happ</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-Android-universal.apk" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Hiddify</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Npv Tunnel</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>V2Box</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/KaringX/karing/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Karing</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/ExclaveNetwork/Exclave/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Exclave</span><span class="text-green-500 text-[12px]">📥</span></a>
					</div>
				</div>
				<div class="bg-blue-50/50 dark:bg-blue-950/20 border border-blue-200/50 dark:border-blue-800/30 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-blue-700 dark:text-blue-500 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg>
						ویندوز
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://github.com/patterniha/PattN/releases/latest/download/PattN-windows-64.zip" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-blue-300 dark:border-blue-800 px-2 py-1.5 rounded text-[10px] font-bold text-blue-700 dark:text-blue-400 hover:border-blue-500 dark:hover:border-blue-500 transition shadow-sm"><span>PattN (پیشنهادی)</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/2dust/v2rayN/releases/latest/download/v2rayN-windows-64.zip" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>v2rayN</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>happ</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-Windows-Setup-x64.exe" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>Hiddify</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/KaringX/karing/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>Karing</span><span class="text-blue-500 text-[12px]">📥</span></a>
					</div>
				</div>
				<div class="bg-gray-50/50 dark:bg-zinc-800/30 border border-gray-200/50 dark:border-gray-700/50 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-gray-700 dark:text-gray-300 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.05 2.95.72 3.88 1.84-3.46 2.06-2.89 6.18.54 7.42-.85 1.58-1.54 2.82-3.07 3.75zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/></svg>
						آیفون
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>V2Box</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>Streisand</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/npv-tunnel/id1629465476" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>NapsternetV</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/happ-proxy-utility/id6504287215" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>happ</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>Hiddify</span><span class="text-gray-500 text-[12px]">📥</span></a>
					</div>
				</div>
			</div>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 mt-6 relative z-10 w-full">
			<button onclick="toggleOwnerMessageBox()" class="w-full flex items-center justify-between text-sm font-bold mb-4 cursor-pointer focus:outline-none">
				<div class="flex items-center gap-2">
					<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path></svg>
					<span>ارسال پیام به مالک</span>
					<span id="owner-msg-badge" class="hidden min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold inline-flex items-center justify-center">0</span>
				</div>
				<svg id="owner-msg-icon" class="w-4 h-4 text-gray-500 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
			</button>
			<div id="owner-msg-content" class="hidden">
				<div id="owner-msg-list" class="h-56 overflow-y-auto space-y-2 p-3 rounded-md bg-gray-50 dark:bg-zinc-900/40 border border-gray-200 dark:border-amoled-border mb-3">
					<p class="text-center text-[11px] text-gray-500 dark:text-zinc-400 py-6">در حال بارگذاری...</p>
				</div>
				<div class="flex items-end gap-2">
					<textarea id="owner-msg-input" rows="2" maxlength="1000" placeholder="پیام خود را برای مالک پنل بنویسید..." class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-800 dark:text-zinc-200 resize-none"></textarea>
					<button type="button" id="owner-msg-send" onclick="sendOwnerMessage()" class="px-4 py-2.5 rounded-md text-[11px] font-bold bg-blue-600 hover:bg-blue-700 text-white transition shadow-sm">ارسال</button>
				</div>
				<p class="text-[10px] text-gray-400 dark:text-zinc-500 mt-2 leading-relaxed">پاسخ مالک پنل در همین بخش برای شما نمایش داده می‌شود.</p>
			</div>
		</div>
		<div id="cfg-donate-section" class="border-t border-gray-100 dark:border-zinc-800 pt-6 mt-6 relative z-10 w-full hidden">
			<button onclick="toggleDonateConfigBox()" class="w-full flex items-center justify-between text-sm font-bold mb-4 cursor-pointer focus:outline-none">
				<div class="flex items-center gap-2">
<svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
    <rect x="3" y="8" width="18" height="4" rx="1"/>
    <path d="M5 12v8a1 1 0 001 1h12a1 1 0 001-1v-8"/>
    <path d="M12 8v13"/>
    <path d="M12 8s-1-4-3.5-4a2 2 0 000 4H12z"/>
    <path d="M12 8s1-4 3.5-4a2 2 0 010 4H12z"/>
</svg>					<span>اهدای بخشی از حجم به دوستم</span>
				</div>
				<svg id="cfg-donate-icon" class="w-4 h-4 text-gray-500 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
			</button>
			<div id="cfg-donate-content" class="hidden">
				<div id="cfg-donate-form">
					<p class="text-[11px] text-gray-500 dark:text-zinc-400 mb-3 leading-relaxed">بخشی از حجم باقیمانده خودتان را انتخاب کنید؛ همان مقدار از حجم کل شما کم می‌شود و یک کانفیگ مستقل با همان مقدار حجم برای دوستتان ساخته می‌شود.</p>
					<p class="text-[11px] font-bold text-gray-700 dark:text-zinc-300 mb-2">حجم باقیمانده شما: <span id="cfg-donate-remaining" class="text-green-600 dark:text-green-400" dir="ltr">-</span></p>
					<div class="flex flex-wrap gap-1.5 mb-3" id="cfg-donate-presets"></div>
					<div class="flex items-center gap-2 mb-3">
						<input type="number" id="cfg-donate-amount" step="0.1" min="0.1" placeholder="حجم دلخواه (GB)" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
						<span class="text-xs font-bold text-gray-500 dark:text-zinc-400">GB</span>
					</div>
					<button type="button" id="cfg-donate-submit-btn" onclick="submitDonateConfig()" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-600 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/20 font-black rounded-xl text-xs sm:text-sm transition shadow-lg">ساخت و اهدای کانفیگ</button>
					<p id="cfg-donate-error" class="text-[11px] font-bold text-red-500 mt-2 empty:hidden"></p>
				</div>
				<div id="cfg-donate-result" class="hidden">
					<p class="text-[11px] font-bold text-green-600 dark:text-green-400 mb-3">✅ کانفیگ با موفقیت برای دوستتان ساخته شد.</p>
					<div class="flex items-center gap-2 mb-2">
						<input type="text" id="cfg-donate-result-link" readonly dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900/40 border border-gray-200 dark:border-amoled-border rounded-lg text-[10px] font-mono text-gray-700 dark:text-zinc-300">
					</div>
					<div class="flex items-center gap-2">
						<button type="button" onclick="copyDonateResultLink()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-950/40 transition">کپی لینک صفحه وضعیت</button>
						<button type="button" onclick="showDonateResultQr()" class="flex-1 py-2 rounded-lg text-[11px] font-black border border-gray-300 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-800 transition">نمایش QR</button>
					</div>
					<button type="button" onclick="resetDonateConfigForm()" class="w-full mt-3 py-2 rounded-lg text-[11px] font-black border border-gray-200 dark:border-zinc-800 text-gray-500 dark:text-zinc-400 hover:bg-gray-50 dark:hover:bg-zinc-800 transition">اهدای مورد دیگر</button>
				</div>
			</div>
		</div>
	</div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
		<div class="flex justify-between items-center mb-4">
			<h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
			<button onclick="toggleQrModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex justify-center bg-gray-100 dark:bg-amoled-bg p-4 rounded-md mb-4 border border-gray-200 dark:border-zinc-800">
			<div id="qrcode-container"></div>
		</div>
		<div id="qr-announce-note" class="hidden mb-4 p-3 rounded-md border border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs font-bold leading-relaxed text-center" style="white-space:pre-wrap;"></div>
		<button onclick="downloadQrCode()" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-md text-sm transition duration-200 shadow-sm flex items-center justify-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
			دانلود تصویر QR
		</button>
	</div>
</div>
${COMMON_TOAST_HTML}
	<script>
		/* {{USER_DATA_PLACEHOLDER}} */
		${COMMON_TOAST_JS}
		function getHost() {
			return window.location.host;
		}
		function getvIeesLink() {
			const u = window.statusUser;
			if (!u) return '';
			const host = getHost();
			var ips = [host];
			if (u.ips) {
				const parsedIps = u.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
				if (parsedIps.length > 0) ips = parsedIps;
			}
			var ports = String(u.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
			var fp = u.fingerprint || 'chrome';
			const dynPath = encodeURIComponent("/stream/PANEL_CASPIAN/" + (u.uuid ? u.uuid.split("-")[4] : "default"));
			const links = [];
			let remVol = "Unlimited";
			if (u.limit_gb) {
				let rem = u.limit_gb - (u.used_gb || 0);
				remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
			}
			let remTime = "Unlimited";
			if (u.expiry_days && u.created_at) {
				const created = new Date(u.created_at);
				const expiryDate = new Date(created.getTime() + u.expiry_days * 24 * 60 * 60 * 1000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
			let remReq = "Unlimited";
			if (u.limit_req) {
				let rem = u.limit_req - (u.used_req || 0);
				remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
			}
			const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
links.push('vle' + 'ss://' + (u.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(infoRemark));
			const rawPath = "/stream/PANEL_CASPIAN/" + (u.uuid ? u.uuid.split("-")[4] : "default");
			let proxyList = [];
			try {
				if (u.user_socks5 && u.user_socks5.trim().startsWith("[")) {
					proxyList = JSON.parse(u.user_socks5);
				} else if (u.user_socks5 || u.user_proxy_ip) {
					proxyList = [u.user_socks5 || u.user_proxy_ip];
				} else {
					proxyList = [null];
				}
			} catch (e) {
				proxyList = [u.user_socks5 || u.user_proxy_ip];
			}
			if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
			const allowDirect = u.enable_direct !== 0;
			if (allowDirect) {
				let hasDirect = proxyList.some(function(p) { return p === null || p === ""; });
				if (!hasDirect) proxyList.push(null);
			} else {
				proxyList = proxyList.filter(function(p) { return p !== null && p !== ""; });
			}
			if (proxyList.length === 0) proxyList = [null];
			let proxyFlagCache = {};
			try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
			let resolvedProxies = [];
			for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
				let proxyItem = proxyList[locIdx];
				let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
				let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : (u.user_proxy_iata || "");
				let flagEmoji = "🌐";
				if (countryCode && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(countryCode);
				} else if (proxyStr && proxyFlagCache[proxyStr] && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(proxyFlagCache[proxyStr]);
				}
				const currentDynPath = encodeURIComponent(rawPath + ((proxyItem !== null && proxyItem !== "") ? "/loc-" + locIdx : ""));
				resolvedProxies.push({ flagEmoji, currentDynPath });
			}
			const userConnType = String(u.connection_type || 'vless').toLowerCase();
			const enableVless = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan') && !userConnType.includes('shadowsocks'));
			const enableTrojan = userConnType.includes('trojan');
			const enableSS = userConnType.includes('shadowsocks');
			ips.forEach((ip) => {
				ports.forEach((portStr) => {
					resolvedProxies.forEach((proxy) => {
						const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
						const tlsVal = isTlsPort ? "tls" : "none";
						let userFrag = "";
						if (u.frag_len && u.frag_int) userFrag += "&fragment=" + encodeURIComponent(u.frag_len + "," + u.frag_int + (isTlsPort ? ",tlshello" : ""));
						if (u.advanced_frag) userFrag += "&fm=" + encodeURIComponent(u.advanced_frag);
						if (isTlsPort && u.cipher_suites) userFrag += "&cs=" + encodeURIComponent(u.cipher_suites);
						if (u.tls_mask) userFrag += "&mask=" + encodeURIComponent(u.tls_mask);
						
						const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

						if (enableVless) {
							const remark = "CASPIAN | " + proxy.flagEmoji + " | " + u.username;
							links.push('vle' + 'ss://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
						}
						if (enableTrojan) {
							const trojanRemark = "CASPIAN | " + proxy.flagEmoji + " | " + u.username;
							links.push('trojan://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(trojanRemark));
						}
						if (enableSS) {
							const ssRemark = "CASPIAN | " + proxy.flagEmoji + " | " + u.username;
							const methodPass = btoa("aes-256-gcm:" + (u.uuid || ''));
							let pluginOpts = "v2ray-plugin;mode=websocket;host=" + host + ";path=" + decodeURIComponent(proxy.currentDynPath) + (isTlsPort ? ";tls" : "");
							let pluginStr = encodeURIComponent(pluginOpts);
							links.push("ss://" + methodPass + "@" + ip + ":" + portStr + "/?plugin=" + pluginStr + "#" + encodeURIComponent(ssRemark));
						}
					});
				});
			});
			return links.join('\\n');
		}
		function copyvIeesConfig() {
			navigator.clipboard.writeText(getvIeesLink()).then(() => alert('✅ کـانفـیگ با موفقیت کپی شد!'));
		}
		function copyTextSub() {
			const link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب متنی کپی شد!'));
		}
		function copyClashSub() {
			const link = window.location.protocol + '//' + getHost() + '/clash/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب Clash (YAML) کپی شد!'));
		}
		function copySingboxSub() {
			const link = window.location.protocol + '//' + getHost() + '/singbox/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب Sing-box کپی شد!'));
		}
		function toggleQrModal(show, text, note) {
			const noteEl = document.getElementById('qr-announce-note');
			if (noteEl) { if (show && note) { noteEl.textContent = '📢 ' + note; noteEl.classList.remove('hidden'); } else { noteEl.textContent = ''; noteEl.classList.add('hidden'); } }
			const modal = document.getElementById('qr-modal');
			const card = document.getElementById('qr-modal-card');
			const container = document.getElementById('qrcode-container');
			if (show) {
				container.innerHTML = '';
				const qrCode = new QRCodeStyling({
					width: 280,
					height: 280,
					data: text,
					margin: 5,
					qrOptions: { errorCorrectionLevel: 'L' },
					dotsOptions: {
						color: "#000000",
						type: "square"
					},
					backgroundOptions: {
						color: "#ffffff"
					},
					cornersSquareOptions: {
						color: "#000000",
						type: "square"
					},
					cornersDotOptions: {
						color: "#000000",
						type: "square"
					}
				});
				qrCode.append(container);
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
		function downloadQrCode() {
			const container = document.getElementById('qrcode-container');
			if (!container) return;
			const canvas = container.querySelector('canvas');
			const img = container.querySelector('img');
			let dataUrl = '';
			if (canvas) {
				dataUrl = canvas.toDataURL("image/png");
			} else if (img && img.src) {
				dataUrl = img.src;
			}
			if (!dataUrl) {
				alert('⚠️ تصویر QR برای دانلود یافت نشد!');
				return;
			}
			const downloadAnchor = document.createElement('a');
			downloadAnchor.href = dataUrl;
			downloadAnchor.download = "caspian_qrcode_" + Date.now() + ".png";
			document.body.appendChild(downloadAnchor);
			downloadAnchor.click();
			downloadAnchor.remove();
		}
		function showSubQr() {
			const link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
			const annNote = (Number(window.statusUser.announce_enabled) === 1 && window.statusUser.announce_text) ? window.statusUser.announce_text : '';
			toggleQrModal(true, link, annNote);
		}
		function showSingboxQr() {
			const link = window.location.protocol + '//' + getHost() + '/singbox/' + encodeURIComponent(window.statusUser.username);
			toggleQrModal(true, link);
		}
		function getFlagEmoji(countryCode) {
			if (!countryCode) return '<span class="caspian-flag-globe">🌐</span>';
			const cc = String(countryCode).toLowerCase().replace(/[^a-z]/g, '');
			if (cc.length !== 2) return '<span class="caspian-flag-globe">🌐</span>';
			return '<span class="fi fi-' + cc + ' caspian-flag" title="' + cc.toUpperCase() + '"></span>';
		}
		function getFlagEmojiText(countryCode) {
			if (!countryCode) return '🌐';
			const cc = String(countryCode).toUpperCase().replace(/[^A-Z]/g, '');
			if (cc.length !== 2) return '🌐';
			try {
				return String.fromCodePoint(...cc.split('').map(char => 127397 + char.charCodeAt(0)));
			} catch (e) {
				return '🌐';
			}
		}
		document.addEventListener('DOMContentLoaded', () => {
			const u = window.statusUser;
			if (!u) return;
			const limit = u.ip_limit !== undefined ? u.ip_limit : u.max_connections;
			document.getElementById('display-username').innerText = u.username;
			const annBox = document.getElementById('announce-banner');
			if (annBox && Number(u.announce_enabled) === 1 && u.announce_text) { annBox.textContent = '📢 ' + u.announce_text; annBox.style.display = 'block'; }
const flagContainer = document.getElementById('display-flag');
	if (u.user_proxy_iata) {
		const flag = getFlagEmoji(u.user_proxy_iata);
		flagContainer.innerHTML = flag + " " + u.user_proxy_iata.toUpperCase();
		flagContainer.style.display = 'block';
} else if (u.user_socks5 || u.user_proxy_ip) {
	flagContainer.style.display = 'block';
	let proxyList = [];
	try {
		if (u.user_socks5 && u.user_socks5.trim().startsWith("[")) {
			proxyList = JSON.parse(u.user_socks5);
		} else {
			proxyList = [u.user_socks5 || u.user_proxy_ip];
		}
	} catch(e) {
		proxyList = [u.user_socks5 || u.user_proxy_ip];
	}
	let initialFlags = proxyList.map(item => {
		let targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
		let targetCountry = typeof item === 'object' && item !== null ? item.country : null;
		if (targetCountry) return getFlagEmoji(targetCountry);
		try {
			const proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
			const cached = proxyFlagCache[targetProxy];
			if (cached && typeof cached === 'string' && /^[a-zA-Z]{2}$/.test(cached)) return getFlagEmoji(cached);
		} catch(e) {}
		return '⏳';
	});
	flagContainer.innerHTML = initialFlags.join(' ');
	Promise.all(proxyList.map((item, index) => {
		let targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
		let targetCountry = typeof item === 'object' && item !== null ? item.country : null;
		if (targetCountry) return Promise.resolve(getFlagEmoji(targetCountry));
		try {
			const proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
			const cached = proxyFlagCache[targetProxy];
			if (cached && typeof cached === 'string' && /^[a-zA-Z]{2}$/.test(cached)) return Promise.resolve(getFlagEmoji(cached));
		} catch(e) {}
		return fetch('/api/test-proxy', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ proxy: targetProxy })
		})
		.then(res => res.json())
		.then(data => {
			if (data.success && data.country) {
				const flagSvg = getFlagEmoji(data.country);
				try {
					const cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
					cache[targetProxy] = data.country.toUpperCase();
					localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
				} catch(e) {}
				return flagSvg;
			}
			return '<span class="caspian-flag-globe">🌐</span>';
		})
		.catch(() => '<span class="caspian-flag-globe">🌐</span>');
	})).then(flags => {
		flagContainer.innerHTML = flags.join(' ');
	});
}
			const badge = document.getElementById('live-connections-badge');
			badge.classList.remove('hidden');
			if (u.online_count && u.online_count > 0) {
				document.getElementById('live-connections-text').innerText = u.online_count + (limit ? '/' + limit : '') + ' دستگاه متصل';
				badge.className = 'inline-flex items-center gap-1.5 px-3 py-1 bg-green-600/10 border border-green-600/20 text-green-600 rounded-full text-xs font-bold shadow-sm';
				badge.querySelector('span.w-2').className = 'w-2 h-2 rounded-full bg-green-600 animate-pulse';
			} else {
				document.getElementById('live-connections-text').innerText = '۰ دستگاه متصل';
				badge.className = 'inline-flex items-center gap-1.5 px-3 py-1 bg-gray-500/10 border border-gray-500/20 text-gray-500 dark:text-zinc-400 rounded-full text-xs font-bold shadow-sm';
				badge.querySelector('span.w-2').className = 'w-2 h-2 rounded-full bg-gray-500';
			}
			const usedGb = u.used_gb || 0;
			const limitGb = u.limit_gb;
			const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
			document.getElementById('used-vol').innerText = formattedUsed;
			let isVolumeExpired = false;
			if (limitGb) {
				document.getElementById('limit-vol').innerText = limitGb + ' GB';
				const pct = Math.min((usedGb / limitGb) * 100, 100);
				document.getElementById('volume-pct').innerText = pct.toFixed(0) + '٪';
				document.getElementById('volume-progress').style.width = pct + '%';
				const hue = 120 - (pct * 1.2);
				document.getElementById('volume-progress').style.backgroundColor = __usageColor(hue);
				if (usedGb >= limitGb) isVolumeExpired = true;
			} else {
				document.getElementById('limit-vol').innerText = 'نامحدود';
				document.getElementById('volume-pct').innerText = '۰٪';
				document.getElementById('volume-progress').style.width = '100%';
				document.getElementById('volume-progress').style.backgroundColor = 'rgb(var(--a500, 59 130 246))';
			}
			updateDonateConfigVisibility(limitGb, usedGb);
			let daysRemaining = 'نامحدود';
			let totalDays = 'نامحدود';
			let isTimeExpired = false;
			if (u.expiry_days) {
				totalDays = u.expiry_days + ' روز';
				if (u.start_on_first_connect === 1 && !u.first_connection_time) {
					daysRemaining = u.expiry_days + ' روز (شروع از اولین اتصال)';
					document.getElementById('expiry-pct').innerText = '۱۰۰٪';
					document.getElementById('expiry-progress').style.width = '100%';
					document.getElementById('expiry-progress').style.backgroundColor = 'rgb(var(--a500, 59 130 246))';
				} else if (u.start_on_first_connect === 1 && u.first_connection_time) {
					const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 86400000));
					const diffDays = Math.ceil((expiryDate - new Date()) / (86400000));
					daysRemaining = (diffDays > 0 ? diffDays : 0) + ' روز';
					const pct = Math.max(0, Math.min(100, (Math.max(0, diffDays) / u.expiry_days) * 100));
					document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
					document.getElementById('expiry-progress').style.width = pct + '%';
					const hue = pct * 1.2;
					document.getElementById('expiry-progress').style.backgroundColor = __usageColor(hue);
					if (new Date() > expiryDate) isTimeExpired = true;
				} else if (u.created_at) {
					const created = new Date(u.created_at);
					const expiryDate = new Date(created.getTime() + (u.expiry_days * 86400000));
					const diffDays = Math.ceil((expiryDate - new Date()) / (86400000));
					daysRemaining = (diffDays > 0 ? diffDays : 0) + ' روز';
					const pct = Math.max(0, Math.min(100, (Math.max(0, diffDays) / u.expiry_days) * 100));
					document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
					document.getElementById('expiry-progress').style.width = pct + '%';
					const hue = pct * 1.2;
					document.getElementById('expiry-progress').style.backgroundColor = __usageColor(hue);
					if (new Date() > expiryDate) isTimeExpired = true;
				}
			} else {
				document.getElementById('expiry-pct').innerText = '۰٪';
				document.getElementById('expiry-progress').style.width = '100%';
				document.getElementById('expiry-progress').style.backgroundColor = 'rgb(var(--a500, 59 130 246))';
			}
			document.getElementById('days-remaining').innerText = daysRemaining === 'نامحدود' ? 'نامحدود' : (daysRemaining.includes('روز') ? daysRemaining : daysRemaining + ' روز');
			document.getElementById('total-days').innerText = totalDays;
			const usedReq = u.used_req || 0;
			const limitReq = u.limit_req;
			document.getElementById('used-req').innerText = usedReq.toLocaleString();
			let isReqExpired = false;
			if (limitReq) {
				document.getElementById('limit-req').innerText = limitReq.toLocaleString();
				const rPct = Math.min((usedReq / limitReq) * 100, 100);
				document.getElementById('req-pct').innerText = rPct.toFixed(0) + '٪';
				document.getElementById('req-progress').style.width = rPct + '%';
				const rHue = 120 - (rPct * 1.2);
				document.getElementById('req-progress').style.backgroundColor = __usageColor(rHue);
				if (usedReq >= limitReq) isReqExpired = true;
			} else {
				document.getElementById('limit-req').innerText = 'نامحدود';
				document.getElementById('req-pct').innerText = '۰٪';
				document.getElementById('req-progress').style.width = '100%';
				document.getElementById('req-progress').style.backgroundColor = 'rgb(var(--a500, 59 130 246))';
			}
			const onlineCount = u.online_count || 0;
			document.getElementById('online-count').innerText = onlineCount;
			if (limit) {
				document.getElementById('limit-online').innerText = limit;
				const oPct = Math.min((onlineCount / limit) * 100, 100);
				document.getElementById('online-pct').innerText = oPct.toFixed(0) + '٪';
				document.getElementById('online-progress').style.width = oPct + '%';
				const oHue = 120 - (oPct * 1.2);
				document.getElementById('online-progress').style.backgroundColor = __usageColor(oHue);
			} else {
				document.getElementById('limit-online').innerText = 'نامحدود';
				document.getElementById('online-pct').innerText = '۰٪';
				document.getElementById('online-progress').style.width = '100%';
				document.getElementById('online-progress').style.backgroundColor = onlineCount > 0 ? 'rgb(var(--a600, 22 163 74))' : '#9ca3af'; 
			}
			let isDailyLocked = false;
			if (u.daily_limit_gb) {
				const dailyCard = document.getElementById('daily-limit-card');
				if (dailyCard) dailyCard.style.display = '';
				const dailyUsed = u.daily_used_gb || 0;
				const step = u.daily_lock_step || 0;
				const windowUsed = Math.max(0, dailyUsed - step);
				const dailyPct = Math.min((windowUsed / u.daily_limit_gb) * 100, 100);
				const formattedDailyUsed = windowUsed < 1 ? (windowUsed * 1024).toFixed(0) + ' MB' : windowUsed.toFixed(2) + ' GB';
				const formattedDailyLimit = u.daily_limit_gb < 1 ? (u.daily_limit_gb * 1024).toFixed(0) + ' MB' : u.daily_limit_gb + ' GB';
				document.getElementById('daily-used').innerText = formattedDailyUsed;
				document.getElementById('daily-limit-text').innerText = formattedDailyLimit;
				document.getElementById('daily-pct').innerText = dailyPct.toFixed(0) + '٪';
				document.getElementById('daily-progress').style.width = dailyPct + '%';
				const dailyHue = 120 - (dailyPct * 1.2);
				document.getElementById('daily-progress').style.backgroundColor = (typeof __usageColor === 'function') ? __usageColor(dailyHue) : ('hsl(' + dailyHue + ', 80%, 45%)');
				const noteEl = document.getElementById('daily-lock-note');
				if (u.daily_lock_until && Date.now() < u.daily_lock_until) {
					isDailyLocked = true;
					const unlockDate = new Date(u.daily_lock_until);
					noteEl.innerText = '⏳ سقف مصرف روزانه تمام شد؛ اتصال تا ساعت ' + unlockDate.toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tehran' }) + ' قفل است.';
					noteEl.style.display = '';
				} else {
					noteEl.style.display = 'none';
				}
			} else {
				const dailyCard = document.getElementById('daily-limit-card');
				if (dailyCard) dailyCard.style.display = 'none';
			}
			const statusCard = document.getElementById('status-card');
			const statusText = document.getElementById('status-text');
			if (u.is_active === 0) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-red-500/10 border-red-500/30 text-red-500 shadow-md shadow-red-500/5';
				statusCard.style.boxShadow = 'inset 0 0 12px rgba(239, 68, 68, 0.1)';
				statusText.innerText = '❌ وضعیت اشتراک: غیرفعال / مسدود دستی';
			} else if (isVolumeExpired || isReqExpired || isTimeExpired) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
				if (isVolumeExpired) statusText.innerText = '⚠️ وضعیت اشتراک: تمام شدن حجم مجاز';
				else if (isReqExpired) statusText.innerText = '📈 وضعیت اشتراک: تمام شدن ریکوئست مجاز';
				else if (isTimeExpired) statusText.innerText = '⏳ وضعیت اشتراک: منقضی شده (پایان زمان اعتبار)';
			} else if (isDailyLocked) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
				statusText.innerText = '⏳ وضعیت اشتراک: قفل موقت (سقف مصرف روزانه)';
			} else {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-green-600/10 border-green-600/30 text-green-600 shadow-md shadow-green-600/5';
				statusText.innerText = '✅ وضعیت اشتراک: فعال و متصل';
			}
		});
		/* ---------------- پیام به مالک پنل ---------------- */
		var ownerMsgOpen = false;
		var ownerMsgTimer = null;
		var ownerMsgLastId = 0;
		var ownerMsgSeenId = 0;
		function ownerMsgEsc(s) {
			return String(s === null || s === undefined ? '' : s)
				.replace(/&/g, '&amp;').replace(/</g, '&lt;')
				.replace(/>/g, '&gt;').replace(/"/g, '&quot;');
		}
		function ownerMsgTime(ts) {
			try { return new Date(ts).toLocaleString('fa-IR'); } catch (e) { return ''; }
		}
		function ownerMsgCreds() {
			var u = window.statusUser || {};
			if (!u.username || !u.uuid) return null;
			return 'username=' + encodeURIComponent(u.username) + '&uuid=' + encodeURIComponent(u.uuid);
		}
		function toggleOwnerMessageBox() {
			var content = document.getElementById('owner-msg-content');
			var icon = document.getElementById('owner-msg-icon');
			if (!content) return;
			ownerMsgOpen = content.classList.contains('hidden');
			content.classList.toggle('hidden');
			if (icon) icon.classList.toggle('rotate-180');
			if (ownerMsgOpen) {
				loadOwnerMessages(true);
				if (ownerMsgTimer) clearInterval(ownerMsgTimer);
				ownerMsgTimer = setInterval(function () { loadOwnerMessages(false); }, 15000);
			} else if (ownerMsgTimer) {
				clearInterval(ownerMsgTimer);
				ownerMsgTimer = null;
			}
		}
		function setOwnerMsgBadge(n) {
			var badge = document.getElementById('owner-msg-badge');
			if (!badge) return;
			if (n > 0) { badge.innerText = n > 99 ? '99+' : String(n); badge.classList.remove('hidden'); }
			else badge.classList.add('hidden');
		}
		async function loadOwnerMessages(scroll) {
			var creds = ownerMsgCreds();
			var box = document.getElementById('owner-msg-list');
			if (!creds || !box) return;
			try {
				var res = await fetch('/api/sub-messages?' + creds);
				if (!res.ok) return;
				var data = await res.json();
				var msgs = data.messages || [];
				if (!msgs.length) {
					box.innerHTML = '<p class="text-center text-[11px] text-gray-500 dark:text-zinc-400 py-6">هنوز پیامی ارسال نکرده‌اید</p>';
					setOwnerMsgBadge(0);
					return;
				}
				box.innerHTML = msgs.map(function (m) {
					var mine = m.sender === 'user';
					var wrap = mine ? 'flex justify-end' : 'flex justify-start';
					var bubble = mine
						? 'max-w-[80%] p-2.5 rounded-xl bg-blue-600 text-white relative group'
						: 'max-w-[80%] p-2.5 rounded-xl bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-800 dark:text-zinc-200 relative group';
					var who = mine ? 'شما' : 'مالک پنل';
					var actions = '';
					if (mine) {
						actions = '<div class="flex items-center gap-1 mt-1.5 opacity-70 group-hover:opacity-100 transition">' +
							'<button type="button" title="ویرایش" onclick="editStatusUserMessage(' + m.id + ',' + JSON.stringify(String(m.body || '')).replace(/</g, '\\u003c') + ')" class="p-0.5 rounded text-white/80 hover:text-white transition" aria-label="ویرایش">' +
							'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536M4 20h4.586a1 1 0 00.707-.293l9.414-9.414a2 2 0 000-2.828l-3.172-3.172a2 2 0 00-2.828 0L4.293 13.707A1 1 0 004 14.414V20z"></path></svg></button>' +
							'<button type="button" title="حذف" onclick="deleteStatusUserMessage(' + m.id + ')" class="p-0.5 rounded text-white/80 hover:text-red-200 transition" aria-label="حذف">' +
							'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6M9 7V4a1 1 0 011-1h4a1 1 0 011 1v3M4 7h16"></path></svg></button>' +
							'</div>';
					}
					return '<div class="' + wrap + '"><div class="' + bubble + '">' +
						'<p class="text-[11px] leading-relaxed" style="white-space:pre-wrap;">' + ownerMsgEsc(m.body) + '</p>' +
						'<p class="text-[9px] opacity-70 mt-1">' + who + ' - ' + ownerMsgTime(m.created_at) + '</p>' +
						actions +
						'</div></div>';
				}).join('');
				ownerMsgLastId = msgs[msgs.length - 1].id || 0;
				if (ownerMsgOpen) ownerMsgSeenId = ownerMsgLastId;
				setOwnerMsgBadge(0);
				if (scroll) box.scrollTop = box.scrollHeight;
			} catch (e) { }
		}
		async function checkOwnerReplies() {
			var creds = ownerMsgCreds();
			if (!creds || ownerMsgOpen) return;
			try {
				var res = await fetch('/api/sub-messages?' + creds);
				if (!res.ok) return;
				var data = await res.json();
				var msgs = data.messages || [];
				var unseen = 0;
				for (var i = 0; i < msgs.length; i++) {
					if (msgs[i].sender === 'owner' && (msgs[i].id || 0) > ownerMsgSeenId) unseen++;
				}
				setOwnerMsgBadge(unseen);
			} catch (e) { }
		}
		async function sendOwnerMessage() {
			var u = window.statusUser || {};
			var input = document.getElementById('owner-msg-input');
			var btn = document.getElementById('owner-msg-send');
			if (!input) return;
			var text = (input.value || '').trim();
			if (!text) { showToast('❌ متن پیام خالی است', 'error'); return; }
			if (btn) { btn.disabled = true; btn.innerText = '...'; }
			try {
				var res = await fetch('/api/sub-messages', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: u.username, uuid: u.uuid, text: text })
				});
				var data = await res.json();
				if (res.ok && data.success) {
					input.value = '';
					await loadOwnerMessages(true);
					showToast('✅ پیام شما برای مالک ارسال شد');
				} else {
					showToast('❌ ' + (data.error || 'خطا در ارسال پیام'), 'error');
				}
			} catch (e) {
				showToast('❌ خطا در ارتباط با سرور', 'error');
			}
			if (btn) { btn.disabled = false; btn.innerText = 'ارسال'; }
		}
		var donateRemainingGb = 0;
		var donateLastResult = null;
		function updateDonateConfigVisibility(limitGb, usedGb) {
			var section = document.getElementById('cfg-donate-section');
			if (!section) return;
			if (!limitGb) {
				section.classList.add('hidden');
				return;
			}
			section.classList.remove('hidden');
			donateRemainingGb = Math.max(0, limitGb - (usedGb || 0));
			var remEl = document.getElementById('cfg-donate-remaining');
			if (remEl) remEl.innerText = donateRemainingGb.toFixed(2) + ' GB';
			var presetsEl = document.getElementById('cfg-donate-presets');
			if (presetsEl) {
				var options = [1, 2, 5, 10, 20].filter(function (v) { return v <= donateRemainingGb; });
				presetsEl.innerHTML = options.map(function (v) {
					return '<button type="button" onclick="setDonateAmount(' + v + ')" class="px-3 py-1 rounded-full bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-900 text-green-700 dark:text-green-400 text-[11px] font-bold hover:bg-green-100 dark:hover:bg-green-900/30 transition">' + v + ' GB</button>';
				}).join('');
			}
		}
		function setDonateAmount(v) {
			var input = document.getElementById('cfg-donate-amount');
			if (input) input.value = v;
		}
		function toggleDonateConfigBox() {
			var content = document.getElementById('cfg-donate-content');
			var icon = document.getElementById('cfg-donate-icon');
			if (!content) return;
			content.classList.toggle('hidden');
			if (icon) icon.classList.toggle('rotate-180');
		}
		function resetDonateConfigForm() {
			var form = document.getElementById('cfg-donate-form');
			var result = document.getElementById('cfg-donate-result');
			var errEl = document.getElementById('cfg-donate-error');
			var input = document.getElementById('cfg-donate-amount');
			if (input) input.value = '';
			if (errEl) errEl.innerText = '';
			if (form) form.classList.remove('hidden');
			if (result) result.classList.add('hidden');
			donateLastResult = null;
		}
		async function submitDonateConfig() {
			var u = window.statusUser || {};
			var input = document.getElementById('cfg-donate-amount');
			var btn = document.getElementById('cfg-donate-submit-btn');
			var errEl = document.getElementById('cfg-donate-error');
			if (errEl) errEl.innerText = '';
			var gb = parseFloat(input ? input.value : '');
			if (!gb || isNaN(gb) || gb <= 0) {
				if (errEl) errEl.innerText = '❌ لطفاً یک مقدار حجم معتبر وارد کنید';
				return;
			}
			if (gb > donateRemainingGb) {
				if (errEl) errEl.innerText = '❌ حجم انتخابی بیشتر از حجم باقیمانده شماست';
				return;
			}
			if (btn) { btn.disabled = true; btn.innerText = 'در حال ساخت...'; }
			try {
				var res = await fetch('/api/donate-config', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: u.username, uuid: u.uuid, gb: gb })
				});
				var data = await res.json();
				if (res.ok && data.success) {
					donateLastResult = data;
					var form = document.getElementById('cfg-donate-form');
					var result = document.getElementById('cfg-donate-result');
					var linkInput = document.getElementById('cfg-donate-result-link');
					if (linkInput) linkInput.value = data.status_url;
					if (form) form.classList.add('hidden');
					if (result) result.classList.remove('hidden');
					showToast('✅ کانفیگ با موفقیت اهدا شد');
				} else {
					if (errEl) errEl.innerText = '❌ ' + (data.error || 'خطا در ساخت کانفیگ');
				}
			} catch (e) {
				if (errEl) errEl.innerText = '❌ خطا در ارتباط با سرور';
			}
			if (btn) { btn.disabled = false; btn.innerText = 'ساخت و اهدای کانفیگ'; }
		}
		function copyDonateResultLink() {
			if (!donateLastResult) return;
			navigator.clipboard.writeText(donateLastResult.status_url).then(function () { showToast('✅ لینک کپی شد'); });
		}
		function showDonateResultQr() {
			if (!donateLastResult) return;
			toggleQrModal(true, donateLastResult.status_url);
		}
		window.updateDonateConfigVisibility = updateDonateConfigVisibility;
		window.setDonateAmount = setDonateAmount;
		window.toggleDonateConfigBox = toggleDonateConfigBox;
		window.resetDonateConfigForm = resetDonateConfigForm;
		window.submitDonateConfig = submitDonateConfig;
		window.copyDonateResultLink = copyDonateResultLink;
		window.showDonateResultQr = showDonateResultQr;
		window.toggleOwnerMessageBox = toggleOwnerMessageBox;
		
		async function deleteStatusUserMessage(id) {
			if (!id) return;
			var u = window.statusUser || {};
			if (!u.username || !u.uuid) return;
			if (!confirm('این پیام حذف شود؟')) return;
			try {
				var res = await fetch('/api/sub-messages', {
					method: 'DELETE',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: u.username, uuid: u.uuid, id: id })
				});
				var data = await res.json().catch(function () { return {}; });
				if (res.ok && data.success) {
					showToast('✅ پیام حذف شد');
					await loadOwnerMessages(false);
				} else {
					showToast('❌ ' + (data.error || 'خطا در حذف پیام'), 'error');
				}
			} catch (e) { showToast('❌ خطا در ارتباط با سرور', 'error'); }
		}
		async function editStatusUserMessage(id, currentText) {
			if (!id) return;
			var u = window.statusUser || {};
			if (!u.username || !u.uuid) return;
			var next = prompt('ویرایش پیام:', currentText == null ? '' : String(currentText));
			if (next === null) return;
			next = String(next).trim();
			if (!next) { showToast('❌ متن پیام خالی است', 'error'); return; }
			if (next.length > 1000) next = next.slice(0, 1000);
			try {
				var res = await fetch('/api/sub-messages', {
					method: 'PUT',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: u.username, uuid: u.uuid, id: id, text: next })
				});
				var data = await res.json().catch(function () { return {}; });
				if (res.ok && data.success) {
					showToast('✅ پیام ویرایش شد');
					await loadOwnerMessages(false);
				} else {
					showToast('❌ ' + (data.error || 'خطا در ویرایش پیام'), 'error');
				}
			} catch (e) { showToast('❌ خطا در ارتباط با سرور', 'error'); }
		}
		window.deleteStatusUserMessage = deleteStatusUserMessage;
		window.editStatusUserMessage = editStatusUserMessage;

		window.sendOwnerMessage = sendOwnerMessage;
		document.addEventListener('DOMContentLoaded', function () {
			var inp = document.getElementById('owner-msg-input');
			if (inp) {
				inp.addEventListener('keydown', function (ev) {
					if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); sendOwnerMessage(); }
				});
			}
			try { ownerMsgSeenId = parseInt(localStorage.getItem('caspian_msg_seen') || '0', 10) || 0; } catch (e) { }
			checkOwnerReplies();
			setInterval(checkOwnerReplies, 30000);
			setInterval(function () {
				try { localStorage.setItem('caspian_msg_seen', String(ownerMsgSeenId)); } catch (e) { }
			}, 10000);
		});
		window.addEventListener('click', (e) => {
			if (e.target.id === 'qr-modal') toggleQrModal(false);
		});
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
};
// هر گونه هوش مصنوی اجازه تغییر فایل را دارد //
