import { connect } from "cloudflare:sockets";
const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;
const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const TCP_CONCURRENCY = 2;
const PRELOAD_RACE_DIAL = true;
export default {
	async fetch(request, env, ctx) {
		trackRequest(env, ctx);
		await DbService.ensureSchema(env.DB);
		const url = new URL(request.url);
		if (Router.isWebSocketUpgrade(request) && url.pathname === "/") {
			return await Router.handleWebSocket(request, env, ctx);
		}
		if (Router.isSubscriptionPath(url.pathname)) {
			return await Router.handleSubscription(url, env);
		}
		if (url.pathname.startsWith("/api/") || url.pathname === "/locations") {
			return await Router.handleApi(request, url, env, ctx);
		}
		if (url.pathname === "/panel" || url.pathname === "/login") {
			return await Router.handlePanel(request, env);
		}
		if (url.pathname.startsWith("/status/")) {
			return await Router.handleUserStatus(url, env);
		}
		return new Response(HTML_TEMPLATES.nginx, {
			headers: { "Content-Type": "text/html; charset=utf-8" },
		});
	},
};
const Router = {
	isWebSocketUpgrade(request) {
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket";
	},
	isSubscriptionPath(pathname) {
		return pathname.startsWith("/sub/") || pathname.startsWith("/feed/");
	},
	async handleWebSocket(request, env, ctx) {
		try {
			let proxyIP = "proxyip.cmliussss.net";
			let socks5 = "";
			try {
				const proxyRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				if (proxyRow && proxyRow.value) {
					proxyIP = proxyRow.value;
				}
				const socksRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				if (socksRow && socksRow.value) {
					socks5 = socksRow.value;
				}
			} catch (e) {}
			const mockStoredData = { proxy_ip: proxyIP, socks5: socks5 };
			return handleVLESS(env, mockStoredData, ctx, request);
		} catch (e) {
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async handleSubscription(url, env) {
		const isSubPath = url.pathname.startsWith("/sub/");
		const offset = isSubPath ? 5 : 6;
		let subUser = decodeURIComponent(url.pathname.slice(offset));
		const host = url.hostname;
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
			if (!user || user.connection_type !== atob("dmxlc3M=")) {
				return new Response("Not Found", { status: 404 });
			}
			return await SubscriptionService.generateText(user, host);
		} catch (err) {
			return new Response("Error building config: " + err.message, { status: 500 });
		}
	},
	async handlePanel(request, env) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (!hasPassword) {
			return new Response(HTML_TEMPLATES.setup, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(HTML_TEMPLATES.login, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		return new Response(HTML_TEMPLATES.panel, {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	},
	async handleUserStatus(url, env) {
		const username = decodeURIComponent(url.pathname.slice(8));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const userJson = JSON.stringify({
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: user.used_gb,
				limit_req: user.limit_req,
				used_req: user.used_req,
				is_active: user.is_active,
				online_count: getActiveIpCount(user.active_ips),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
			});
			const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson};`);
			return new Response(html, {
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
			const { password } = await request.json();
			if (!password || password.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(password);
			await DbService.setPanelPassword(env.DB, hashed);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const { password } = await request.json();
			const hashedInput = await DbService.sha256(password);
			const storedHash = await DbService.getPanelPassword(env.DB);
			if (storedHash === hashedInput) {
				return new Response(JSON.stringify({ success: true }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + storedHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			}
			return new Response(JSON.stringify({ error: "رمز عبور اشتباه است" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
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
			const { api_token } = await request.json();
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
					return new Response(JSON.stringify({ error: "این توکن متعلق به صاحب پنل نیست (ای کــثـــکـــش)" }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
				cachedPanelPassword = null;
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
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			let currentToken = env.CF_API_TOKEN || body.cf_token;
			let currentAccountId = env.CF_ACCOUNT_ID;

			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}

			try {
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + currentToken },
					});
					const accData = await accRes.json();
					if (!accData.success || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}

				const githubRes = await fetch("https://raw.githubusercontent.com/sepehr-gamer/Zeus-pannel/refs/heads/main/zeus.js?t=" + Date.now() + Math.random(), {
					headers: {
						"Cache-Control": "no-cache, no-store, must-revalidate",
						Pragma: "no-cache",
						Expires: "0",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب");
				const newCode = await githubRes.text();

				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: { Authorization: "Bearer " + currentToken },
				});
				const bindingsData = await bindingsRes.json();
				if (!bindingsData.success) throw new Error("عدم دسترسی به تنظیمات ورکر. توکن نامعتبر است.");

				const newBindings = [];
				for (const b of bindingsData.result) {
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.name === "CF_API_TOKEN") {
						newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
					} else if (b.name === "CF_ACCOUNT_ID") {
						newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
					}
				}

				if (!newBindings.some((b) => b.name === "CF_API_TOKEN")) {
					newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				}
				if (!newBindings.some((b) => b.name === "CF_ACCOUNT_ID")) {
					newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				}

				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2024-02-08",
					bindings: newBindings,
				};

				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");

				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: { Authorization: "Bearer " + currentToken },
					body: formData,
				});
				const deployData = await deployRes.json();
				if (!deployData.success) throw new Error("خطا در اعمال آپدیت در کلودفلر.");

				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				const errorMsg = err.message + " | در صورت عدم موفقیت، از طریق لینک زیر آپدیت کنید: https://zeus-panel.ir-netlify.workers.dev/";
				return new Response(JSON.stringify({ error: errorMsg }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			let currentToken = env.CF_API_TOKEN;
			let currentAccountId = env.CF_ACCOUNT_ID;

			if (!currentToken || !currentAccountId) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}

			try {
				const githubRes = await fetch("https://raw.githubusercontent.com/sepehr-gamer/Zeus-pannel/refs/heads/main/zeus.js?t=" + Date.now(), {
					headers: {
						"Cache-Control": "no-cache, no-store, must-revalidate",
						Pragma: "no-cache",
						Expires: "0",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس از گیت‌هاب");
				const newCode = await githubRes.text();

				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: { Authorization: "Bearer " + currentToken },
				});
				const bindingsData = await bindingsRes.json();
				if (!bindingsData.success) throw new Error("عدم دسترسی به تنظیمات ورکر");

				const newBindings = [];
				for (const b of bindingsData.result) {
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					}
				}

				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });

				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2024-02-08",
					bindings: newBindings,
				};

				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");

				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: { Authorization: "Bearer " + currentToken },
					body: formData,
				});
				const deployData = await deployRes.json();
				if (!deployData.success) throw new Error("خطا در اعمال ری‌استارت در کلودفلر");

				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password } = await request.json();
			if (!current_password || !new_password) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی و جدید الزامی هستند" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const currentHash = await DbService.sha256(current_password);
			const storedHash = await DbService.getPanelPassword(env.DB);
			if (storedHash && storedHash !== currentHash) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (new_password.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(new_password);
			await DbService.setPanelPassword(env.DB, newHash);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/locations") {
			try {
				const response = await fetch("https://speed.cloudflare.com/locations", {
					headers: { Referer: "https://speed.cloudflare.com/" },
				});
				const data = await response.json();
				return new Response(JSON.stringify(data), {
					headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach(r => { settingsObj[r.key] = r.value; });
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
			}
			if (request.method === "POST") {
				const body = await request.json();
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
				const { proxy_ip, iata, socks5 } = await request.json();
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
						proxy_ip: rowIp ? rowIp.value : "proxyip.cmliussss.net",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : ""
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const { proxy } = await request.json();
			if (!proxy) return new Response(JSON.stringify({ error: "پروکسی وارد نشده است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			try {
				let ip = "";
				let workingProxy = proxy;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = proxy.match(/server=([^&]+)/)?.[1] || "";
				} else {
					let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, '');
					let remain = cleanProxy;
					if (remain.includes('@')) remain = remain.substring(remain.lastIndexOf('@') + 1);
					if (remain.startsWith('[')) {
						ip = remain.substring(1, remain.indexOf(']'));
					} else {
						const lastColon = remain.lastIndexOf(':');
						if (lastColon !== -1 && remain.indexOf(':') === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
				}
				let country = "UN";
				if (ip) {
					try {
						const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
						const geoData = await geoRes.json();
						if (geoData && geoData.countryCode) country = geoData.countryCode;
					} catch (e) {}
				}
				const startTime = Date.now();
				const payload = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
				const s = await connectProxy(proxy, "1.1.1.1", 80, payload);
				const reader = s.readable.getReader();
				const res = await reader.read();
				if (res.done || !res.value) {
					s.close();
					throw new Error("تایم‌اوت در دریافت دیتا");
				}
				s.close();
				const ping = Date.now() - startTime;
				return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				let msg = e.message;
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "ارتباط با سرور قطع شد (احتمالاً پروکسی مسدود یا خاموش است)";
				else if (msg.includes("timeout") || msg.includes("timed out") || msg.includes("تایم‌اوت")) msg = "تایم‌اوت در اتصال (پروکسی در دسترس نیست)";
				else if (msg.includes("Invalid URL") || msg.includes("Invalid format")) msg = "فرمت وارد شده برای پروکسی اشتباه است";
				else if (msg === "err") msg = "خطای نامشخص (ارتباط برقرار نشد)";
				return new Response(JSON.stringify({ error: msg }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname.startsWith("/api/users")) {
			const pathParts = url.pathname.split("/");
			const isUserAction = pathParts.length > 3;
			if (isUserAction) {
				const username = decodeURIComponent(pathParts.pop());
				if (request.method === "PUT") {
					const body = await request.json();
					if (body.toggle_only !== undefined) {
						await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else if (body.reset_action !== undefined) {
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0 WHERE username = ?").bind(username).run();
							GLOBAL_TRAFFIC_CACHE.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0 WHERE username = ?").bind(username).run();
							USER_REQ_CACHE.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE username = ?").bind(username).run();
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip } = body;
						if (new_username && new_username !== username) {
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(new_username).first();
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
						await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ? WHERE username = ?")
							.bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, username)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) {}
					const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
					const now = Date.now();
					const enrichedUsers = (results || []).map((user) => ({
						...user,
						is_online: user.last_active && now - user.last_active < 25000 ? 1 : 0,
						online_count: getActiveIpCount(user.active_ips),
					}));
					let cfReqs = { today: 0, total: 0 };
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
					} catch (e) {}
					return new Response(
						JSON.stringify({
							users: enrichedUsers,
							serverTime: now,
							cfRequestsToday: cfReqs.today,
							cfRequestsTotal: cfReqs.total,
						}),
						{
							headers: {
								"Content-Type": "application/json",
								"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
							},
						},
					);
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip } = await request.json();
					if (!username) {
						return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 32) {
						return new Response(JSON.stringify({ error: "نام کاربری نمی‌تواند بیشتر از ۳۲ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					const finalUuid = uuid || crypto.randomUUID();
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					try {
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, atob("dmxlc3M="), tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null)
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
let cachedPanelPassword = null;
const DbService = {
	async ensureSchema(db) {
		if (schemaEnsured) return;
		try {
			await db
				.prepare(
					`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          uuid TEXT,
          limit_gb REAL,
          expiry_days INTEGER,
          ips TEXT,
          connection_type TEXT,
          tls TEXT,
          port INTEGER,
          used_gb REAL DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          last_active INTEGER,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `,
				)
				.run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN last_active INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN fingerprint TEXT DEFAULT 'chrome'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN max_connections INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN limit_req INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN used_req INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN ip_limit INTEGER DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN active_ips TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN block_porn INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN block_ads INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN frag_len TEXT DEFAULT '200-3000'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN frag_int TEXT DEFAULT '1-2'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN lifetime_used_gb REAL DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN user_proxy_ip TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN user_proxy_iata TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN user_socks5 TEXT DEFAULT NULL").run();
		} catch (e) {}
		schemaEnsured = true;
	},
	async getPanelPassword(db) {
		if (cachedPanelPassword !== null) return cachedPanelPassword;
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row ? row.value : "";
			return cachedPanelPassword || null;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async verifyApiAuth(request, env) {
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		if (!storedPasswordHash) return true;
		const cookies = request.headers.get("Cookie") || "";
		const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
		if (!sessionCookie) return false;
		const sessionToken = sessionCookie.split("=")[1].trim();
		return sessionToken === storedPasswordHash;
	},
	async sha256(message) {
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
			if (now - lastSeen <= 30000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
const SubscriptionService = {
	async generateText(user, host) {
		let ips = [host];
		if (user.ips) {
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
		links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + host + ":80?path=/&security=none&encryption=none&host=" + host + "&fp=" + fp + "&type=ws#" + encodeURIComponent(infoRemark));
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
				const tlsVal = isTlsPort ? "tls" : "none";
				const userFrag = user.frag_len && user.frag_int ? "&fragment=" + user.frag_len + "," + user.frag_int : "";
				const remark = user.username;
				links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + ip + ":" + portStr + "?path=/&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + userFrag + "#" + encodeURIComponent(remark));
			});
		});
		const noise = ["# System Update Feed: OK", "# Sync Code: " + Math.random().toString(36).slice(2, 10), "# Version: 2.10.1", "# Description: Secure Node Configurations", ""].join("\n");
		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));
		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days && user.created_at) {
			expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
			},
		});
	},
};
async function flushExpiredTraffic(env) {
	const now = Date.now();
	for (const [uname, cachedBytes] of GLOBAL_TRAFFIC_CACHE.entries()) {
		const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) continue;
		if (GLOBAL_WRITE_LOCK.get(uname)) continue;
		const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
		const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 25000) {
			GLOBAL_WRITE_LOCK.set(uname, true);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
			} catch (e) {
				console.error(e.message);
			} finally {
				GLOBAL_WRITE_LOCK.delete(uname);
				GLOBAL_TRAFFIC_CACHE.delete(uname);
				USER_REQ_CACHE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		}
	}
}
async function handleVLESS(env, storedData = null, ctx = null, request = null) {
	const clientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	let username = null;
	let tickCount = 0;
	let validUUID = null;
	let userIpLimit = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
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
		let thresholdBytes = 10 * 1024 * 1024;
		if (current >= thresholdBytes || (current > 0 && now - lastDbWrite > 60000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, 0);
			USER_REQ_CACHE.set(username, 0);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, username).run();
				} catch (e) {
					console.error(e.message);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		if (clientIP && clientIP !== "unknown" && validUUID) {
			const removeIpTask = async () => {
				try {
					const user = await env.DB.prepare("SELECT active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						console.log(`[setOffline Task] DB active_ips for ${uname}: ${user.active_ips}`);
						let activeIps = JSON.parse(user.active_ips || "{}");
						if (activeIps[clientIP]) {
							if (typeof activeIps[clientIP] === "object") {
								activeIps[clientIP].count = (activeIps[clientIP].count || 1) - 1;
								if (activeIps[clientIP].count <= 0) {
									delete activeIps[clientIP];
								}
							} else {
								delete activeIps[clientIP];
							}
							await env.DB.prepare("UPDATE users SET active_ips = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), validUUID).run();
							console.log(`[setOffline Task] Updated active_ips in DB to: ${JSON.stringify(activeIps)}`);
						} else {
							console.log(`[setOffline Task] IP ${clientIP} not found in user's active_ips`);
						}
					}
				} catch (e) {
					console.error(`[setOffline Task] Error: ${e.message}`);
				}
			};
			if (ctx) ctx.waitUntil(removeIpTask());
			else removeIpTask();
		}
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 1;
		activeCount = activeCount - 1;
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			if ((cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
					} catch (e) {
						console.error(e.message);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_TRAFFIC_CACHE.delete(uname);
						USER_REQ_CACHE.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_TRAFFIC_CACHE.delete(uname);
				USER_REQ_CACHE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
				GLOBAL_WRITE_LOCK.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	const heartbeat = setInterval(async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID) return;
				tickCount++;
				if (tickCount >= 1) {
					tickCount = 0;
					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						userIpLimit = user.ip_limit;
					}
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						if (user.limit_gb && user.used_gb >= user.limit_gb) {
							isExpired = true;
						}
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) {
							isExpired = true;
						}
						if (user.expiry_days && user.created_at) {
							const created = new Date(user.created_at);
							const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
							if (new Date() > expiryDate) {
								isExpired = true;
							}
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try {
								activeIps = JSON.parse(user.active_ips || "{}");
							} catch (e) {}
							const nowTime = Date.now();
							let hasChanges = false;
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 30000) {
									delete activeIps[ip];
									hasChanges = true;
								}
							}
							if (!activeIps[clientIP]) {
								isIpLimitExpired = true;
								console.log(`[Heartbeat] IP ${clientIP} expired from active_ips due to inactivity.`);
							} else {
								const sortedIps = Object.keys(activeIps).sort((a, b) => {
									const tA = activeIps[a] && typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
									const tB = activeIps[b] && typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
									return tB - tA;
								});
								const clientIpIndex = sortedIps.indexOf(clientIP);
								if (user.ip_limit && user.ip_limit > 0 && clientIpIndex >= user.ip_limit) {
									isIpLimitExpired = true;
									console.log(`[Heartbeat] IP Limit Exceeded. Client IP index ${clientIpIndex} >= limit ${user.ip_limit}.`);
								}
							}
							if (hasChanges || isIpLimitExpired) {
								updatedActiveIps = JSON.stringify(activeIps);
							}
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearInterval(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						console.log(`[Heartbeat] Terminating socket for user ${username}.`);
						clearInterval(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					const now = Date.now();
					const lastRecorded = GLOBAL_LAST_ACTIVE_WRITE.get(username) || 0;
					if (now - lastRecorded > 120000 || updatedActiveIps !== null) {
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						if (updatedActiveIps !== null) {
							await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(now, updatedActiveIps, username).run();
						} else {
							await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
						}
					}
				}
			} catch (e) {}
		} else {
			clearInterval(heartbeat);
		}
	}, 120000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	const proxyIP = storedData?.proxy_ip || "proxyip.cmliussss.net";
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
			} catch (e) {}
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
			} catch (e) {}
			closeSocketQuietly(serverSock);
		},
		name: "VlessWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		await addBytes(bytes);
		if (isDnsQuery) {
			await forwardVlessUDP(chunk, serverSock, null, addBytes, targetDns);
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			if (chunkBuffer.byteLength < 24) return;
			if (isHeaderParsing) return;
			isHeaderParsing = true;
			reqUUID = extractUUIDFromVless(chunkBuffer);
			if (!reqUUID) {
				serverSock.close();
				return;
			}
			let user = null;
			try {
				user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(reqUUID).first();
			} catch (e) {}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (!user || user.is_active === 0) {
				serverSock.close();
				return;
			}
			if (user.limit_gb && user.used_gb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(user.username) || 0) >= user.limit_req) {
				serverSock.close();
				return;
			}
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				if (new Date() > expiryDate) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) {}
					serverSock.close();
					return;
				}
			}
			userIpLimit = user.ip_limit;
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
				console.log(`[VLESS Handshake] User: ${user.username}, clientIP: ${clientIP}, active_ips in DB: ${user.active_ips}`);
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) {}
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 30000) {
						delete activeIps[ip];
					}
				}
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps).sort((a, b) => {
						const tA = activeIps[a] && typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
						const tB = activeIps[b] && typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
						return tB - tA;
					});
					console.log(`[VLESS Handshake] Non-expired active IPs: ${JSON.stringify(activeIps)}, count: ${sortedIps.length}, limit: ${user.ip_limit}`);
					if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) {
						console.log(`[VLESS Handshake] BLOCKED user ${user.username} because sortedIps.length (${sortedIps.length}) >= limit (${user.ip_limit})`);
						serverSock.close();
						return;
					}
					activeIps[clientIP] = { timestamp: now, count: 1 };
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
					console.log(`[VLESS Handshake] Reconnected from same IP: ${clientIP}, count: ${activeIps[clientIP].count}`);
				}
				try {
					await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
					console.log(`[VLESS Handshake] Successfully updated active_ips to: ${JSON.stringify(activeIps)}`);
				} catch (e) {
					console.error(`[VLESS Handshake] DB Update Error: ${e.message}`);
				}
			}
			validUUID = reqUUID;
			username = user.username;
			isHeaderParsed = true;
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
			ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
			if (activeCount === 0) {
				const setOnlineTask = async () => {
					try {
						const now = Date.now();
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
					} catch (e) {}
				};
				if (ctx) ctx.waitUntil(setOnlineTask());
				else setOnlineTask();
			}
			try {
				let offset = 17;
				const optLen = chunkBuffer[offset++];
				offset += optLen;
				const cmd = chunkBuffer[offset++];
				const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
				const addrType = chunkBuffer[offset++];
				let addr = "";
				if (addrType === 1) {
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (addrType === 2) {
					const domainLen = chunkBuffer[offset++];
					addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (addrType === 3) {
					const v6 = [];
					for(let i=0; i<8; i++) {
						v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
					}
					addr = v6.join(":");
				}
				const rawData = chunkBuffer.slice(offset);
				const respHeader = new Uint8Array([chunkBuffer[0], 0]);
				if (cmd === 2) {
					if (port === 53) {
						isDnsQuery = true;
						await forwardVlessUDP(rawData, serverSock, respHeader, addBytes, targetDns);
					} else {
						serverSock.close();
					}
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
						const socks5 = user?.user_socks5 || "";
						
						if (socks5) {
							s = await connectProxy(socks5, addr, port, dataPayload);
						} else {
							let activeProxyIP = "";
							if (user?.user_proxy_iata) {
								activeProxyIP = user.user_proxy_iata.toLowerCase() + ".proxyip.cmliussss.net";
							} else if (user?.user_proxy_ip) {
								activeProxyIP = user.user_proxy_ip;
							}

							let fHost = activeProxyIP;
							let fPort = port;
							if (activeProxyIP) {
								if (activeProxyIP.startsWith("[")) {
									const closeIdx = activeProxyIP.indexOf("]");
									if (closeIdx !== -1) {
										fHost = activeProxyIP.substring(1, closeIdx);
										if (activeProxyIP.length > closeIdx + 1 && activeProxyIP[closeIdx + 1] === ":") {
											fPort = parseInt(activeProxyIP.substring(closeIdx + 2)) || port;
										}
									}
								} else {
									const lastColon = activeProxyIP.lastIndexOf(":");
									if (lastColon !== -1 && activeProxyIP.indexOf(":") === lastColon) {
										fHost = activeProxyIP.substring(0, lastColon);
										fPort = parseInt(activeProxyIP.substring(lastColon + 1)) || port;
									} else {
										fHost = activeProxyIP;
									}
								}
							}
							const isCustomProxy = activeProxyIP && activeProxyIP !== "proxyip.cmliussss.net";

							if (isCustomProxy) {
								try {
									s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
								} catch (err) {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								}
							} else {
								try {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								} catch (err) {
									if (useFallback && activeProxyIP) {
										s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
									} else {
										throw err;
									}
								}
							}
						}
						remoteConnWrapper.socket = s;
						s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
						connectStreams(s, serverSock, respHeader, null, (b) => {
							addBytes(b);
						});
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
		clearInterval(heartbeat);
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
async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0 };
	try {
		const now = new Date();
		const startOfDay = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()).toISOString();
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
        }
      }
    }`;
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
		});
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		return { today: todayReqs, total: totalReqs };
	} catch (e) {
		return { today: 0, total: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function stripIPv6Brackets(hostname = "") {
	const host = String(hostname || "").trim();
	return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = "") {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(":")) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	const chunks = chunkList.map(convertToUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
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
	} catch (e) {}
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
				const enc = new TextEncoder().encode(label);
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
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
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
			for (;;) {
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
					await new Promise((resolve) => setTimeout(resolve, 0));
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
		} finally {
			draining = false;
			if (!closed && head < chunks.length) setTimeout(drain, 0);
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
			} catch (_) {}
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
		if (!draining) setTimeout(drain, 0);
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
	const packetCap = DOWNSTREAM_GRAIN_BYTES;
	const tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
	const lowWaterBytes = Math.max(4096, tailBytes << 3);
	let header = headerData;
	let pendingBuffer = new Uint8Array(packetCap);
	let pendingBytes = 0;
	let flushTimer = null;
	let taskQueued = false;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
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
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		taskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap);
		pendingBytes = 0;
		waitRounds = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	const scheduleFlush = () => {
		if (flushTimer || taskQueued) return;
		taskQueued = true;
		scheduledGeneration = generation;
		setTimeout(() => {
			taskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) {
				flush().catch(() => closeSocketQuietly(webSocket));
				return;
			}
			flushTimer = setTimeout(
				() => {
					flushTimer = null;
					if (!pendingBytes) return;
					if (packetCap - pendingBytes < tailBytes) {
						flush().catch(() => closeSocketQuietly(webSocket));
						return;
					}
					if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
						waitRounds++;
						scheduledGeneration = generation;
						scheduleFlush();
						return;
					}
					flush().catch(() => closeSocketQuietly(webSocket));
				},
				Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1),
			);
		}, 0);
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
				if (!pendingBytes && totalBytes - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					continue;
				}
				const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				generation++;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
				else scheduleFlush();
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		let maxAttempts = 150;
		while (ws.bufferedAmount > 256 * 1024 && maxAttempts > 0) {
			if (ws.readyState !== WebSocket.OPEN) break;
			await new Promise((r) => setTimeout(r, 20));
			maxAttempts--;
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
	let header = headerData,
		hasData = false,
		reader,
		useBYOB = false;
	const BYOB_LIMIT = 64 * 1024;
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		reader = remoteSocket.readable.getReader({ mode: "byob" });
		useBYOB = true;
	} catch (e) {
		reader = remoteSocket.readable.getReader();
	}
	try {
		if (!useBYOB) {
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				await downstreamSender.send(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB_LIMIT);
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
					await downstreamSender.flush();
					await downstreamSender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOB_LIMIT);
				} else {
					await downstreamSender.send(value);
					readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
				}
			}
		}
		await downstreamSender.flush();
	} catch (err) {
		closeSocketQuietly(webSocket);
	} finally {
		try {
			reader.cancel();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function buildRaceCandidates(address, port, targetDoh) {
	if (!PRELOAD_RACE_DIAL || isIPHostname(address)) return null;
	const [aRecords, aaaaRecords] = await Promise.all([dohQuery(address, "A", targetDoh), dohQuery(address, "AAAA", targetDoh)]);
	const ipv4List = [
		...new Set(
			aRecords.flatMap((r) => {
				return r.type === 1 && typeof r.data === "string" && isIPv4(r.data) ? [r.data] : [];
			}),
		),
	];
	const ipv6List = [
		...new Set(
			aaaaRecords.flatMap((r) => {
				return r.type === 28 && typeof r.data === "string" && isIPHostname(r.data) ? [r.data] : [];
			}),
		),
	];
	const limit = Math.max(1, TCP_CONCURRENCY | 0);
	const ipList = ipv4List.length >= limit ? ipv4List.slice(0, limit) : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
	if (ipList.length === 0) return null;
	return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const raceCandidates = await buildRaceCandidates(address, port, targetDoh);
	const candidates = raceCandidates || Array.from({ length: TCP_CONCURRENCY }, () => ({ hostname: address, port }));
	const openConnection = async (host, prt) => {
		const socket = connect({ hostname: host, port: prt });
		await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1000))]);
		return socket;
	};
	if (candidates.length === 1) {
		const s = await openConnection(candidates[0].hostname, candidates[0].port);
		if (initialData && initialData.byteLength > 0) {
			const w = s.writable.getWriter();
			await w.write(convertToUint8Array(initialData));
			w.releaseLock();
		}
		return s;
	}
	const attempts = candidates.map((c) => openConnection(c.hostname, c.port).then((socket) => ({ socket, candidate: c })));
	let winner = null;
	try {
		winner = await Promise.any(attempts);
		if (initialData && initialData.byteLength > 0) {
			const w = winner.socket.writable.getWriter();
			await w.write(convertToUint8Array(initialData));
			w.releaseLock();
		}
		return winner.socket;
	} finally {
		if (winner) {
			for (const attempt of attempts) {
				attempt
					.then(({ socket }) => {
						if (socket !== winner.socket) {
							try {
								socket.close();
							} catch (e) {}
						}
					})
					.catch(() => {});
			}
		}
	}
}
async function forwardVlessUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	const requestData = convertToUint8Array(udpChunk);
	try {
		const tcpSocket = connect({ hostname: dnsServer, port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(
			new WritableStream({
				async write(chunk) {
					const response = convertToUint8Array(chunk);
					if (typeof onBytes === "function") onBytes(response.byteLength);
					if (webSocket.readyState !== WebSocket.OPEN) return;
					if (vlessHeader) {
						const merged = new Uint8Array(vlessHeader.length + response.byteLength);
						merged.set(vlessHeader, 0);
						merged.set(response, vlessHeader.length);
						webSocket.send(merged.buffer);
						vlessHeader = null;
					} else {
						webSocket.send(response);
					}
				},
			}),
		);
	} catch (e) {}
}
function extractUUIDFromVless(data) {
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
			} catch (e) {}
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

	const isHttp = normalized.toLowerCase().startsWith('http://') || normalized.toLowerCase().startsWith('https://');
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, '');
	
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	return await connectSocks5(cleanStr, destAddr, destPort, initialData);
}

async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	let user = "", pass = "", host = "", port = 1080;
	let auth = false;
	let remain = socksStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx); pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") {
				port = parseInt(remain.substring(closeIdx + 2)) || 1080;
			}
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon); port = parseInt(remain.substring(lastColon + 1)) || 1080;
		} else {
			host = remain;
		}
	}

	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();

	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}

		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پروکسی SOCKS5 نیست یا خاموش است)");

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
			let authRes = await reader.read();
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پروکسی اشتباه است");
		}

		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split('.').map(Number));
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xFF;
		req[portOffset + 1] = destPort & 0xFF;

		await writer.write(req);
		let connRes = await reader.read();
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("پروکسی وصل شد اما دسترسی به اینترنت آزاد ندارد");

		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch(err){}
		try { reader.releaseLock(); } catch(err){}
		try { socket.close(); } catch(err){}
		throw e;
	}
}

async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	let user = "", pass = "", host = "", port = 80;
	let auth = false;
	let remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx); pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") {
				port = parseInt(remain.substring(closeIdx + 2)) || 80;
			}
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon); port = parseInt(remain.substring(lastColon + 1)) || 80;
		} else {
			host = remain;
		}
	}

	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();

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
		while (true) {
			const res = await reader.read();
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += new TextDecoder().decode(res.value, { stream: true });
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
		try { writer.releaseLock(); } catch(err){}
		try { reader.releaseLock(); } catch(err){}
		try { socket.close(); } catch(err){}
		throw e;
	}
}

const HTML_TEMPLATES = {
	nginx: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>دسترسی به پنل</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl p-8 text-center flex flex-col items-center gap-4">
        <div class="p-4 bg-blue-50 dark:bg-blue-900/20 text-blue-500 rounded-full mb-2">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <h2 class="text-xl font-bold text-gray-900 dark:text-white">ورود به پنل مدیریت</h2>
        <p class="text-sm text-gray-600 dark:text-gray-400 leading-relaxed mt-2">
            برای ورود به پنل، لطفاً عبارت 
            <span class="inline-block px-2 py-1 bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-zinc-800 rounded-md font-mono text-blue-500 font-bold mx-1 shadow-sm" dir="ltr">/panel</span> 
            را به انتهای آدرس مرورگر خود اضافه کنید.
        </p>
        <button onclick="window.location.href='/panel'" class="mt-4 w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-xl text-sm transition-colors duration-200 shadow-lg font-bold">
            ورود به پنل
        </button>
    </div>
</body>
</html>`,
	setup: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تعریف رمز عبور پنل</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl p-6">
        <h2 class="text-xl font-bold mb-2 text-center text-blue-600 dark:text-blue-400">تنظیم رمز عبور جدید</h2>
        <p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-6">این اولین ورود شما به پنل مدیریت است. لطفاً رمز عبور خود را تعیین کنید.</p>
        <form onsubmit="handleSetup(event)" class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1.5">رمز عبور</label>
                <input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
            </div>
            <div>
                <label class="block text-sm font-medium mb-1.5">تکرار رمز عبور</label>
                <input type="password" id="confirm-password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
            </div>
            <button type="submit" id="submit-btn" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-lg text-sm transition font-bold">ثبت و ورود</button>
        </form>
    </div>
    <div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>
    <script>
        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            const colors = type === 'error' 
                ? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
                : 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
            toast.className = 'px-4 py-3 border rounded-xl shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
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
            const msgStr = message ? message.toString() : '';
            if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
                showToast(msgStr, 'error');
            } else {
                showToast(msgStr, 'success');
            }
        };

        async function handleSetup(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
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
</body>
</html>`,

	login: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به پنل مدیریت</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl p-6">
        <div id="login-section">
            <h2 class="text-xl font-bold mb-6 text-center text-blue-600 dark:text-blue-400">ورود به پنل مدیریت</h2>
            <form onsubmit="handleLogin(event)" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-1.5">رمز عبور</label>
                    <input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required>
                </div>
                <button type="submit" id="submit-btn" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-lg text-sm transition font-bold">ورود</button>
            </form>
            <div class="mt-4 text-center">
                <button onclick="toggleRecovery(true)" class="text-xs text-blue-500 hover:text-blue-600 transition font-medium">بازیابی رمز پنل</button>
            </div>
        </div>
        <div id="recovery-section" class="hidden">
            <h2 class="text-xl font-bold mb-4 text-center text-orange-600 dark:text-orange-400">بازیابی رمز پنل</h2>
            
            <div class="mb-5 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800/50 rounded-xl text-xs leading-relaxed text-orange-800 dark:text-orange-300">
                برای احراز هویت و اثبات مالکیت پنل، از طریق دکمه زیر وارد کلودفلر شوید و توکن دریافتی را کپی کرده و در کادر زیر وارد کنید.
                <a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Zeus-Deployer-Token" target="_blank" class="mt-3 w-full flex items-center justify-center gap-2 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 rounded-lg font-bold transition shadow-md">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                    دریافت توکن
                </a>
            </div>

            <form onsubmit="handleRecovery(event)" class="space-y-4">
                <div>
                    <input type="password" id="api-token" placeholder="توکن را وارد کنید" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-orange-500 text-xs text-center font-mono" required>
                </div>
                <div class="flex gap-2 pt-2">
                    <button type="button" onclick="toggleRecovery(false)" class="w-1/3 py-2.5 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-lg text-sm transition shadow-sm">انصراف</button>
                    <button type="submit" id="recover-btn" class="w-2/3 py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-lg text-sm transition font-bold">بازیابی رمز پنل</button>
                </div>
            </form>
        </div>
    </div>
    <div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>
    <script>
        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            const colors = type === 'error' 
                ? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
                : 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
            toast.className = 'px-4 py-3 border rounded-xl shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
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
            const msgStr = message ? message.toString() : '';
            if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
                showToast(msgStr, 'error');
            } else {
                showToast(msgStr, 'success');
            }
        };

        async function handleLogin(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
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
                    alert('❌ رمز عبور اشتباه است');
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
                btn.innerText = 'بازیابی رمز پنل';
            }
        }
    </script>
</body>
</html>`,

	panel: `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caspian Panel</title>
    <script>
        const originalWarn = console.warn;
        console.warn = (...args) => {
            if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
            originalWarn(...args);
        };
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Vazirmatn', sans-serif; }
		.dark input[type="checkbox"] {
            filter: invert(1) hue-rotate(180deg);
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
        .dark ::-webkit-scrollbar-track {
            background: #080b0f; 
        }
        .dark ::-webkit-scrollbar-thumb {
            background: #1c2330; 
        }
        .dark ::-webkit-scrollbar-thumb:hover {
            background: #2d3748;
        }
        * {
            scrollbar-width: thin;
            scrollbar-color: #d1d5db #f3f4f6;
        }
        .dark * {
            scrollbar-color: #1c2330 #080b0f;
        }
    </style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen transition-colors duration-200">
    <header class="border-b border-gray-200 dark:border-amoled-border bg-white dark:bg-amoled-card px-4 py-4">
        <div class="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
            <div class="flex flex-row flex-wrap justify-center items-center gap-3 w-full md:w-auto">
                <h1 class="text-lg font-bold flex items-center gap-2" dir="ltr">
                    Caspian Panel 
                    <span id="panel-version" class="text-xs px-2 py-0.5 font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 rounded-full">v1.5.10</span>
                </h1>
                 <div class="flex items-center gap-3 bg-gray-100 dark:bg-zinc-800/60 px-3 py-1.5 rounded-full border border-gray-200 dark:border-zinc-800/80 shadow-sm flex-shrink-0 w-fit">
                    <a href="https://github.com/sepehr-gamer/Zeus-pannel" target="_blank" rel="noopener noreferrer" class="text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 transition-all transform hover:scale-125 duration-200 flex-shrink-0" title="GitHub">
                        <svg class="w-[22px] h-[22px] flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
                        </svg>
                    </a>
                    <a href="https://t.me/PV_Golestaneh" target="_blank" rel="noopener noreferrer" class="text-sky-500 hover:text-sky-600 dark:hover:text-sky-400 transition-all transform hover:scale-125 duration-200 flex-shrink-0" title="Telegram">
                        <svg class="w-[22px] h-[22px] flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/>
                        </svg>
                    </a>
                </div>
            </div>
            <div class="flex items-center justify-center gap-3 w-full md:w-auto mt-2 md:mt-0">
			
				<button onclick="restartCore()" 
                        class="p-2 rounded-lg 
                               bg-blue-50 dark:bg-blue-950/30 
                               border border-blue-200 dark:border-blue-900 
                               hover:bg-blue-100 dark:hover:bg-blue-900/50 
                               transition-all duration-200 
                               text-blue-600 dark:text-blue-400 shadow-sm" 
                        title="ری استارت پنل">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                    </svg>
                </button>
				
                <button id="theme-toggle" 
                        class="p-2 rounded-lg 
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
                        class="p-2 rounded-lg 
                               bg-green-50 dark:bg-green-950/30 
                               border border-green-200 dark:border-green-900 
                               hover:bg-green-100 dark:hover:bg-green-900/50 
                               transition-all duration-200 
                               text-green-700 dark:text-green-500 
                               relative shadow-sm" 
                        title="آپدیت">
                    
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 11l3-3m0 0l3 3m-3-3v8m0-13a9 9 0 110 18 9 9 0 010-18z"></path>
                    </svg>
                    <span id="update-badge" class="absolute top-0 right-0 w-2.5 h-2.5 bg-red-500 border-2 border-green-50 dark:border-green-900 rounded-full hidden animate-pulse"></span>
                </button>
                
                <button onclick="toggleSettingsModal(true)" 
                        class="p-2 rounded-lg 
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
				
                <button 
                    onclick="logoutAdmin()" 
                    class="p-2 rounded-lg 
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
    <main class="max-w-6xl mx-auto px-4 py-8 pb-56 md:pb-32">
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5 mb-8">
    <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm flex flex-col justify-between hover:shadow-md hover:border-indigo-400 dark:hover:border-indigo-500/50 transition duration-300 relative overflow-hidden group">
        <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-indigo-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
        <div class="flex items-center justify-between relative z-10 mb-2">
            <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">تعداد کل کاربران</span>
            <div class="p-2 bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400 rounded-xl flex-shrink-0">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
            </div>
        </div>
        <div class="space-y-1.5 relative z-10 min-w-0 flex-1">
            <div class="text-2xl font-black text-gray-900 dark:text-zinc-100 transition-all" id="stat-total-users">0</div>
            <span class="text-[11px] text-indigo-500 dark:text-indigo-400 flex items-center gap-1 font-medium whitespace-nowrap">
                <span class="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-ping"></span>
                کل کاربران تعریف شده
            </span>
        </div>
    </div>
    <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm flex flex-col justify-between hover:shadow-md hover:border-emerald-400 dark:hover:border-emerald-500/50 transition duration-300 relative overflow-hidden group">
        <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-emerald-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
        <div class="flex items-center justify-between relative z-10 mb-2">
            <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">کاربران فعال (آنلاین)</span>
            <div class="p-2 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400 rounded-xl flex-shrink-0">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
            </div>
        </div>
        <div class="space-y-1.5 relative z-10 min-w-0 flex-1">
            <div class="text-2xl font-black text-emerald-600 dark:text-emerald-400 transition-all" id="stat-active-users">0</div>
            <span class="text-[11px] text-emerald-500 dark:text-emerald-400 flex items-center gap-1 font-medium whitespace-nowrap">
                <span class="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                متصل در این لحظه
            </span>
        </div>
    </div>
	<div id="card-cf-requests" class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm flex flex-col justify-between hover:shadow-md hover:border-orange-400 dark:hover:border-orange-500/50 transition duration-300 relative overflow-hidden group">
	    <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-orange-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
	    <div class="flex items-center justify-between relative z-10 mb-2">
	        <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">ریکوئست‌های روزانه</span>
	        <div class="p-2 bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 rounded-xl flex-shrink-0">
	            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
	        </div>
	    </div>
	    <div class="space-y-2 relative z-10 min-w-0 flex-1">
	        <div class="flex items-center gap-1">
	            <span class="text-2xl font-black text-orange-600 dark:text-orange-400 transition-all" id="stat-cf-requests">0</span>
	            <span class="text-xs font-bold text-gray-400 mr-1">/ 100k</span>
	            <button id="cf-warning-btn" onclick="openUsageWarning()" class="hidden flex items-center justify-center w-5 h-5 bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 rounded-full font-bold text-xs animate-bounce shadow-sm border border-red-300 dark:border-red-700 mr-2">!</button>
	        </div>
	        <div class="w-full bg-gray-100 dark:bg-zinc-800 rounded-full h-1.5 mt-1">
	            <div id="stat-cf-progress" class="bg-orange-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
	        </div>
	        <span class="text-[11px] text-orange-500 dark:text-orange-400 flex items-center justify-between font-medium whitespace-nowrap mt-1">
	            <span>Total: <span id="stat-cf-total">0</span></span>
	            <span dir="ltr">Cloudflare</span>
	        </span>
	    </div>
	</div>
    <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm flex flex-col justify-between hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500/50 transition duration-300 relative overflow-hidden group">
        <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-blue-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
        <div class="flex items-center justify-between relative z-10 mb-2">
            <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">حجم مصرفی (۳۰ روز)</span>
            <div class="p-2 bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 rounded-xl flex-shrink-0">
               <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
</svg>
            </div>
        </div>
        <div class="space-y-1.5 relative z-10 min-w-0 flex-1">
            <div class="text-2xl font-black text-blue-600 dark:text-blue-400 transition-all whitespace-nowrap" id="stat-total-usage">0 GB</div>
            <span class="text-[11px] text-blue-500 dark:text-blue-400 flex items-center gap-1 font-medium whitespace-nowrap">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"></path></svg>
                مصرف کل کاربران
            </span>
        </div>
    </div>
    <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm flex flex-col justify-between hover:shadow-md hover:border-amber-400 dark:hover:border-amber-500/50 transition duration-300 relative overflow-hidden group">
        <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-amber-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
        <div class="flex items-center justify-between relative z-10 mb-2">
            <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap">پر مصرف‌ترین کاربر</span>
            <div class="p-2 bg-amber-50 dark:bg-amber-950/30 text-amber-600 dark:text-amber-400 rounded-xl flex-shrink-0">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <!-- تاج -->
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 3L9 8l-3-2 2 5H4l2-4-2-3 5 1 3-3 3 3 5-1-2 3 2 4h-4l2-5-3 2-3-5z" />
    <!-- نمایه کاربر -->
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 9a3 3 0 11-6 0 3 3 0 016 0z" />
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 13a6 6 0 00-6 6h12a6 6 0 00-6-6z" />
    <!-- نمودار افزایشی در پایین -->
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 19l4-4 3 2 5-4 4 3" />
</svg>
            </div>
        </div>
        <div class="space-y-1.5 relative z-10 min-w-0 flex-1">
            <div class="text-xl font-black text-amber-600 dark:text-amber-400 transition-all truncate max-w-[150px]" id="stat-top-user">-</div>
            <span class="text-[11px] text-amber-500 dark:text-amber-400 flex items-center gap-1 font-medium whitespace-nowrap" id="stat-top-user-usage">۰ GB مصرف شده</span>
        </div>
    </div>
</div>
        <div id="loading-state" class="text-center py-12">
            <span class="text-gray-500 dark:text-gray-400">در حال بارگذاری کاربران...</span>
        </div>
        <div class="mb-5 flex flex-col md:flex-row gap-2 justify-between items-center bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-xl p-2 shadow-sm">
            <div class="relative w-full md:w-80">
                <input type="text" id="search-input" oninput="filterAndRenderUsers()" placeholder="جستجوی نام کاربری یا UUID..." class="w-full pl-3 pr-8 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs">
                <div class="absolute inset-y-0 right-0 flex items-center pr-2.5 pointer-events-none text-gray-400">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                </div>
            </div>
            <div class="flex items-center gap-2 w-full md:w-auto">
                <select id="filter-status" onchange="filterAndRenderUsers()" class="flex-1 min-w-0 px-2 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer truncate">
                    <option value="all">🔍 همه</option>
					<option value="active">✅ فعال</option>
                    <option value="inactive">❌ غیرفعال</option>
                    <option value="online">⚡ آنلاین</option>
                    <option value="offline">💤 آفلاین</option>
                    <option value="expired">⏳ منقضی</option>
                </select>
                <select id="sort-users" onchange="filterAndRenderUsers()" class="flex-1 min-w-0 px-2 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer truncate">
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
			<button onclick="openCreateModal()" class="p-2 rounded-lg bg-blue-50 dark:bg-blue-900/30 border-2 border-blue-200 dark:border-blue-800/50 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-all duration-300 text-blue-600 dark:text-blue-400 shadow-sm hover:shadow hover:scale-110">
    			<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
			</button>
		</div>
        <div id="users-table-container" class="hidden overflow-x-auto border border-gray-200 dark:border-amoled-border rounded-xl bg-white dark:bg-amoled-card">
            <table class="w-full text-right border-collapse">
                <thead>
                    <tr class="bg-gray-100 dark:bg-zinc-900/50 border-b border-gray-200 dark:border-amoled-border text-xs text-gray-500 dark:text-gray-400 text-center">
                        <th class="p-2 w-10 text-center"><input type="checkbox" id="select-all-users" onchange="toggleSelectAllUsers(this)" class="w-5 h-5 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-blue-600 bg-white dark:bg-zinc-800 checked:bg-blue-600 checked:border-blue-600 focus:ring-blue-500/50 focus:ring-offset-0 transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95"></th>
                        <th class="p-4">نام کاربر و عملیات</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">لینک ساب</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">پورت</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">حجم</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">ریکوئست</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">زمان</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">کاربران آنلاین</th>
                        <th class="p-2 border-r border-gray-200 dark:border-zinc-800">تاریخ ساخت</th>
                    </tr>
                </thead>
                <tbody id="users-tbody" class="divide-y divide-gray-150 dark:divide-amoled-border text-sm"></tbody>
            </table>
        </div>
        <div id="empty-state" class="hidden p-8 border-2 border-dashed border-red-500/60 dark:border-red-500/50 bg-red-50 dark:bg-red-900/10 rounded-2xl text-center animate-pulse shadow-sm">
            <p class="text-red-600 dark:text-red-400 font-bold text-lg">کاربری وجود ندارد. برای ساخت اولین کاربر روی دکمه « + » کلیک کنید.</p>
        </div>
    </main>
<div id="path-warning-modal" class="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-red-500/50 rounded-3xl shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 text-red-500 mb-4 shadow-inner">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
        </div>
        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">تغییر مهم در ساختار کانفیگ‌ها</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
            به دلیل ارتقای امنیت و تغییر مسیر (Path) اتصال ، کانفیگ‌های قبل از نسخه 1.3.4 غیرفعال شده‌اند. درصورت عدم اتصال لطفاً ساب خود را بروزرسانی کنید .
        </p>
        <button onclick="closePathWarning()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-xl text-sm transition duration-300 shadow-lg">
            متوجه شدم، کانفیگ‌های جدید را می‌گیرم 
        </button>
    </div>
</div>
<div id="usage-warning-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-orange-500/50 rounded-3xl shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-500 mb-4 shadow-inner">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
        </div>
        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">هشدار محدودیت درخواست روزانه</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
            درخواست‌های روزانه کلودفلر شما از ۹۰,۰۰۰ عبور کرده است. در صورت عبور از محدودیت رایگان ۱۰۰,۰۰۰ درخواست، دسترسی به پنل و اتصالات تا ساعت ۳:۳۰ بامداد (به وقت ایران) قطع خواهد شد.
        </p>
        <button onclick="closeUsageWarning()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-xl text-sm transition duration-300 shadow-lg">
            متوجه شدم
        </button>
    </div>
</div>
<div id="free-panel-warning-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-rose-500/50 rounded-3xl shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-rose-100 dark:bg-rose-900/30 text-rose-500 mb-4 shadow-inner">
        <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
        </div>
        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">پیام همگانی</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
          دوست <span class="text-pink-500 font-bold">عزیز</span> با استفاده درست و فشار نیاوردن به کلودفلر میتونی ما را خوشحال کنی!
        </p>
        <button onclick="closeFreePanelWarning()" class="w-full py-3.5 bg-transparent border-2 border-purple-800 text-purple-900 hover:bg-purple-800 hover:text-white dark:border-purple-800 dark:text-purple-700 dark:hover:bg-purple-900 dark:hover:text-white font-black rounded-xl text-sm transition duration-300 shadow-lg">
            تأیید و موافقت
        </button>
    </div>
</div>
    <div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
        <div id="user-modal-card" class="w-full max-w-xl bg-white dark:bg-zinc-950 border border-gray-200 dark:border-zinc-800 rounded-2xl shadow-xl overflow-hidden transition-[opacity,transform] duration-200 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh] transform-gpu" style="will-change: transform, opacity;">
            <div class="px-6 py-4 border-b border-gray-150 dark:border-zinc-800/80 flex justify-between items-center bg-gray-50/50 dark:bg-zinc-900/30">
                <div class="flex items-center gap-2">
                    <div class="w-2.5 h-2.5 rounded-full bg-blue-500"></div>
                    <h3 id="modal-title" class="font-bold text-gray-900 dark:text-zinc-100 text-base">ایجاد کاربر جدید</h3>
                </div>
                <button onclick="toggleModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <form id="create-user-form" class="p-6 space-y-5 overflow-y-auto flex-1 overscroll-contain" style="-webkit-overflow-scrolling: touch; transform: translate3d(0,0,0); will-change: scroll-position, transform;" onsubmit="handleFormSubmit(event)">
                <div class="space-y-2.5">
                    <div>
                        <label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">نام کاربری</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                            </span>
                            <input type="text" id="input-name" placeholder="ali" maxlength="32" class="w-full pl-3 pr-9 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition" required>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                        <div>
                            <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">حجم (GB)</label>
                            <div class="relative">
                                <span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                                </span>
                                <input type="number" id="input-limit" min="0" step="any" placeholder="نامحدود" class="w-full pl-3 pr-9 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                            </div>
                        </div>
                        <div>
                            <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">اعتبار (روز)</label>
                            <div class="relative">
                                <span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                </span>
                                <input type="number" id="input-expiry" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                            </div>
                        </div>
                        <div>
                            <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">سقف ریکوئست</label>
                            <div class="relative">
                                <span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                                </span>
                                <input type="number" id="input-req-limit" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                            </div>
                        </div>
                        <div>
                            <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">محدودیت کاربر</label>
                            <div class="relative">
                                <span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                                </span>
                                <input type="number" id="input-ip-limit" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                            </div>
                        </div>
                    </div>
                </div>
<div class="mt-2.5 pt-2.5 border-t border-gray-100 dark:border-zinc-900">
    <div class="flex items-center justify-between mb-1.5">
        <span class="text-[11px] font-bold text-gray-500 dark:text-zinc-400 uppercase tracking-wider">تنظیمات فرگمنت</span>
        <label class="relative inline-flex items-center cursor-pointer scale-90 select-none">
            <input type="checkbox" id="input-frag-toggle" onchange="toggleFragInputs(this.checked)" class="sr-only peer">
            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-600"></div>
        </label>
    </div>
    <div id="frag-inputs-container" class="grid grid-cols-2 gap-2.5 hidden transition-all duration-300 mt-1.5">
        <div>
            <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">Fragment Length</label>
            <input type="text" id="input-frag-len" placeholder="200-3000" value="200-3000" dir="ltr" class="w-full px-2 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition">
        </div>
        <div>
            <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">Fragment Interval</label>
            <input type="text" id="input-frag-int" placeholder="1-2" value="1-2" dir="ltr" class="w-full px-2 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition">
        </div>
    </div>
</div>
                <div class="pt-2 border-t border-gray-100 dark:border-zinc-900">
                    <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-3 uppercase tracking-wider">پورت‌های اتصال (انتخاب چندگانه)</label>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="p-3 bg-gray-50/50 dark:bg-zinc-900/20 border border-gray-200/60 dark:border-zinc-800 rounded-2xl shadow-sm">
                            <div class="flex items-center gap-1.5 mb-2">
                                <span class="flex h-2 w-2 rounded-full bg-blue-500 shadow-sm"></span>
                                <span class="text-[11px] font-bold text-blue-600 dark:text-blue-400">🔒 پورت‌های امن (TLS)</span>
                            </div>
                            <div class="grid grid-cols-3 gap-1.5" id="tls-ports-list">
                            </div>
                        </div>
                        <div class="p-3 bg-gray-50/50 dark:bg-zinc-900/20 border border-gray-200/60 dark:border-zinc-800 rounded-2xl shadow-sm">
                            <div class="flex items-center gap-1.5 mb-2">
                                <span class="flex h-2 w-2 rounded-full bg-amber-500 shadow-sm"></span>
                                <span class="text-[11px] font-bold text-amber-600 dark:text-amber-400">🔓 پورت‌های معمولی (Non-TLS)</span>
                            </div>
                            <div class="grid grid-cols-3 gap-1.5" id="nontls-ports-list">
                            </div>
                        </div>
                    </div>
					<div class="mt-4 p-3 bg-gray-50/50 dark:bg-zinc-900/20 border border-gray-200/60 dark:border-zinc-800 rounded-2xl shadow-sm">
                        <div class="flex items-center gap-1.5 mb-2">
                            <span class="flex h-2 w-2 rounded-full bg-green-600 shadow-sm"></span>
                            <span class="text-[11px] font-bold text-green-700 dark:text-green-500">⚙️ پورت‌های دلخواه (با فاصله جدا کنید)</span>
                        </div>
                        <input type="text" id="input-custom-ports" placeholder="8080 2096 5000" dir="ltr" class="w-full px-2 py-2 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-left text-gray-800 dark:text-zinc-100 transition">
                    </div>
                </div>
                <div class="pt-4 border-t border-gray-100 dark:border-zinc-900 space-y-4">
					<div>
    					<div class="flex items-center justify-between mb-2">
        					<label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 uppercase tracking-wider">آیپی تمیز (توصیح میشود)</label>
        					<button 
								type="button" 
  								onclick="openIpSelectorModal()" 
  								class="px-2.5 py-1 bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/70 border border-amber-400 dark:border-amber-600 rounded-lg text-xs font-bold transition-all">
  								مخزن آیپی تمیز
							</button>
    					</div>
    					<textarea id="input-ips" rows="2" placeholder="104.16.0.1" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition resize-none"></textarea>
					</div>
                    <div class="mt-4 pt-4 border-t border-gray-150 dark:border-zinc-900 space-y-4">
                        <div id="user-cf-proxy-section" class="transition-opacity duration-300">
                            <label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">ثابت کردن کشور (Cloudflare)</label>
                            <div class="mb-2">
                                <input type="text" id="user-location-search" oninput="filterUserLocations()" placeholder="جستجوی شهر، کشور یا IATA" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-lg shadow-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-200 transition">
                            </div>
                            <div class="relative">
                                <select id="user-location-select" class="w-full pl-8 pr-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-lg shadow-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-200 cursor-pointer appearance-none">
                                    <option value="">بدون لوکیشن (پیش‌فرض)</option>
                                </select>
                                <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500 dark:text-zinc-400">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                                </div>
                            </div>
                        </div>
                        
                        <div class="pt-4 border-t-2 border-gray-200 dark:border-zinc-800">
                            <div class="flex items-center justify-between gap-2 mb-3">
                                <div class="flex items-center gap-1.5 min-w-0">
                                    <label class="relative inline-flex items-center cursor-pointer select-none flex-shrink-0">
                                        <input type="checkbox" id="user-proxy-mode-toggle" onchange="toggleUserProxyMode(this.checked)" class="sr-only peer">
                                        <div class="w-7 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                                    </label>
                                    <label class="block text-xs sm:text-sm font-medium text-gray-700 dark:text-zinc-300 cursor-pointer truncate" onclick="document.getElementById('user-proxy-mode-toggle').click()">ثابت کردن کشور و آیپی</label>
                                </div>
                                <a href="" target="_blank" class="text-[11px] bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 px-2 py-0.5 rounded border border-blue-200 dark:border-blue-800 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition font-bold shadow-sm flex-shrink-0">ساخت پروکسی شخصی</a>
                            </div>
                            
                            <div class="relative transition-opacity duration-300 opacity-50 pointer-events-none" id="user-socks5-container">
                                <input type="text" id="user-socks5-input" placeholder="socks5:// یا http:// یا (user:pass@ip:port)" dir="ltr" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-800 dark:text-zinc-100 transition" disabled>
                                <div class="w-full text-center">
                                    <span id="test-user-proxy-result" class="inline-block mt-2 text-[11px] font-bold transition-colors break-words leading-relaxed empty:hidden"></span>
                                </div>
                                <div class="mt-2 flex items-center justify-between w-full gap-2">
                                    <button type="button" onclick="testUserSocksProxy()" id="test-user-proxy-btn" class="flex-1 text-center text-[11px] bg-sky-50 dark:bg-sky-900/30 text-sky-600 dark:text-sky-400 py-1.5 rounded border border-sky-200 dark:border-sky-800 hover:bg-sky-100 dark:hover:bg-sky-900/50 transition font-bold shadow-sm">تست پروکسی</button>
                                    <button type="button" onclick="openProxySelectorModal()" class="flex-1 text-center text-[11px] bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 py-1.5 rounded border border-purple-200 dark:border-purple-800 hover:bg-purple-100 dark:hover:bg-purple-900/50 transition font-bold shadow-sm">مخزن پروکسی</button>
                                </div>
                                <div class="mt-3 p-3 border-2 border-dashed border-orange-400 dark:border-orange-500/70 bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300 rounded-xl text-[11px] font-bold leading-relaxed text-center w-full">
                                    پروکسی‌های موجود در این مخزن عمومی بوده و ممکن است باعث افت سرعت و کاهش پایداری کانفیگ‌ها شوند. جهت دستیابی به بالاترین سطح کیفیت، پیشنهاد می‌شود از طریق دکمه‌ی <span class="text-blue-600 dark:text-blue-400 font-black">«ساخت پروکسی شخصی»</span> نسبت به راه‌اندازی پروکسی اختصاصی بر روی سرور خود اقدام نمایید.
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-2 uppercase tracking-wider">شبیه‌ساز اثر انگشت مرورگر (Fingerprint)</label>
                        <div class="relative">
                            <select id="fingerprint-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-700 dark:text-zinc-300 cursor-pointer appearance-none">
                                <option value="chrome">🌐 Chrome</option>
                                <option value="firefox">🦊 Firefox</option>
                                <option value="safari">🧭 Safari</option>
                                <option value="ios" selected>📱 iOS Device (پیشنهادی)</option>
                                <option value="android">🤖 Android Device</option>
                                <option value="edge">🌀 Microsoft Edge</option>
                                <option value="360">🔒 360 Browser</option>
                                <option value="qq">💬 QQ Browser</option>
                                <option value="random">🎲 Random (اتفاقی)</option>
                                <option value="randomized">🎭 Randomized (پویا)</option>
                            </select>
                            <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500 dark:text-zinc-400">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                            </div>
                        </div>
                    </div>
						<div class="grid grid-cols-2 gap-2 mt-3">
    <!-- Porn Blocker -->
    <div class="flex items-center justify-between bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-2xl p-2 shadow-sm">
        <div class="flex items-center gap-2">
            <span class="text-[10px] sm:text-xs font-semibold text-gray-700 dark:text-zinc-300 whitespace-nowrap">Porn Blocker</span>
            <!-- دایره قرمز با دایره صورتی سوراخ‌دار و چین‌خورده داخل -->
            <span class="inline-flex items-center justify-center w-7 h-7 rounded-full border-2 border-red-500 bg-white dark:bg-zinc-800 relative flex-shrink-0 overflow-hidden">
                <!-- دایره صورتی سوراخ‌دار با چین‌خوردگی -->
                <svg class="w-5 h-5" viewBox="0 0 100 100">
                    <!-- حلقه صورتی با چین‌خوردگی -->
                    <defs>
                        <radialGradient id="pinkHole" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stop-color="#ff69b4" stop-opacity="1"/>
                            <stop offset="60%" stop-color="#ff85b3" stop-opacity="1"/>
                            <stop offset="100%" stop-color="#d4508c" stop-opacity="1"/>
                        </radialGradient>
                        <!-- چین‌خوردگی به صورت موج‌های کوچک دور حلقه -->
                        <filter id="wrinkle">
                            <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="3" result="noise"/>
                            <feDisplacementMap in="SourceGraphic" in2="noise" scale="3" xChannelSelector="R" yChannelSelector="G"/>
                        </filter>
                    </defs>
                    <!-- حلقه با سوراخ وسط -->
                    <circle cx="50" cy="50" r="40" fill="none" stroke="url(#pinkHole)" stroke-width="18" filter="url(#wrinkle)"/>
                    <!-- چین‌خوردگی اضافی به صورت دایره‌های کوچک دور حلقه -->
                    <circle cx="50" cy="50" r="40" fill="none" stroke="#ff69b4" stroke-width="1" stroke-dasharray="3 5" opacity="0.7"/>
                    <circle cx="50" cy="50" r="35" fill="none" stroke="#ff85b3" stroke-width="0.5" stroke-dasharray="2 4" opacity="0.5"/>
                    <!-- سوراخ وسط (خالی) -->
                    <circle cx="50" cy="50" r="15" fill="none"/>
                </svg>
                <!-- خط کج قرمز -->
                <span class="absolute inset-0 flex items-center justify-center pointer-events-none">
                    <span class="w-[142%] h-[2.5px] bg-red-500 absolute rounded-full" style="transform: rotate(-45deg);"></span>
                </span>
            </span>
        </div>
        <label class="relative inline-flex items-center cursor-pointer scale-[0.65] sm:scale-75 origin-left">
            <input type="checkbox" id="input-block-porn" class="sr-only peer">
            <div class="w-11 h-6 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-rose-500"></div>
        </label>
    </div>

    <!-- ADS Blocker -->
    <div class="flex items-center justify-between bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-2xl p-2 shadow-sm">
        <div class="flex items-center gap-2">
            <span class="text-[10px] sm:text-xs font-semibold text-gray-700 dark:text-zinc-300 whitespace-nowrap">ADS Blocker</span>
            <!-- دایره قرمز با نوشته ADS مشکی و خط کج -->
            <span class="inline-flex items-center justify-center w-7 h-7 rounded-full border-2 border-red-500 bg-white dark:bg-zinc-800 relative text-[9px] font-black text-black dark:text-white flex-shrink-0 overflow-hidden">
                ADS
                <span class="absolute inset-0 flex items-center justify-center pointer-events-none">
                    <span class="w-[142%] h-[2.5px] bg-red-500 absolute rounded-full" style="transform: rotate(-45deg);"></span>
                </span>
            </span>
        </div>
        <label class="relative inline-flex items-center cursor-pointer scale-[0.65] sm:scale-75 origin-left">
            <input type="checkbox" id="input-block-ads" class="sr-only peer">
            <div class="w-11 h-6 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
        </label>
    </div>
</div>
                </div>
                <div class="pt-4 flex gap-3">
                    <button type="button" onclick="toggleModal(false)" class="flex-1 py-3 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-xl text-sm transition duration-200 shadow-sm">انصراف</button>
                    <button type="submit" id="submit-btn" class="flex-1 py-3 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-xl text-sm transition duration-200 shadow-md hover:shadow-lg">ایجاد کاربر</button>
                </div>
            </form>
        </div>
    </div>
<div id="ip-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
            <h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm">مخزن آیپی تمیز</h3>
            <button type="button" onclick="toggleIpSelectorModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
        <div class="p-6 space-y-4">
            <div id="ip-loading-state" class="text-center text-sm text-gray-500 dark:text-zinc-400 hidden">
                Loading IPs...
            </div>
            <div id="ip-selection-form" class="space-y-4">
                <div>
                    <label class="block text-xs font-medium mb-1.5 text-gray-700 dark:text-zinc-300">اوپراتور</label>
                    <select id="ip-operator-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-xl text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
                        <option value="all">همه (توصیه شده)</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-medium mb-1.5 text-gray-700 dark:text-zinc-300">تعداد</label>
                    <input type="number" id="ip-count-input" min="1" value="20" dir="ltr" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
                </div>
            </div>
            <div class="pt-4 flex gap-3">
                <button type="button" onclick="toggleIpSelectorModal(false)" class="flex-1 py-2 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-xl text-xs transition shadow-sm">لغو</button>
                <button type="button" onclick="applySelectedIps()" class="flex-1 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-xl text-xs transition">دریافت</button>
            </div>
        </div>
    </div>
</div>
<div id="proxy-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
            <h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm">مخزن پروکسی آیپی ثابت</h3>
            <button type="button" onclick="toggleProxySelectorModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
        <div class="p-6 space-y-4">
            <div id="proxy-loading-state" class="text-center text-sm text-purple-500 font-bold hidden">
                در حال پردازش...
            </div>
            <div id="proxy-selection-form" class="space-y-4">
                <div>
                    <label class="block text-xs font-medium mb-1.5 text-gray-700 dark:text-zinc-300">کشور را انتخاب کنید</label>
                    <select id="proxy-country-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-xl text-xs focus:outline-none focus:ring-2 focus:ring-purple-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
                        <option value="">در حال دریافت کشورها...</option>
                    </select>
                </div>
            </div>
            <div class="pt-4 flex gap-3">
                <button type="button" onclick="toggleProxySelectorModal(false)" class="flex-1 py-2 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-xl text-xs transition shadow-sm">لغو</button>
                <button type="button" onclick="fetchAndLoadProxy()" id="proxy-fetch-btn" class="flex-1 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-xl text-xs transition shadow-sm disabled:opacity-50 disabled:cursor-not-allowed" disabled>دریافت پروکسی</button>
            </div>
        </div>
    </div>
</div>
    <div id="settings-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
        <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
            <div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
                <h3 class="font-bold text-gray-900 dark:text-zinc-100">تنظیمات پنل</h3>
                <button onclick="toggleSettingsModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4 overflow-y-auto flex-1 overscroll-contain">
                <div class="pt-2">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">نرخ رفرش خودکار پنل</label>
                    <div class="relative">
                        <select id="refresh-rate-select" onchange="changeRefreshRate(this.value)" class="w-full pl-8 pr-3 py-2.5 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-200 cursor-pointer appearance-none">
                            <option value="1000">۱ ثانیه</option>
                            <option value="2000" selected>۲ ثانیه (پیش‌فرض)</option>
                            <option value="5000">۵ ثانیه</option>
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
               
                <div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
                    <h4 class="text-sm font-bold mb-3 text-gray-800 dark:text-zinc-200">🔒 تغییر رمز عبور مدیریت</h4>
                    <div class="space-y-3">
                        <div>
                            <label class="block text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-1">رمز عبور فعلی</label>
                            <input type="password" id="change-pwd-current" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
                        </div>
                        <div>
                            <label class="block text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-1">رمز عبور جدید</label>
                            <input type="password" id="change-pwd-new" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
                        </div>
                        <button type="button" onclick="changeAdminPassword()" id="change-pwd-btn" class="w-full py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-semibold rounded-lg text-xs transition-all shadow-sm">تغییر رمز عبور</button>
                    </div>
                </div>
                <div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
                    <h4 class="text-sm font-bold mb-3 text-gray-800 dark:text-zinc-200">💾 پشتیبان‌گیری و بازیابی</h4>
                    <div class="grid grid-cols-2 gap-3">
                        <button type="button" onclick="exportUsersBackup()" class="py-2.5 bg-indigo-50 dark:bg-indigo-950/20 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/30 border border-indigo-200 dark:border-indigo-900/50 rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
                            📤 پشتیبان گیری
                        </button>
                        <button type="button" onclick="triggerImportBackup()" class="py-2.5 bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-500 hover:bg-green-100 dark:hover:bg-green-900/30 border border-green-200 dark:border-green-900/50 rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
                            📥 بازیابی
                        </button>
                    </div>
                    <input type="file" id="backup-file-input" onchange="importUsersBackup(event)" accept=".json" class="hidden">
                </div>
                <div class="pt-4 flex gap-3">
                    <button type="button" onclick="toggleSettingsModal(false)" class="flex-1 py-2 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-lg text-sm transition shadow-sm">انصراف</button>
                    <button type="button" onclick="saveSettings()" id="save-settings-btn" class="flex-1 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-lg text-sm transition">ذخیره تنظیمات</button>
                </div>
            </div>
        </div>
    </div>
<div id="update-modal" class="fixed inset-0 z-[90] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-3xl shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-500 mb-4 shadow-inner">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        </div>
        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">بروزرسانی پنل</h3>
        <p id="update-modal-text" class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
            نسخه جدید در دسترس است. اگر آپدیت خودکار جواب نداد، حتماً از طریق لینک زیر آپدیت دستی را انجام دهید.
        </p>
        <div class="space-y-3">
            <button onclick="applyUpdate()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-xl text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                آپدیت خودکار (توصیه شده)
            </button>
            <div class="relative py-2">
                <div class="absolute inset-0 flex items-center">
                    <div class="w-full border-t border-gray-200 dark:border-zinc-800"></div>
                </div>
                <div class="relative flex justify-center text-xs">
                    <span class="bg-white dark:bg-amoled-card px-2 text-gray-400">یا</span>
                </div>
            </div>
            <a href="https://raw.githubusercontent.com/sepehr-gamer/Zeus-pannel/refs/heads/main/zeus.js" target="_blank" class="w-full py-3.5 bg-orange-50 dark:bg-orange-950/30 hover:bg-orange-100 dark:hover:bg-orange-900/50 text-orange-600 dark:text-orange-500 border border-orange-300 dark:border-orange-500 font-bold rounded-xl text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                </svg>
                آپدیت دستی (رفتن به سایت)
            </a>
        </div>
        <button onclick="toggleUpdateModal(false)" class="mt-5 w-full py-3.5 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-xl text-sm transition duration-300 shadow-sm flex items-center justify-center">
            انصراف
        </button>
    </div>
</div>
	<div id="token-modal" class="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
        <div id="token-modal-card" class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-3xl shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200">
            <div class="flex justify-between items-center mb-6">
                <div class="flex items-center gap-2">
                    <div class="w-2.5 h-2.5 rounded-full bg-orange-500"></div>
                    <h3 class="text-lg font-bold text-gray-900 dark:text-white">تنظیم توکن کلودفلر</h3>
                </div>
                <button onclick="toggleTokenModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            
            <div class="mb-5 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800/50 rounded-xl text-xs leading-relaxed text-orange-800 dark:text-orange-300 font-medium">
                توکن کلودفلر شما در این پنل ذخیره نشده است. برای فعال‌سازی آپدیت خودکار از داخل پنل، لطفاً توکن خود را دریافت کرده و در کادر زیر وارد کنید.
            </div>

            <a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Zeus-Deployer-Token" target="_blank" class="flex items-center justify-center gap-2 w-full py-3 bg-[#d94800] hover:bg-[#e35802] text-white font-bold rounded-xl text-sm transition duration-300 mb-4 shadow-md shadow-orange-500/20">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                دریافت توکن کلودفلر
            </a>

            <div class="space-y-4">
                <input type="password" id="update-token-input" placeholder="توکن را اینجا وارد کنید" class="w-full px-4 py-3 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-orange-500 text-sm font-mono text-center text-gray-900 dark:text-zinc-100 transition" dir="auto">
                
                <button id="submit-token-btn" onclick="submitTokenForUpdate()" class="w-full py-3 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-xl text-sm transition duration-300 shadow-lg">
                    ثبت و آپدیت پنل
                </button>
            </div>
        </div>
    </div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
    <div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-3xl shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
        <div class="flex justify-between items-center mb-4">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
            <button onclick="toggleQrModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
        <div class="flex justify-center bg-white p-4 rounded-xl mb-4">
            <div id="qrcode-container"></div>
        </div>
    </div>
</div>
    <div id="bulk-actions-bar" class="fixed bottom-4 left-1/2 -translate-x-1/2 z-[40] bg-white dark:bg-zinc-900/90 border border-gray-200 dark:border-zinc-800/80 px-6 py-4 rounded-2xl shadow-2xl flex flex-wrap items-center justify-between gap-4 w-[95%] max-w-4xl transition-all duration-300 transform translate-y-28 opacity-0 pointer-events-none backdrop-blur-md">
        <div class="flex items-center gap-2">
            <span class="w-3 h-3 bg-blue-500 rounded-full animate-pulse shadow-sm shadow-blue-500/50"></span>
            <span id="bulk-selected-count" class="text-sm font-bold text-gray-800 dark:text-zinc-200">۰ کاربر انتخاب شده</span>
        </div>
        <div class="flex flex-wrap gap-2 justify-end">
            <button onclick="bulkEdit()" class="px-3 py-1.5 bg-yellow-50 dark:bg-yellow-950/20 text-yellow-600 dark:text-yellow-400 hover:bg-yellow-100 dark:hover:bg-yellow-900/30 rounded-xl text-xs font-bold transition border border-yellow-200 dark:border-yellow-900/50 flex items-center gap-1">
                ✏️ ویرایش گروهی
            </button>
            <button onclick="bulkToggleStatus(1)" class="px-3 py-1.5 bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-500 hover:bg-green-100 dark:hover:bg-green-900/30 rounded-xl text-xs font-bold transition border border-green-200 dark:border-green-900/50 flex items-center gap-1">
                ✅ فعال‌سازی
            </button>
            <button onclick="bulkToggleStatus(0)" class="px-3 py-1.5 bg-amber-50 dark:bg-amber-950/20 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/30 rounded-xl text-xs font-bold transition border border-amber-200 dark:border-amber-900/50 flex items-center gap-1">
                ❌ غیرفعال‌سازی
            </button>
            <button onclick="bulkReset('volume')" class="px-3 py-1.5 bg-blue-50 dark:bg-blue-950/20 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-xl text-xs font-bold transition border border-blue-200 dark:border-blue-900/50 flex items-center gap-1">
                📊 ریست حجم
            </button>
            <button onclick="bulkReset('req')" class="px-3 py-1.5 bg-sky-50 dark:bg-sky-950/20 text-sky-600 dark:text-sky-400 hover:bg-sky-100 dark:hover:bg-sky-900/30 rounded-xl text-xs font-bold transition border border-sky-200 dark:border-sky-900/50 flex items-center gap-1">
                ⚡ ریست ریکوئست
            </button>
            <button onclick="bulkReset('time')" class="px-3 py-1.5 bg-purple-50 dark:bg-purple-950/20 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900/30 rounded-xl text-xs font-bold transition border border-purple-200 dark:border-purple-900/50 flex items-center gap-1">
                ⏳ ریست زمان
            </button>
            <button onclick="bulkDelete()" class="px-3 py-1.5 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-450 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-xl text-xs font-bold transition border border-red-200 dark:border-red-900/50 flex items-center gap-1">
                🗑️ حذف گروهی
            </button>
        </div>
    </div>
    <div id="bulk-edit-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
        <div id="bulk-edit-modal-card" class="w-full max-w-xl bg-white dark:bg-zinc-950 border border-gray-200 dark:border-zinc-800 rounded-2xl shadow-xl overflow-hidden transition-[opacity,transform] duration-200 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh] transform-gpu" style="will-change: transform, opacity;">
            <div class="px-6 py-4 border-b border-gray-150 dark:border-zinc-800/80 flex justify-between items-center bg-gray-50/50 dark:bg-zinc-900/30">
                <div class="flex items-center gap-2">
                    <div class="w-2.5 h-2.5 rounded-full bg-yellow-500"></div>
                    <h3 class="font-bold text-gray-900 dark:text-zinc-100 text-base">ویرایش گروهی کاربران</h3>
                </div>
                <button onclick="toggleBulkEditModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <form id="bulk-edit-form" class="p-6 space-y-5 overflow-y-auto flex-1 overscroll-contain" style="-webkit-overflow-scrolling: touch; transform: translate3d(0,0,0); will-change: scroll-position, transform;" onsubmit="handleBulkEditSubmit(event)">
                <p class="text-xs text-amber-600 dark:text-amber-400 font-semibold mb-2">💡 تغییرات فقط روی بخش‌هایی اعمال می‌شوند که دکمه فعال‌ساز تغییر (چپ) آن‌ها روشن باشد.</p>
                <div class="space-y-4">
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-limit" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">حجم (GB)</label>
                            <input type="number" id="bulk-input-limit" min="0" step="any" placeholder="بدون تغییر" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-sm font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                        </div>
                    </div>
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-expiry" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">اعتبار (روز)</label>
                            <input type="number" id="bulk-input-expiry" min="0" placeholder="بدون تغییر" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-sm font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                        </div>
                    </div>
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-req-limit" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">سقف ریکوئست</label>
                            <input type="number" id="bulk-input-req-limit" min="0" placeholder="بدون تغییر" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-sm font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                        </div>
                    </div>
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-ip-limit" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">محدودیت کاربر</label>
                            <input type="number" id="bulk-input-ip-limit" min="0" placeholder="بدون تغییر" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-sm font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition">
                        </div>
                    </div>
					<div class="flex flex-col gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<label class="relative inline-flex items-center cursor-pointer select-none">
									<input type="checkbox" id="bulk-apply-frag" onchange="toggleBulkFragContainer(this.checked)" class="sr-only peer">
									<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
								</label>
								<span class="text-xs font-bold text-gray-500 dark:text-zinc-400 uppercase tracking-wider">تنظیمات فرگمنت</span>
							</div>
							<label id="bulk-frag-toggle-wrapper" class="relative inline-flex items-center cursor-pointer select-none hidden">
								<input type="checkbox" id="bulk-frag-enable-toggle" onchange="toggleBulkFragInputs(this.checked)" class="sr-only peer">
								<div class="relative w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-600"></div>
								<span class="mr-2 text-xs font-bold text-gray-700 dark:text-zinc-300">فعال‌سازی برای همه</span>
							</label>
						</div>
						<div id="bulk-frag-inputs-container" class="grid grid-cols-2 gap-2 hidden transition-all duration-300 pt-2 border-t border-gray-100 dark:border-zinc-800">
							<div>
								<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">Fragment Length</label>
								<input type="text" id="bulk-input-frag-len" placeholder="200-3000" value="200-3000" class="w-full px-2 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition" dir="ltr">
							</div>
							<div>
								<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">Fragment Interval</label>
								<input type="text" id="bulk-input-frag-int" placeholder="1-2" value="1-2" class="w-full px-2 py-1.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition" dir="ltr">
							</div>
						</div>
					</div>
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-fingerprint" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5 uppercase tracking-wider">Fingerprint</label>
                            <select id="bulk-fingerprint-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-700 dark:text-zinc-300 cursor-pointer">
                                <option value="chrome">🌐 Chrome</option>
                                <option value="firefox">🦊 Firefox</option>
                                <option value="safari">🧭 Safari</option>
                                <option value="ios">📱 iOS Device</option>
                                <option value="android">🤖 Android Device</option>
                                <option value="edge">🌀 Microsoft Edge</option>
                                <option value="360">🔒 360 Browser</option>
                                <option value="qq">💬 QQ Browser</option>
                                <option value="random">🎲 Random (اتفاقی)</option>
                                <option value="randomized">🎭 Randomized (پویا)</option>
                            </select>
                        </div>
                    </div>
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-ports" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1 space-y-3">
                            <div>
                                <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-2 uppercase tracking-wider">پورت‌های پیش‌فرض</label>
                                <div class="grid grid-cols-4 gap-2">
                                    <label class="flex items-center gap-1 text-[11px] text-gray-700 dark:text-zinc-300 cursor-pointer"><input type="checkbox" name="bulk-ports" value="443" class="rounded border-gray-300 dark:border-zinc-800 text-blue-600 focus:ring-blue-500"> 443</label>
                                    <label class="flex items-center gap-1 text-[11px] text-gray-700 dark:text-zinc-300 cursor-pointer"><input type="checkbox" name="bulk-ports" value="80" class="rounded border-gray-300 dark:border-zinc-800 text-blue-600 focus:ring-blue-500"> 80</label>
                                    <label class="flex items-center gap-1 text-[11px] text-gray-700 dark:text-zinc-300 cursor-pointer"><input type="checkbox" name="bulk-ports" value="2053" class="rounded border-gray-300 dark:border-zinc-800 text-blue-600 focus:ring-blue-500"> 2053</label>
                                    <label class="flex items-center gap-1 text-[11px] text-gray-700 dark:text-zinc-300 cursor-pointer"><input type="checkbox" name="bulk-ports" value="2083" class="rounded border-gray-300 dark:border-zinc-800 text-blue-600 focus:ring-blue-500"> 2083</label>
                                </div>
                            </div>
                            <div>
                                <label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">پورت‌های دلخواه (با فاصله جدا کنید)</label>
                                <input type="text" id="bulk-input-custom-ports" placeholder="8080 2096 5000" dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-left text-gray-800 dark:text-zinc-100 transition">
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center gap-3 border border-gray-100 dark:border-zinc-900 p-3 rounded-xl bg-gray-50/20 dark:bg-zinc-900/10">
                        <label class="relative inline-flex items-center cursor-pointer select-none">
                            <input type="checkbox" id="bulk-apply-ips" class="sr-only peer">
                            <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-green-700"></div>
                        </label>
                        <div class="flex-1">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1 uppercase tracking-wider">آیپی تمیز (توصیح میشود)</label>
                            <textarea id="bulk-input-ips" rows="2" placeholder="104.16.0.1" class="w-full px-3 py-2 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400/80 transition resize-none"></textarea>
                        </div>
                    </div>
                </div>
                <div class="pt-4 flex gap-3">
                    <button type="button" onclick="toggleBulkEditModal(false)" class="flex-1 py-3 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-xl text-sm transition duration-200 shadow-sm">انصراف</button>
                    <button type="submit" id="bulk-submit-btn" class="flex-1 py-3 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-xl text-sm transition duration-200 shadow-md">ثبت تغییرات گروهی</button>
                </div>
            </form>
        </div>
    </div>
	<div id="update-success-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
		<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-green-600/50 rounded-3xl shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
			<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 text-green-600 mb-4 shadow-inner">
				<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>
			</div>
			<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">آپدیت موفقیت‌آمیز</h3>
			<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
				آپدیت موفق بود لطفا صفحه را 10 ثانیه دیگر رفرش کنید تا نسخه جدید لود شود
			</p>
			<button onclick="window.location.reload()" class="w-full py-3.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-black rounded-xl text-sm transition duration-300 shadow-lg">
				رفرش صفحه
			</button>
		</div>
	</div>
<div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>

<div id="custom-confirm-modal" class="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div id="custom-confirm-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-3xl shadow-2xl overflow-hidden p-6 text-center transform transition-all scale-95 duration-300">
        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-3">تأیید عملیات</h3>
        <p id="custom-confirm-message" class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium"></p>
        <div class="flex gap-3">
            <button id="custom-confirm-cancel" class="flex-1 py-3 bg-transparent border-2 border-rose-700 text-rose-700 hover:bg-rose-900/20 hover:text-rose-800 dark:border-rose-700 dark:text-rose-500 dark:hover:bg-rose-900/40 dark:hover:text-rose-400 font-bold rounded-xl text-sm transition duration-200 shadow-sm">انصراف</button>
            <button id="custom-confirm-ok" class="flex-1 py-3 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-xl text-sm transition duration-200 shadow-lg">تأیید</button>
        </div>
    </div>
</div>
    <script>
		function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            const colors = type === 'error' 
                ? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
                : 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
            
            toast.className = 'px-4 py-3 border rounded-xl shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
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
                            if (res.ok) successCount++;
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
        window.toggleBulkFragContainer = function(show) {
            const wrapper = document.getElementById('bulk-frag-toggle-wrapper');
            const inputs = document.getElementById('bulk-frag-inputs-container');
            const enableToggle = document.getElementById('bulk-frag-enable-toggle');
            if (wrapper && inputs) {
                if (show) {
                    wrapper.classList.remove('hidden');
                    if (enableToggle && enableToggle.checked) {
                        inputs.classList.remove('hidden');
                    }
                } else {
                    wrapper.classList.add('hidden');
                    inputs.classList.add('hidden');
                }
            }
        };

        window.toggleBulkFragInputs = function(show) {
            const inputs = document.getElementById('bulk-frag-inputs-container');
            if (inputs) {
                if (show) {
                    inputs.classList.remove('hidden');
                } else {
                    inputs.classList.add('hidden');
                }
            }
        };

        function toggleBulkEditModal(show) {
            const modal = document.getElementById('bulk-edit-modal');
            const card = document.getElementById('bulk-edit-modal-card');
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
                document.getElementById('bulk-edit-form').reset();
                window.toggleBulkFragContainer(false);
				const bulkCustomPortInput = document.getElementById('bulk-input-custom-ports');
				if (bulkCustomPortInput) bulkCustomPortInput.value = '';
            }
        }
        function bulkEdit() {
            toggleBulkEditModal(true);
        }
        async function handleBulkEditSubmit(event) {
            event.preventDefault();
            const submitButton = document.getElementById('bulk-submit-btn');
            submitButton.disabled = true;
            submitButton.innerText = 'در حال ثبت تغییرات...';
            const usernames = Array.from(window.selectedUsernames);
            const applyLimit = document.getElementById('bulk-apply-limit').checked;
            const limitValue = document.getElementById('bulk-input-limit').value || null;
            const applyExpiry = document.getElementById('bulk-apply-expiry').checked;
            const expiryValue = document.getElementById('bulk-input-expiry').value || null;
            const applyReqLimit = document.getElementById('bulk-apply-req-limit').checked;
            const reqLimitValue = document.getElementById('bulk-input-req-limit').value || null;
            const applyIpLimit = document.getElementById('bulk-apply-ip-limit').checked;
            const ipLimitValue = document.getElementById('bulk-input-ip-limit').value || null;
            const applyFingerprint = document.getElementById('bulk-apply-fingerprint').checked;
            const fingerprintValue = document.getElementById('bulk-fingerprint-select').value;
            const applyPorts = document.getElementById('bulk-apply-ports').checked;
            const checkedPorts = Array.from(document.querySelectorAll('input[name="bulk-ports"]:checked')).map(cb => cb.value);
            const bulkCustomPortsRaw = document.getElementById('bulk-input-custom-ports') ? document.getElementById('bulk-input-custom-ports').value : '';
            const bulkCustomPortsArray = bulkCustomPortsRaw.replace(/ +/g, ',').split(',').map(p => p.trim()).filter(p => p.length > 0);
            const finalBulkPortsArray = checkedPorts.concat(bulkCustomPortsArray);
            const portsValue = finalBulkPortsArray.join(',');
            const tlsValue = finalBulkPortsArray.some(p => tlsPorts.includes(p)) ? 'on' : 'off';
            const applyIps = document.getElementById('bulk-apply-ips').checked;
            const ipsValue = document.getElementById('bulk-input-ips').value;
			const applyFrag = document.getElementById('bulk-apply-frag').checked;
            const isBulkFragEnabled = document.getElementById('bulk-frag-enable-toggle').checked;
			const fragLenValue = isBulkFragEnabled ? (document.getElementById('bulk-input-frag-len').value || '200-3000') : "";
			const fragIntValue = isBulkFragEnabled ? (document.getElementById('bulk-input-frag-int').value || '1-2') : "";
            if (!applyLimit && !applyExpiry && !applyReqLimit && !applyIpLimit && !applyFingerprint && !applyPorts && !applyIps && !applyFrag) {
                alert('⚠️ لطفا حداقل یک فیلد را برای اعمال تغییر انتخاب کنید!');
                submitButton.disabled = false;
                submitButton.innerText = 'ثبت تغییرات گروهی';
                return;
            }
            try {
                let successCount = 0;
                await Promise.all(usernames.map(async (uname) => {
                    const user = window.allUsers.find(u => u.username === uname);
                    if (!user) return;
                    const limit = applyLimit ? limitValue : user.limit_gb;
                    const expiry = applyExpiry ? expiryValue : user.expiry_days;
                    const reqLimit = applyReqLimit ? reqLimitValue : user.limit_req;
                    const ipLimit = applyIpLimit ? ipLimitValue : user.ip_limit;
                    const fingerprint = applyFingerprint ? fingerprintValue : user.fingerprint;
                    const port = applyPorts ? portsValue : user.port;
                    const tls = applyPorts ? tlsValue : user.tls;
                    const ips = applyIps ? ipsValue : user.ips;
					const frag_len = applyFrag ? fragLenValue : user.frag_len;
					const frag_int = applyFrag ? fragIntValue : user.frag_int;
                    try {
                        const response = await fetch('/api/users/' + encodeURIComponent(uname), {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                username: uname,
                                limit_gb: limit,
                                expiry_days: expiry,
                                limit_req: reqLimit,
                                tls,
                                port,
                                ips,
                                fingerprint,
                                ip_limit: ipLimit,
                                frag_len: frag_len,
                                frag_int: frag_int
                            })
                        });
                        if (response.ok) {
                            successCount++;
                        }
                    } catch (e) {}
                }));
                alert('✅ تغییرات با موفقیت روی ' + successCount + ' کاربر اعمال شد.');
                toggleBulkEditModal(false);
                window.selectedUsernames.clear();
                updateBulkActionsBar();
                await loadUsers(true);
            } catch (err) {
                alert('خطا در انجام تغییرات گروهی');
            } finally {
                submitButton.disabled = false;
                submitButton.innerText = 'ثبت تغییرات گروهی';
            }
        }
        const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
        const nonTlsPorts = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];
        let isEditMode = false;
        let editingUsername = '';
        function renderPortCheckboxes() {
            const tlsContainer = document.getElementById('tls-ports-list');
            const nonTlsContainer = document.getElementById('nontls-ports-list');
            tlsContainer.innerHTML = tlsPorts.map(function(port) {
                const isCheckedDefault = port === '443' ? 'checked' : '';
                return '<label class="relative cursor-pointer">' +
                    '<input type="checkbox" name="ports" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
                    '<div class="flex items-center justify-center gap-1 px-1.5 py-1.5 border border-gray-200 dark:border-zinc-800/80 rounded-lg text-[11px] font-semibold select-none transition-all duration-200 hover:bg-gray-50 dark:hover:bg-zinc-800/40 text-gray-700 dark:text-zinc-300 peer-checked:bg-blue-50 dark:peer-checked:bg-blue-950/25 peer-checked:border-blue-500 dark:peer-checked:border-blue-500/70 peer-checked:text-blue-600 dark:peer-checked:text-blue-400 shadow-sm">' +
                        '<span>' + port + '</span>' +
                        '<svg class="w-3 h-3 hidden peer-checked:block text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
                    '</div>' +
                '</label>';
            }).join('');
            nonTlsContainer.innerHTML = nonTlsPorts.map(function(port) {
                const isCheckedDefault = port === '80' ? 'checked' : '';
                return '<label class="relative cursor-pointer">' +
                    '<input type="checkbox" name="ports" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
                    '<div class="flex items-center justify-center gap-1 px-1.5 py-1.5 border border-gray-200 dark:border-zinc-800/80 rounded-lg text-[11px] font-semibold select-none transition-all duration-200 hover:bg-gray-50 dark:hover:bg-zinc-800/40 text-gray-700 dark:text-zinc-300 peer-checked:bg-amber-50 dark:peer-checked:bg-amber-950/25 peer-checked:border-amber-500 dark:peer-checked:border-amber-500/70 peer-checked:text-amber-600 dark:peer-checked:text-amber-400 shadow-sm">' +
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
            if (cb80) cb80.checked = true;
        }, 100);
        function toggleSettingsModal(show) {
            const modal = document.getElementById('settings-modal');
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
        window.toggleFragInputs = function(show) {
            const container = document.getElementById('frag-inputs-container');
            if (container) {
                if (show) {
                    container.classList.remove('hidden');
                } else {
                    container.classList.add('hidden');
                }
            }
        };

        function toggleModal(show) {
            const modal = document.getElementById('user-modal');
            const card = document.getElementById('user-modal-card');
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
                isEditMode = false;
                editingUsername = '';
                document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
                document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
                document.getElementById('input-name').disabled = false;
                document.getElementById('create-user-form').reset();
                const cb443 = document.querySelector('input[name="ports"][value="443"]');
                if (cb443) cb443.checked = true;
                const cb80 = document.querySelector('input[name="ports"][value="80"]');
                if (cb80) cb80.checked = true;
                const fpSelect = document.getElementById('fingerprint-select');
                if (fpSelect) fpSelect.value = 'ios';
                const bpCheck = document.getElementById('input-block-porn');
                if (bpCheck) bpCheck.checked = false;
                const baCheck = document.getElementById('input-block-ads');
				if (baCheck) baCheck.checked = false;
				const fragLenInput = document.getElementById('input-frag-len');
				if (fragLenInput) fragLenInput.value = '200-3000';
				const fragIntInput = document.getElementById('input-frag-int');
				if (fragIntInput) fragIntInput.value = '1-2';
                const fragToggle = document.getElementById('input-frag-toggle');
                if (fragToggle) fragToggle.checked = false;
                window.toggleFragInputs(false);
				const customPortInput = document.getElementById('input-custom-ports');
				if (customPortInput) customPortInput.value = '';
            }
        }
		function toggleUpdateModal(show, version = '') {
            const modal = document.getElementById('update-modal');
            const card = modal.querySelector('div');
            if (show) {
                if (version) {
                    document.getElementById('update-modal-text').innerHTML = 'نسخه جدید (<b>v' + version + '</b>) در دسترس است.<br>اگر آپدیت خودکار جواب نداد، از روش دستی استفاده کنید.';
                }
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
        function openCreateModal() {
            isEditMode = false;
            editingUsername = '';
            document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
            document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
            document.getElementById('input-name').disabled = false;
            document.getElementById('create-user-form').reset();
            const cb443 = document.querySelector('input[name="ports"][value="443"]');
            if (cb443) cb443.checked = true;
            const cb80 = document.querySelector('input[name="ports"][value="80"]');
            if (cb80) cb80.checked = true;
            const fpSelect = document.getElementById('fingerprint-select');
            if (fpSelect) fpSelect.value = 'ios';
            const fragToggle = document.getElementById('input-frag-toggle');
            if (fragToggle) fragToggle.checked = false;
            window.toggleFragInputs(false);

            const userProxyToggle = document.getElementById('user-proxy-mode-toggle');
            if (userProxyToggle) userProxyToggle.checked = false;
            if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(false);
            const userLocSelect = document.getElementById('user-location-select');
            if (userLocSelect) userLocSelect.value = '';
            const userLocSearch = document.getElementById('user-location-search');
            if (userLocSearch) userLocSearch.value = '';
            const userSocksInput = document.getElementById('user-socks5-input');
            if (userSocksInput) userSocksInput.value = '';
            const userProxyResult = document.getElementById('test-user-proxy-result');
            if (userProxyResult) userProxyResult.innerText = '';

            toggleModal(true);
        }
        const themeToggleBtn = document.getElementById('theme-toggle');
		if (localStorage.getItem('color-theme') === 'dark' || (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        themeToggleBtn.addEventListener('click', () => {
            if (document.documentElement.classList.contains('dark')) {
                document.documentElement.classList.remove('dark');
                localStorage.setItem('color-theme', 'light');
            } else {
                document.documentElement.classList.add('dark');
                localStorage.setItem('color-theme', 'dark');
            }
        });
		async function restartCore() {
			if (!await customConfirm('آیا از ری استارت پنل مطمئن هستید؟ کاربران شما لحظه ای قطع خواهند شد.')) return;
            
            const btn = document.querySelector('button[title="ری استارت پنل"]');
            if (btn) {
                btn.disabled = true;
                btn.classList.add('animate-pulse');
            }
            
            try {
                const res = await fetch('/api/restart-core', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const data = await res.json();
                if (res.status === 400 && data.error === "TOKEN_REQUIRED") {
					toggleTokenModal(true);
					if (btn) {
						btn.disabled = false;
						btn.classList.remove('animate-pulse');
					}
					return;
				}
                if (res.ok && data.success) {
                    alert('پنل ری استارت شد صفحه رفرش می شود.');
                    window.location.reload();
                } else {
                    alert('خطا در ری‌استارت پنل: ' + (data.error || 'ناشناخته'));
                    if (btn) {
                        btn.disabled = false;
                        btn.classList.remove('animate-pulse');
                    }
                }
            } catch (err) {
                alert('خطا در ارتباط با سرور.');
                if (btn) {
                    btn.disabled = false;
                    btn.classList.remove('animate-pulse');
                }
            }
        }
        async function loadUsers(silent = false) {
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
                const users = data.users || [];
                window.allUsers = users;
                const serverTime = data.serverTime || Date.now();
                window.lastServerTime = serverTime;
                const totalUsersCount = users.length;
                const activeUsersCount = users.reduce((sum, u) => sum + (u.online_count || 0), 0);
                const totalGbUsage = users.reduce((sum, u) => sum + (u.lifetime_used_gb || u.used_gb || 0), 0);
                document.getElementById('stat-total-users').innerText = totalUsersCount;
                document.getElementById('stat-active-users').innerText = activeUsersCount;
                document.getElementById('stat-total-usage').innerText = totalGbUsage < 1 ? (totalGbUsage * 1024).toFixed(0) + ' MB' : totalGbUsage.toFixed(2) + ' GB';
                let topUser = null;
let maxUsage = 0;

for (const u of users) {
    const usage = u.used_gb || 0;
    if (usage > maxUsage) {
        maxUsage = usage;
        topUser = u;
    }
}

const topUserElement = document.getElementById('stat-top-user');
const topUserUsageElement = document.getElementById('stat-top-user-usage');

if (topUser && topUser.username) {
    topUserElement.innerText = topUser.username;
    const topUsage = topUser.used_gb || 0;
    topUserUsageElement.innerText = topUsage < 1 ? (topUsage * 1024).toFixed(0) + ' MB مصرف شده' : topUsage.toFixed(2) + ' GB مصرف شده';
} else {
    topUserElement.innerText = '—';
    topUserUsageElement.innerText = '۰ GB مصرف شده';
}
// ====== پایان بخش پر مصرف‌ترین کاربر ======
                const cfRequests = data.cfRequestsToday || 0;
                const reqCard = document.getElementById('card-cf-requests');
                const warningBtn = document.getElementById('cf-warning-btn');
                if (cfRequests >= 90000) {
                    if (reqCard) {
                        reqCard.className = "bg-red-50 dark:bg-red-950/20 border border-red-500 rounded-xl p-2.5 shadow-[0_0_15px_rgba(239,68,68,0.4)] flex flex-col justify-center gap-1 hover:shadow-md transition duration-300 relative overflow-hidden group min-h-[64px] animate-pulse";
                    }
                    if (warningBtn) {
                        warningBtn.classList.remove('hidden');
                    }
                    const today = new Date().toISOString().split('T')[0];
                    if (localStorage.getItem('zeus_usage_warned_date') !== today) {
                        openUsageWarning();
                    }
                } else {
                    if (reqCard) {
                        reqCard.className = "bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-xl p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-orange-400 dark:hover:border-orange-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]";
                    }
                    if (warningBtn) {
                        warningBtn.classList.add('hidden');
                    }
                }
                const cfTotal = data.cfRequestsTotal || 0;
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
                    if (u.expiry_days && u.created_at) {
                        const created = new Date(u.created_at);
                        const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                        if (new Date(serverTime) > expiryDate) isExpired = true;
                    }
                    if (filterStatus === 'active') return isActive && !isExpired;
                    if (filterStatus === 'inactive') return !isActive;
                    if (filterStatus === 'online') return isOnline;
                    if (filterStatus === 'offline') return !isOnline;
                    if (filterStatus === 'expired') return isExpired || !isActive;
                    return true;
                });
            }
            filtered.sort((a, b) => {
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
                        if (!u.created_at) return Infinity;
                        const created = new Date(u.created_at);
                        const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
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

            let locationsMap = {};
            try {
                const cachedLocations = localStorage.getItem('cached_locations_list');
                if (cachedLocations) {
                    JSON.parse(cachedLocations).forEach(loc => {
                        if (loc.iata && loc.cca2) locationsMap[loc.iata.toUpperCase()] = loc.cca2;
                    });
                }
            } catch(e) {}
            if (users.length === 0) {
                loadingState.classList.add('hidden');
                emptyState.classList.remove('hidden');
                tableContainer.classList.add('hidden');
                if (window.allUsers && window.allUsers.length > 0) {
                    emptyState.querySelector('p').innerText = 'کاربری با مشخصات جستجو شده یافت نشد.';
                } else {
                    emptyState.querySelector('p').innerText = 'کاربری وجود ندارد. برای ساخت اولین کاربر روی دکمه « + » کلیک کنید.';
                }
            } else {
                loadingState.classList.add('hidden');
                emptyState.classList.add('hidden');
                tableContainer.classList.remove('hidden');
                
                let locationsMap = {};
                try {
                    const cachedLocations = localStorage.getItem('cached_locations_list');
                    if (cachedLocations) {
                        JSON.parse(cachedLocations).forEach(loc => {
                            if (loc.iata && loc.cca2) locationsMap[loc.iata.toUpperCase()] = loc.cca2;
                        });
                    }
                } catch(e) {}

                let proxyFlagCache = {};
                try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache') || '{}'); } catch(e) {}

                tbody.innerHTML = users.map(user => {
                    const createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString('fa-IR') : '-';
                    let daysRemaining = 'نامحدود';
                    let daysPercent = 100;
                    if (user.expiry_days) {
                        if (user.created_at) {
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
					    reqHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full rounded-full transition-all duration-500" style="height: ' + reqPercent + '%; background-color: hsl(' + reqHue + ', 80%, 45%)"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">مصرف: ' + usedReq.toLocaleString() + '</span>' +
					            '<span class="leading-none">کل: ' + user.limit_req.toLocaleString() + '</span>' +
					            '<button onclick="resetUserData(\\'' + encodeURIComponent(user.username) + '\\', \\'req\\')" class="mt-1 inline-block w-full text-center px-1 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors cursor-pointer">ریست</button>' +
					        '</div>' +
					    '</div>';
					} else {
					    reqHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full bg-blue-500 rounded-full transition-all duration-500" style="height: 100%"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">مصرف: ' + usedReq.toLocaleString() + '</span>' +
					            '<span class="leading-none">کل: نامحدود</span>' +
					            '<button onclick="resetUserData(\\'' + encodeURIComponent(user.username) + '\\', \\'req\\')" class="mt-1 inline-block w-full text-center px-1 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors cursor-pointer">ریست</button>' +
					        '</div>' +
					    '</div>';
					}
					let volumeHtml = '';
					if (user.limit_gb) {
					    const limitPercent = Math.min((usedGb / user.limit_gb) * 100, 100);
					    const limitHue = 120 - (limitPercent * 1.2);
					    const formattedLimit = user.limit_gb < 1 ? (user.limit_gb * 1024).toFixed(0) + ' MB' : user.limit_gb + ' GB';
					    volumeHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full rounded-full transition-all duration-500" style="height: ' + limitPercent + '%; background-color: hsl(' + limitHue + ', 80%, 45%)"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">مصرف: ' + formattedUsed + '</span>' +
					            '<span class="leading-none">کل: ' + formattedLimit + '</span>' +
					            '<button onclick="resetUserData(\\'' + encodeURIComponent(user.username) + '\\', \\'volume\\')" class="mt-1 inline-block w-full text-center px-1 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors cursor-pointer">ریست</button>' +
					        '</div>' +
					    '</div>';
					} else {
					    volumeHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full bg-blue-500 rounded-full transition-all duration-500" style="height: 100%"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">مصرف: ' + formattedUsed + '</span>' +
					            '<span class="leading-none">کل: نامحدود</span>' +
					            '<button onclick="resetUserData(\\'' + encodeURIComponent(user.username) + '\\', \\'volume\\')" class="mt-1 inline-block w-full text-center px-1 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors cursor-pointer">ریست</button>' +
					        '</div>' +
					    '</div>';
					}
					let expiryHtml = '';
					if (user.expiry_days) {
					    const expiryHue = daysPercent * 1.2;
					    expiryHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full rounded-full transition-all duration-500" style="height: ' + daysPercent + '%; background-color: hsl(' + expiryHue + ', 80%, 45%)"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">مانده: ' + daysRemaining + ' روز</span>' +
					            '<span class="leading-none">کل: ' + user.expiry_days + ' روز</span>' +
					            '<button onclick="resetUserData(\\'' + encodeURIComponent(user.username) + '\\', \\'time\\')" class="mt-1 inline-block w-full text-center px-1 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors cursor-pointer">ریست</button>' +
					        '</div>' +
					    '</div>';
					} else {
					    expiryHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full bg-blue-500 rounded-full transition-all duration-500" style="height: 100%"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">مانده: نامحدود</span>' +
					            '<span class="leading-none">کل: نامحدود</span>' +
					            '<button onclick="resetUserData(\\'' + encodeURIComponent(user.username) + '\\', \\'time\\')" class="mt-1 inline-block w-full text-center px-1 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors cursor-pointer">ریست</button>' +
					        '</div>' +
					    '</div>';
					}
					const onlineCount = user.online_count || 0;
					const limit = user.ip_limit !== undefined ? user.ip_limit : user.max_connections;
					let onlineHtml = '';
					if (limit) {
					    const onlinePercent = Math.min((onlineCount / limit) * 100, 100);
					    const onlineHue = 120 - (onlinePercent * 1.2);
					    onlineHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full rounded-full transition-all duration-500" style="height: ' + onlinePercent + '%; background-color: hsl(' + onlineHue + ', 80%, 45%)"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">متصل: ' + onlineCount + '</span>' +
					            '<span class="leading-none">سقف: ' + limit + '</span>' +
					        '</div>' +
					    '</div>';
					} else {
					    onlineHtml = '<div class="flex flex-row items-center gap-2 w-full min-w-[90px] select-none">' +
					        '<div class="w-2 h-20 bg-gray-200 dark:bg-zinc-700 rounded-full flex flex-col justify-end overflow-hidden flex-shrink-0">' +
					            '<div class="w-full ' + (onlineCount > 0 ? 'bg-green-600' : 'bg-gray-400') + ' rounded-full transition-all duration-500" style="height: 100%"></div>' +
					        '</div>' +
					        '<div class="flex flex-col justify-between h-20 text-[10px] text-gray-500 dark:text-gray-400 font-medium text-right flex-1 whitespace-nowrap">' +
					            '<span class="text-gray-800 dark:text-zinc-200 leading-none">متصل: ' + onlineCount + '</span>' +
					            '<span class="leading-none">سقف: نامحدود</span>' +
					        '</div>' +
					    '</div>';
					}
                    let isExpired = false;
                    if (user.limit_gb && (user.used_gb || 0) >= user.limit_gb) isExpired = true;
                    if (user.limit_req && (user.used_req || 0) >= user.limit_req) isExpired = true;
                    if (user.expiry_days && user.created_at) {
                        const created = new Date(user.created_at);
                        const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                        if (new Date(serverTime) > expiryDate) isExpired = true;
                    }
                    const isEffectivelyActive = user.is_active !== 0 && !isExpired;
                    const statusBtnColor = user.is_active === 0 ? 'text-green-700 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/30' : 'text-amber-600 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/30';
                    const statusBtnTitle = user.is_active === 0 ? 'فعال کردن کاربر' : 'قطع کردن کاربر';
                    const statusBtnIcon = user.is_active === 0 
                        ? '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
                        : '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
                    const isChecked = (window.selectedUsernames && window.selectedUsernames.has(user.username)) ? 'checked' : '';
                    
                    
                    let locBadge = '';
                    if (user.user_proxy_iata) {
                        const iata = user.user_proxy_iata.toUpperCase();
                        const cca2 = locationsMap[iata];
                        const flag = cca2 ? getFlagEmoji(cca2) : '🌐';
                        locBadge = '<span title="کشور: ' + iata + '" class="text-xl leading-none px-0.5 drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)]">' + flag + '</span>';
                    } else if (user.user_socks5 || user.user_proxy_ip) {
                        const targetProxy = user.user_socks5 || user.user_proxy_ip;
                        const cachedFlag = proxyFlagCache[targetProxy];
                        if (cachedFlag) {
                            locBadge = '<span title="پروکسی اختصاصی" class="text-xl leading-none px-0.5 drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)]">' + cachedFlag + '</span>';
                        } else {
                            locBadge = '<span data-proxy="' + targetProxy + '" title="پروکسی اختصاصی" class="async-proxy-flag text-xl leading-none px-0.5 drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)]">⏳</span>';
                        }
                    }

                    return '<tr class="hover:bg-gray-50 dark:hover:bg-zinc-900/40 border-b border-gray-100 dark:border-zinc-800 last:border-0">' +
                            '<td class="p-2 border-r border-gray-100 dark:border-zinc-800 text-center select-none">' +
                                '<input type="checkbox" name="select-user" value="' + encodeURIComponent(user.username) + '" onchange="onUserSelectChange(this)" ' + isChecked + ' class="w-5 h-5 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-blue-600 bg-white dark:bg-zinc-800 checked:bg-blue-600 checked:border-blue-600 focus:ring-blue-500/50 focus:ring-offset-0 transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95">' +
                            '</td>' +
                            '<td class="p-2 border-r border-gray-100 dark:border-zinc-800 text-center">' +
                                '<div class="flex flex-col items-center gap-1.5 w-[165px] mx-auto select-none">' +
                                    '<span class="font-bold text-gray-900 dark:text-zinc-100 text-sm truncate max-w-full">' + user.username + '</span>' +
                                    '<div class="flex flex-nowrap items-center gap-1 w-full justify-center text-center whitespace-nowrap">' +
                                        (!isEffectivelyActive ? '<span class="px-1 py-0.5 text-[10px] font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 rounded-md whitespace-nowrap">غیرفعال</span>' : '<span class="px-1 py-0.5 text-[10px] font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 rounded-md whitespace-nowrap">فعال</span>') +
                                        locBadge +
                                        (user.is_online === 1 ? '<span class="px-1 py-0.5 text-[10px] font-medium bg-green-600 text-white rounded-md animate-pulse whitespace-nowrap" dir="rtl">' + user.online_count + '</span>' : '<span class="px-1 py-0.5 text-[10px] font-medium bg-gray-200 text-gray-600 dark:bg-zinc-800 dark:text-zinc-400 rounded-md whitespace-nowrap">آفلاین</span>') +
                                    '</div>' +
                                    '<div class="grid grid-cols-2 gap-1 w-full">' +
                                        '<button onclick="copyConfig(\\'' + encodeURIComponent(user.username) + '\\')" title="کپی کانفیگ" class="p-1.5 flex items-center justify-center bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-blue-50 dark:hover:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button>' +
                                        '<button onclick="editUser(\\'' + encodeURIComponent(user.username) + '\\')" title="ویرایش" class="p-1.5 flex items-center justify-center bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-yellow-50 dark:hover:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg></button>' +
                                        '<button onclick="deleteUser(\\'' + encodeURIComponent(user.username) + '\\')" title="حذف" class="p-1.5 flex items-center justify-center bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-red-50 dark:hover:bg-red-950/20 text-red-600 dark:text-red-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>' +
                                        '<button onclick="toggleUserStatus(\\'' + encodeURIComponent(user.username) + '\\')" title="' + statusBtnTitle + '" class="p-1.5 flex items-center justify-center bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 ' + statusBtnColor + ' rounded-md transition shadow-sm">' + statusBtnIcon + '</button>' +
                                    '</div>' +
                                '</div>' +
                            '</td>' +
                            							'<td class="p-2 border-r border-gray-100 dark:border-zinc-800">' +
							    '<div class="flex flex-col gap-2 w-max mx-auto">' +
							        '<div class="flex gap-1">' +
							            '<button onclick="copySubLink(\\'' + encodeURIComponent(user.username) + '\\')" class="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 rounded-lg text-xs font-bold transition border border-indigo-200 dark:border-indigo-800">' +
							                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>' +
							                'ساب متنی' +
							            '</button>' +
							        '</div>' +
									'<div class="flex gap-1">' +
							            '<button onclick="showSubQr(\\'' + encodeURIComponent(user.username) + '\\')" class="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/50 rounded-lg text-xs font-bold transition border border-amber-200 dark:border-amber-800">' +
							                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg>' +
							                'QR ساب' +
							            '</button>' +
							        '</div>' +
							        '<div class="flex gap-1">' +
							            '<button onclick="copyStatusLink(\\'' + encodeURIComponent(user.username) + '\\')" class="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-500 hover:bg-green-100 dark:hover:bg-green-900/50 rounded-lg text-xs font-bold transition border border-green-200 dark:border-green-800">' +
							                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>' +
							                'صفحه وضعیت' +
							            '</button>' +
							        '</div>' +
							    '</div>' +
							'</td>' +
							'<td class="p-2 border-r border-gray-100 dark:border-zinc-800 text-xs">' + 
							    '<div class="grid grid-flow-col grid-rows-5 gap-1.5 w-fit mx-auto">' +
							        String(user.port || "").split(",").map(function(p) {
							            p = p.trim();
							            if (!p) return "";
							            var isTls = tlsPorts.includes(p);
							            return '<span class="inline-block w-10 text-center px-1 py-0.5 text-[10px] font-semibold rounded ' + (isTls ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400' : 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400') + '">' + p + '</span>';
							        }).join("") +
							    '</div>' +
							'</td>' +
							'<td class="p-2 border-r border-gray-100 dark:border-zinc-800">' + volumeHtml + '</td>' +
							'<td class="p-2 border-r border-gray-100 dark:border-zinc-800">' + reqHtml + '</td>' +
							'<td class="p-2 border-r border-gray-100 dark:border-zinc-800">' + expiryHtml + '</td>' +
							'<td class="p-2 border-r border-gray-100 dark:border-zinc-800">' + onlineHtml + '</td>' +
                            '<td class="p-2 border-r border-gray-100 dark:border-zinc-800 text-xs text-gray-500 text-center">' + createdDate + '</td>'
							'</tr>';
                }).join('');
                updateBulkActionsBar();

                if (typeof loadProxyFlags === 'function') {
                    setTimeout(loadProxyFlags, 50);
                }
            }
        }
		async function resetUserData(encodedUsername, actionType) {
			const username = decodeURIComponent(encodedUsername);
			let actionName = '';
			if (actionType === 'volume') actionName = 'حجم';
			else if (actionType === 'req') actionName = 'ریکوئست';
			else if (actionType === 'time') actionName = 'زمان';
			if (await customConfirm('آیا از ریست کردن ' + actionName + ' کاربر ' + username + ' مطمئن هستید؟')) {
                try {
                    const response = await fetch('/api/users/' + encodeURIComponent(username), {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ reset_action: actionType })
                    });
                    if (response.ok) {
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
        async function handleFormSubmit(event) {
            event.preventDefault();
            const submitButton = document.getElementById('submit-btn');
            submitButton.disabled = true;
            submitButton.innerText = isEditMode ? 'در حال ذخیره تغییرات...' : 'در حال ایجاد...';
            const username = document.getElementById('input-name').value;
            const limit = document.getElementById('input-limit').value || null;
            const expiry = document.getElementById('input-expiry').value || null;
            const reqLimit = document.getElementById('input-req-limit').value || null;
            const ipLimit = document.getElementById('input-ip-limit').value || null;
            const customPortsRaw = document.getElementById('input-custom-ports') ? document.getElementById('input-custom-ports').value : '';
			const customPortsArray = customPortsRaw.replace(/ +/g, ',').split(',').map(p => p.trim()).filter(p => p.length > 0);
			const checkedPorts = Array.from(document.querySelectorAll('input[name="ports"]:checked')).map(cb => cb.value).concat(customPortsArray);
            const block_porn = document.getElementById('input-block-porn').checked ? 1 : 0;
            const block_ads = document.getElementById('input-block-ads').checked ? 1 : 0;
            const isFragEnabled = document.getElementById('input-frag-toggle').checked;
            const frag_len = isFragEnabled ? (document.getElementById('input-frag-len').value || "200-3000") : "";
            const frag_int = isFragEnabled ? (document.getElementById('input-frag-int').value || "1-2") : "";
            
            // گرفتن مقادیر لوکیشن اختصاصی
            const userProxyMode = document.getElementById('user-proxy-mode-toggle') ? document.getElementById('user-proxy-mode-toggle').checked : false;
            const userProxyIata = !userProxyMode ? (document.getElementById('user-location-select') ? document.getElementById('user-location-select').value : null) : null;
            const userSocks5 = userProxyMode ? (document.getElementById('user-socks5-input') ? document.getElementById('user-socks5-input').value.trim() : null) : null;

            if (checkedPorts.length === 0) {
                alert('⚠️ لطفا حداقل یک پورت را برای اتصال انتخاب کنید!');
                submitButton.disabled = false;
                submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر';
                return;
            }
            const port = checkedPorts.join(',');
            const tls = checkedPorts.some(p => tlsPorts.includes(p)) ? 'on' : 'off';
            const ips = document.getElementById('input-ips').value;
            const fingerprint = document.getElementById('fingerprint-select').value;
            const url = isEditMode ? '/api/users/' + encodeURIComponent(editingUsername) : '/api/users';
            const method = isEditMode ? 'PUT' : 'POST';
            try {
                const response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username, limit_gb: limit, expiry_days: expiry, limit_req: reqLimit, tls, port, ips, fingerprint, ip_limit: ipLimit, block_porn: block_porn, block_ads: block_ads, frag_len: frag_len, frag_int: frag_int,
                        user_proxy_iata: userProxyIata || null,
                        user_socks5: userSocks5 || null,
                        user_proxy_ip: null
                    })
                });
                if (response.ok) {
                    toggleModal(false);
                    await loadUsers(true);
                } else {
                    const errData = await response.json();
                    alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            } finally {
                submitButton.disabled = false;
                submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر';
            }
        }
function closePathWarning() {
    const modal = document.getElementById('path-warning-modal');
    const card = modal.querySelector('div');
    modal.classList.remove('opacity-100', 'pointer-events-auto');
    modal.classList.add('opacity-0', 'pointer-events-none');
    card.classList.remove('opacity-100', 'scale-100');
    card.classList.add('opacity-0', 'scale-95');
    localStorage.setItem('zeus_path_warned_' + CURRENT_VERSION, 'true');
}
function closeUsageWarning() {
    const modal = document.getElementById('usage-warning-modal');
    const card = modal.querySelector('div');
    modal.classList.remove('opacity-100', 'pointer-events-auto');
    modal.classList.add('opacity-0', 'pointer-events-none');
    card.classList.remove('opacity-100', 'scale-100');
    card.classList.add('opacity-0', 'scale-95');
    const today = new Date().toISOString().split('T')[0];
    localStorage.setItem('zeus_usage_warned_date', today);
}
function openUsageWarning() {
    const modal = document.getElementById('usage-warning-modal');
    const card = modal.querySelector('div');
    modal.classList.remove('opacity-0', 'pointer-events-none');
    modal.classList.add('opacity-100', 'pointer-events-auto');
    card.classList.remove('opacity-0', 'scale-95');
    card.classList.add('opacity-100', 'scale-100');
}
function closeFreePanelWarning() {
    const modal = document.getElementById('free-panel-warning-modal');
    const card = modal.querySelector('div');
    modal.classList.remove('opacity-100', 'pointer-events-auto');
    modal.classList.add('opacity-0', 'pointer-events-none');
    card.classList.remove('opacity-100', 'scale-100');
    card.classList.add('opacity-0', 'scale-95');
}
function getVlessLink(username) {
            const user = window.allUsers.find(u => u.username === username);
            if (!user) return '';
            const host = window.location.hostname;
            let ips = [host];
            if (user.ips) {
                const parsedIps = user.ips.split('\\n').map(ip => ip.trim()).filter(ip => ip.length > 0);
                if (parsedIps.length > 0) ips = parsedIps;
            }
            const ports = String(user.port || '443').split(',').map(p => p.trim()).filter(p => p.length > 0);
            const fp = user.fingerprint || 'chrome';
            const userFrag = (user.frag_len && user.frag_int) ? '&fragment=' + user.frag_len + ',' + user.frag_int : '';
            const links = [];
            ips.forEach((ip) => {
                ports.forEach((portStr) => {
                    const isTlsPort = tlsPorts.includes(portStr);
                    const tlsVal = isTlsPort ? 'tls' : 'none';
                    const remark = user.username;
                    links.push('vle' + 'ss://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=/&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + userFrag + '#' + encodeURIComponent(remark));
                });
            });
            return links.join('\\n');
        }
        function getSubLink(username) {
            return window.location.origin + '/feed/' + encodeURIComponent(username);
        }
        function getStatusLink(username) {
            return window.location.origin + '/status/' + encodeURIComponent(username);
        }
        function copySubLink(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            navigator.clipboard.writeText(getSubLink(username)).then(() => {
                alert('✅ لینک ساب متنی با موفقیت کپی شد!');
            }).catch(() => {
                alert('خطا در کپی کردن لینک ساب!');
            });
        }
		function toggleQrModal(show, text) {
            const modal = document.getElementById('qr-modal');
            const card = document.getElementById('qr-modal-card');
            const container = document.getElementById('qrcode-container');
            if (show) {
                container.innerHTML = '';
                new QRCode(container, {
                    text: text,
                    width: 200,
                    height: 200,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
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

        function showSubQr(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            const link = getSubLink(username);
            toggleQrModal(true, link);
        }
        function copyStatusLink(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            navigator.clipboard.writeText(getStatusLink(username)).then(() => {
                alert('✅ لینک صفحه وضعیت با موفقیت کپی شد!');
            }).catch(() => {
                alert('خطا در کپی کردن لینک صفحه وضعیت!');
            });
        }
        function copyConfig(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            const link = getVlessLink(username);
            if (!link) return;
            navigator.clipboard.writeText(link).then(() => {
                alert('✅ کانفیگ VLESS با موفقیت کپی شد!');
            }).catch(() => {
                alert('خطا در کپی کردن کانفیگ!');
            });
        }
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
    document.getElementById('submit-btn').innerText = 'ذخیره تغییرات';
    
    const nameInput = document.getElementById('input-name');
    nameInput.value = username;
    nameInput.disabled = false;
    document.getElementById('input-limit').value = user.limit_gb || '';
    document.getElementById('input-expiry').value = user.expiry_days || '';
    document.getElementById('input-req-limit').value = user.limit_req || '';
    document.getElementById('input-ip-limit').value = user.ip_limit !== undefined ? (user.ip_limit || '') : (user.max_connections || '');
    document.getElementById('input-ips').value = user.ips || '';
    document.getElementById('fingerprint-select').value = user.fingerprint || 'chrome';
    
    document.getElementById('input-block-porn').checked = (user.block_porn === 1);
    document.getElementById('input-block-ads').checked = (user.block_ads === 1);
    
    const hasFrag = Boolean(user.frag_len && user.frag_len !== "" && user.frag_int && user.frag_int !== "");
    const fragToggle = document.getElementById('input-frag-toggle');
    if (fragToggle) fragToggle.checked = hasFrag;
    
    document.getElementById('input-frag-len').value = hasFrag ? user.frag_len : '200-3000';
    document.getElementById('input-frag-int').value = hasFrag ? user.frag_int : '1-2';
    window.toggleFragInputs(hasFrag);

    const userPorts = String(user.port || '').split(',').map(p => p.trim());
    const predefinedPorts = [...tlsPorts, ...nonTlsPorts];
    const customPorts = userPorts.filter(p => !predefinedPorts.includes(p) && p !== '');

    document.querySelectorAll('input[name="ports"]').forEach(cb => {
        cb.checked = userPorts.includes(cb.value);
    });

    const customPortInput = document.getElementById('input-custom-ports');
    if (customPortInput) customPortInput.value = customPorts.join(' ');

    const userProxyToggle = document.getElementById('user-proxy-mode-toggle');
    const userLocSelect = document.getElementById('user-location-select');
    const userSocksInput = document.getElementById('user-socks5-input');

	const targetProxy = user.user_socks5 || user.user_proxy_ip;
	const userProxyResult = document.getElementById('test-user-proxy-result');
	if (userProxyResult) userProxyResult.innerText = '';

	if (targetProxy) {
		if (userProxyToggle) userProxyToggle.checked = true;
		if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(true);
		if (userSocksInput) userSocksInput.value = targetProxy;
		if (userLocSelect) userLocSelect.value = '';
	} else {
		if (userProxyToggle) userProxyToggle.checked = false;
		if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(false);
		if (userSocksInput) userSocksInput.value = '';
		if (userLocSelect) userLocSelect.value = user.user_proxy_iata || '';
	}

	toggleModal(true);
}
        async function deleteUser(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			if (await customConfirm('آیا از حذف کاربر ' + username + ' مطمئن هستید؟')) {
                try {
                    const response = await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
                    if (response.ok) {
                        alert('✅ کاربر با موفقیت حذف شد.');
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
            if (!countryCode) return '🌐';
            const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
            try {
                return String.fromCodePoint(...codePoints);
            } catch (e) {
                return '🌐';
            }
        }
        function renderLocationsUI(locations, activeIata) {
            const select = document.getElementById('location-select');
            const userSelect = document.getElementById('user-location-select');
            locations.sort((a, b) => (a.cca2 || '').localeCompare(b.cca2 || ''));
            
            let html = '<option value="">🌐 پیش‌فرض (لوکیشن خودکار)</option>';
            let userHtml = '<option value="">🌐 استفاده از تنظیمات عمومی پنل</option>';
            
            locations.forEach(loc => {
                if (loc.iata && loc.city) {
                    const flag = getFlagEmoji(loc.cca2);
                    const isSelected = loc.iata.toUpperCase() === activeIata.toUpperCase() ? 'selected' : '';
                    const optionStr = '<option value="' + loc.iata + '" ' + isSelected + '>' + flag + ' ' + loc.city + ' (' + loc.iata + ')</option>';
                    html += optionStr;
                    userHtml += '<option value="' + loc.iata + '">' + flag + ' ' + loc.city + ' (' + loc.iata + ')</option>';
                }
            });
            if (select) select.innerHTML = html;
            if (userSelect) userSelect.innerHTML = userHtml;
        }
async function loadLocations() {
    const select = document.getElementById('location-select');
    const cachedLocations = localStorage.getItem('cached_locations_list');
    const cachedActiveIata = localStorage.getItem('cached_active_iata') || '';
    let hasCachedLocs = false;
    if (cachedLocations) {
        try {
            const parsedLocs = JSON.parse(cachedLocations);
            if (Array.isArray(parsedLocs) && parsedLocs.length > 0) {
                renderLocationsUI(parsedLocs, cachedActiveIata);
                hasCachedLocs = true;
            }
        } catch(e) {}
    }
    
    try {
        const locRes = await fetch('/locations');
        if (locRes.ok) {
            const locData = await locRes.json();
            if (Array.isArray(locData) && locData.length > 0) {
                localStorage.setItem('cached_locations_list', JSON.stringify(locData));
                hasCachedLocs = true;
            }
        }
    } catch(e) {}

    try {
        const statusRes = await fetch('/api/proxy-ip');
        let activeIata = '';
        if (statusRes.ok) {
            const statusData = await statusRes.json();
            activeIata = statusData.iata || '';
            localStorage.setItem('cached_active_iata', activeIata);
            
            const socksInput = document.getElementById('socks5-input');
            const proxyToggle = document.getElementById('proxy-mode-toggle');
            
            if (statusData.socks5) {
                if (socksInput) socksInput.value = statusData.socks5;
                if (proxyToggle) {
                    proxyToggle.checked = true;
                    if (typeof window.toggleProxyMode === 'function') window.toggleProxyMode(true);
                }
            } else {
                if (socksInput) socksInput.value = '';
                if (proxyToggle) {
                    proxyToggle.checked = false;
                    if (typeof window.toggleProxyMode === 'function') window.toggleProxyMode(false);
                }
            }
        }
        
        const updatedCachedLocs = localStorage.getItem('cached_locations_list');
        if (updatedCachedLocs) {
            const parsed = JSON.parse(updatedCachedLocs);
            renderLocationsUI(parsed, activeIata);
        }
    } catch (err) {
        if (!hasCachedLocs) {
            select.innerHTML = '<option value="">⚠️ خطا در دریافت لوکیشن‌ها</option>';
        }
    }
}
async function saveSettings() {
    const proxyModeToggle = document.getElementById('proxy-mode-toggle');
    const isProxyMode = proxyModeToggle ? proxyModeToggle.checked : false;
    const select = document.getElementById('location-select');
    const socksInput = document.getElementById('socks5-input');
    const socks5Proxy = (isProxyMode && socksInput) ? socksInput.value.trim() : '';
    let iata = (!isProxyMode && select) ? select.value : '';
    const btn = document.getElementById('save-settings-btn');
    btn.disabled = true;
    btn.innerText = 'در حال ذخیره...';
    try {
        let resolvedIp = 'proxyip.cmliussss.net';
        if (iata) {
            const domain = iata.toLowerCase() + '.proxyip.cmliussss.net';
            const dnsRes = await fetch('https://cloudflare-dns.com/dns-query?name=' + domain + '&type=A', {
                headers: { 'accept': 'application/dns-json' }
            });
            resolvedIp = domain;
            if (dnsRes.ok) {
                const dnsData = await dnsRes.json();
                if (dnsData.Answer && dnsData.Answer.length > 0) {
                    const ips = dnsData.Answer.filter(ans => ans.type === 1).map(ans => ans.data);
                    if (ips.length > 0) {
                        resolvedIp = ips[Math.floor(Math.random() * ips.length)];
                    }
                }
            }
        }
        const response = await fetch('/api/proxy-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proxy_ip: resolvedIp, iata: iata ? iata.toUpperCase() : '', socks5: socks5Proxy })
        });
        if (response.ok) {
            alert('✅ تنظیمات با موفقیت ذخیره شد.\\n' + (isProxyMode ? 'آی‌پی با پروکسی ثابت شد.' : (iata ? 'آی‌پی پروکسی کلودفلر: ' + resolvedIp : 'آدرس پروکسی به حالت پیش‌فرض بازگشت.')));
            toggleSettingsModal(false);
        } else {
            alert('خطا در ذخیره تنظیمات');
        }
    } catch (err) {
        alert('خطا در برقراری ارتباط با سرور');
    } finally {
        btn.disabled = false;
        btn.innerText = 'ذخیره تنظیمات';
    }
}
async function testSocksProxy() {
	const btn = document.getElementById('test-proxy-btn');
	const resultSpan = document.getElementById('test-proxy-result');
	const proxyStr = document.getElementById('socks5-input').value.trim();
	if (!proxyStr) {
		resultSpan.innerText = 'وارد نشده!';
		resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1';
		return;
	}
	btn.disabled = true;
	btn.innerText = 'صبر کنید...';
	resultSpan.innerText = '';
	resultSpan.className = 'text-[11px] font-bold transition-colors empty:hidden';
	
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), 5000);

	try {
		const res = await fetch('/api/test-proxy', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ proxy: proxyStr }),
			signal: controller.signal
		});
		clearTimeout(timeoutId);
		const data = await res.json();
		if (res.ok && data.success) {
			const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(data.country) : '🌐';
			resultSpan.innerText = flag + ' پینگ: ' + data.ping + 'ms';
			resultSpan.className = 'text-[11px] font-bold text-green-600';
		} else {
			resultSpan.innerText = 'خطا: ' + (data.error || 'ناموفق');
			resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
		}
	} catch (e) {
		clearTimeout(timeoutId);
		if (e.name === 'AbortError') {
			resultSpan.innerText = 'تایم‌اوت (پروکسی خراب است)';
		} else {
			resultSpan.innerText = 'خطا در ارتباط';
		}
		resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
	} finally {
		btn.disabled = false;
		btn.innerText = 'تست پروکسی';
	}
}

window.toggleProxyMode = function(isSocksMode) {
    const cfSection = document.getElementById('cf-proxy-section');
    const socksContainer = document.getElementById('socks5-container');
    const locationSelect = document.getElementById('location-select');
    const locationSearch = document.getElementById('location-search');
    const socksInput = document.getElementById('socks5-input');

    if (isSocksMode) {
        if (cfSection) cfSection.classList.add('opacity-50', 'pointer-events-none');
        if (locationSelect) locationSelect.disabled = true;
        if (locationSearch) locationSearch.disabled = true;

        if (socksContainer) socksContainer.classList.remove('opacity-50', 'pointer-events-none');
        if (socksInput) socksInput.disabled = false;
    } else {
        if (cfSection) cfSection.classList.remove('opacity-50', 'pointer-events-none');
        if (locationSelect) locationSelect.disabled = false;
        if (locationSearch) locationSearch.disabled = false;

        if (socksContainer) socksContainer.classList.add('opacity-50', 'pointer-events-none');
        if (socksInput) socksInput.disabled = true;
    }
};
window.toggleUserProxyMode = function(isSocksMode) {
    const cfSection = document.getElementById('user-cf-proxy-section');
    const socksContainer = document.getElementById('user-socks5-container');
    const locationSelect = document.getElementById('user-location-select');
    const locationSearch = document.getElementById('user-location-search');
    const socksInput = document.getElementById('user-socks5-input');

    if (isSocksMode) {
        if (cfSection) cfSection.classList.add('opacity-50', 'pointer-events-none');
        if (locationSelect) locationSelect.disabled = true;
        if (locationSearch) locationSearch.disabled = true;
        if (socksContainer) socksContainer.classList.remove('opacity-50', 'pointer-events-none');
        if (socksInput) socksInput.disabled = false;
    } else {
        if (cfSection) cfSection.classList.remove('opacity-50', 'pointer-events-none');
        if (locationSelect) locationSelect.disabled = false;
        if (locationSearch) locationSearch.disabled = false;
        if (socksContainer) socksContainer.classList.add('opacity-50', 'pointer-events-none');
        if (socksInput) socksInput.disabled = true;
    }
};
async function loadProxyFlags() {
    const badges = document.querySelectorAll('.async-proxy-flag');
    if (badges.length === 0) return;
    
    let cache = {};
    try { cache = JSON.parse(localStorage.getItem('proxy_flag_cache') || '{}'); } catch(e) {}

    for (let badge of badges) {
        const proxyStr = badge.getAttribute('data-proxy');
        if (!proxyStr) continue;

        if (cache[proxyStr]) {
            badge.innerHTML = cache[proxyStr];
            badge.classList.remove('async-proxy-flag');
            continue;
        }

        badge.classList.remove('async-proxy-flag');

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 4000);
            const res = await fetch('/api/test-proxy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ proxy: proxyStr }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            const data = await res.json();
            
            let flag = '🌐';
            if (res.ok && data.success && data.country) {
                flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(data.country) : '🌐';
            }
            
            cache[proxyStr] = flag;
            localStorage.setItem('proxy_flag_cache', JSON.stringify(cache));
            
            badge.innerHTML = flag;
        } catch (e) {
            badge.innerHTML = '🌐';
        }
    }
}
window.filterUserLocations = function() {
    const searchTerm = document.getElementById('user-location-search').value.toLowerCase().trim();
    const cachedLocations = localStorage.getItem('cached_locations_list');
    
    if (!cachedLocations) return;
    
    try {
        const allLocations = JSON.parse(cachedLocations);
        const filteredLocations = allLocations.filter(loc => {
            if (!loc.iata || !loc.city) return false;
            const searchString = (loc.iata + ' ' + loc.city + ' ' + (loc.cca2 || '')).toLowerCase();
            return searchString.includes(searchTerm);
        });
        
        const userSelect = document.getElementById('user-location-select');
        let userHtml = '<option value="">🌐 استفاده از تنظیمات عمومی پنل</option>';
        filteredLocations.forEach(loc => {
            const flag = getFlagEmoji(loc.cca2);
            userHtml += '<option value="' + loc.iata + '">' + flag + ' ' + loc.city + ' (' + loc.iata + ')</option>';
        });
        if (userSelect) userSelect.innerHTML = userHtml;
    } catch(e) {}
};

async function testUserSocksProxy() {
	const btn = document.getElementById('test-user-proxy-btn');
	const resultSpan = document.getElementById('test-user-proxy-result');
	const proxyStr = document.getElementById('user-socks5-input').value.trim();
	if (!proxyStr) {
		resultSpan.innerText = 'وارد نشده!';
		resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1';
		return;
	}
	btn.disabled = true;
	btn.innerText = 'صبر کنید...';
	resultSpan.innerText = '';
	
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), 5000);

	try {
		const res = await fetch('/api/test-proxy', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ proxy: proxyStr }),
			signal: controller.signal
		});
		clearTimeout(timeoutId);
		const data = await res.json();
		if (res.ok && data.success) {
			const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(data.country) : '🌐';
			resultSpan.innerText = flag + ' پینگ: ' + data.ping + 'ms';
			resultSpan.className = 'text-[11px] font-bold text-green-600';
		} else {
			resultSpan.innerText = 'خطا: ' + (data.error || 'ناموفق');
			resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
		}
	} catch (e) {
		clearTimeout(timeoutId);
		if (e.name === 'AbortError') resultSpan.innerText = 'تایم‌اوت (پروکسی خراب است)';
		else resultSpan.innerText = 'خطا در ارتباط';
		resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
	} finally {
		btn.disabled = false;
		btn.innerText = 'تست پروکسی';
	}
}
window.filterLocations = function() {
    const searchTerm = document.getElementById('location-search').value.toLowerCase().trim();
    const cachedLocations = localStorage.getItem('cached_locations_list');
    const activeIata = localStorage.getItem('cached_active_iata') || '';
    
    if (!cachedLocations) return;
    
    try {
        const allLocations = JSON.parse(cachedLocations);
        const filteredLocations = allLocations.filter(loc => {
            if (!loc.iata || !loc.city) return false;
            const searchString = (loc.iata + ' ' + loc.city + ' ' + (loc.cca2 || '')).toLowerCase();
            return searchString.includes(searchTerm);
        });
        renderLocationsUI(filteredLocations, activeIata);
    } catch(e) {}
};
        async function exportUsersBackup() {
            if (!window.allUsers || window.allUsers.length === 0) {
                alert('⚠️ کاربری برای پشتیبان‌گیری وجود ندارد!');
                return;
            }
            try {
                const settingsRes = await fetch('/api/settings/bulk');
                const settingsData = await settingsRes.json();
                const backupData = {
                    users: window.allUsers,
                    settings: settingsData
                };
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(backupData, null, 2));
                const downloadAnchor = document.createElement('a');
                const dateStr = new Date().toISOString().split('T')[0];
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", "zeus_full_backup_" + dateStr + ".json");
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
            } catch (err) {
                alert('❌ خطا در دریافت تنظیمات برای بک‌آپ.');
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
                        const restoreSettings = await customConfirm('⚙️ فایل بک‌آپ شامل تنظیمات پنل نیز می‌باشد. آیا می‌خواهید تنظیمات هم بازگردانی شوند؟');
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
                    for (const u of validBackupUsers) {
                        currentStep++;
                        if (importBtn) {
                            importBtn.innerText = '⏳ بازیابی (' + currentStep + '/' + validBackupUsers.length + ')';
                        }
                        const exists = existingUsernames.has(u.username);
                        if (exists) {
                            if (overwrite) {
                                try {
                                    await fetch('/api/users/' + encodeURIComponent(u.username), { method: 'DELETE' });
                                    const res = await fetch('/api/users', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({
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
                                            frag_int: u.frag_int
                                        })
                                    });
                                    if (res.ok) successCount++;
                                } catch(err) {}
                            }
                        } else {
                            try {
                                const res = await fetch('/api/users', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({
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
                                        frag_int: u.frag_int
                                    })
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
            const currentPwd = document.getElementById('change-pwd-current').value;
            const newPwd = document.getElementById('change-pwd-new').value;
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
			if (await customConfirm('آیا می‌خواهید از پنل خارج شوید؟ ⚠️ ')) {
                try {
                    await fetch('/api/logout', { method: 'POST' });
                } catch (err) {}
                window.location.reload();
            }
        }
const CURRENT_VERSION = '1.8.3';
const UPDATE_FIX = "constsCURRENT_VERSION='d.d.d'";
		async function checkForUpdates(isManual = false) {
            try {
                if (isManual) {
                    document.getElementById('update-toggle').classList.add('animate-pulse');
                }
                const res = await fetch('https://raw.githubusercontent.com/sepehr-gamer/Zeus-pannel/refs/heads/main/zeus.js?t=' + Date.now());
                if (!res.ok) throw new Error('Network response was not ok');
                const text = await res.text();
                const match = text.match(/const\\s+CURRENT_VERSION\\s*=\\s*['"](\\d+\\.\\d+\\.\\d+)['"]/i);
                const latestVersion = match ? match[1] : null;
                if (isManual) {
                    document.getElementById('update-toggle').classList.remove('animate-pulse');
                }
                if (latestVersion && latestVersion !== CURRENT_VERSION) {
                    document.getElementById('update-toggle').className = "p-2 rounded-lg bg-red-100 dark:bg-red-900/60 border border-red-500 hover:bg-red-200 dark:hover:bg-red-900/80 transition text-red-700 dark:text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.6)] animate-pulse relative";
                    const badge = document.getElementById('update-badge');
                    if (badge) badge.remove();
                    if (isManual) {
                        toggleUpdateModal(true, latestVersion);
                    }
                } else {
                    if (isManual) {
                        alert('شما در حال استفاده از آخرین نسخه (v' + CURRENT_VERSION + ') هستید.');
                    }
                }
            } catch (err) {
                if (isManual) {
                    document.getElementById('update-toggle').classList.remove('animate-pulse');
                    alert('خطا در بررسی آپدیت از گیت هاب.');
                }
            }
        }
        function toggleTokenModal(show) {
            const modal = document.getElementById('token-modal');
            const card = document.getElementById('token-modal-card');
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
                document.getElementById('update-token-input').value = '';
            }
        }

        function submitTokenForUpdate() {
            const token = document.getElementById('update-token-input').value.trim();
            if (!token) {
                alert('لطفاً توکن را وارد کنید.');
                return;
            }
            toggleTokenModal(false);
            applyUpdate(token);
        }

        async function applyUpdate(token = null) {
            if (!token) toggleUpdateModal(false);
            const btn = document.getElementById('update-toggle');
            btn.disabled = true;
            if (!token) alert('در حال دریافت و اعمال آپدیت... لطفاً چند ثانیه صبر کنید.');
            try {
                const reqBody = token ? JSON.stringify({ cf_token: token }) : "{}";
                const res = await fetch('/api/update-panel', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: reqBody
                });
                const data = await res.json();
                if (res.status === 400 && data.error === "TOKEN_REQUIRED") {
                    toggleTokenModal(true);
                    btn.disabled = false;
                    return;
                }
                if (res.ok && data.success) {
                    const successModal = document.getElementById('update-success-modal');
                    const successCard = successModal.querySelector('div');
                    
                    successModal.classList.remove('opacity-0', 'pointer-events-none');
                    successModal.classList.add('opacity-100', 'pointer-events-auto');
                    successCard.classList.remove('opacity-0', 'scale-95');
                    successCard.classList.add('opacity-100', 'scale-100');
                    
                    setTimeout(() => {
                        window.location.reload();
                    }, 10000);
                } else {
                    alert('خطا در بروزرسانی. لطفاً با استفاده از دکمه "آپدیت دستی" اقدام کنید.');
                    btn.disabled = false;
                }
            } catch (err) {
                alert('خطا در ارتباط با سرور. لطفاً از گزینه آپدیت دستی استفاده کنید.');
                btn.disabled = false;
            }
        }
let cachedIpsData = {};
async function fetchIpsList() {
    try {
        const response = await fetch('https://raw.githubusercontent.com/sepehr-gamer/Zeus-pannel/refs/heads/main/ips.txt?t=' + Date.now() + Math.random());
        if (!response.ok) throw new Error('Fetch failed');
        const text = await response.text();
        const blocks = text.split('----------');
        cachedIpsData = {};
        blocks.forEach(block => {
            const lines = block.trim().split('\\n').map(l => l.trim()).filter(l => l.length > 0);
            if (lines.length === 0) return;
            let opName = "Unknown";
            const ips = [];
            lines.forEach(line => {
                if (line.includes('#')) {
                    opName = line.split('#')[1].trim();
                } else if (!line.startsWith('[source')) {
                    ips.push(line);
                }
            });
            if (ips.length > 0) {
                cachedIpsData[opName] = ips;
            }
        });
        populateIpSelect();
    } catch (err) {
        alert('Failed to load IP list from GitHub.');
        toggleIpSelectorModal(false);
    }
}
function populateIpSelect() {
    const select = document.getElementById('ip-operator-select');
    select.innerHTML = '<option value="all">همه (توصیه شده)</option>';
    Object.keys(cachedIpsData).forEach(op => {
        const option = document.createElement('option');
        option.value = op;
        option.textContent = op;
        select.appendChild(option);
    });
}
function toggleIpSelectorModal(show) {
    const modal = document.getElementById('ip-selector-modal');
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
async function openIpSelectorModal() {
    toggleIpSelectorModal(true);
    document.getElementById('ip-loading-state').classList.remove('hidden');
    document.getElementById('ip-selection-form').classList.add('hidden');
    await fetchIpsList();
    document.getElementById('ip-loading-state').classList.add('hidden');
    document.getElementById('ip-selection-form').classList.remove('hidden');
}
function applySelectedIps() {
    const operator = document.getElementById('ip-operator-select').value;
    let count = parseInt(document.getElementById('ip-count-input').value, 10);
    if (isNaN(count) || count < 1) count = 10;
    let availableIps = [];
    if (operator === 'all') {
        Object.values(cachedIpsData).forEach(ips => {
            availableIps = availableIps.concat(ips);
        });
    } else {
        availableIps = cachedIpsData[operator] || [];
    }
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
    toggleIpSelectorModal(false);
}
document.addEventListener('DOMContentLoaded', () => {
			const freeModal = document.getElementById('free-panel-warning-modal');
            const freeCard = freeModal.querySelector('div');
            freeModal.classList.remove('opacity-0', 'pointer-events-none');
            freeModal.classList.add('opacity-100', 'pointer-events-auto');
            freeCard.classList.remove('opacity-0', 'scale-95');
            freeCard.classList.add('opacity-100', 'scale-100');
            if (localStorage.getItem('zeus_path_warned_' + CURRENT_VERSION) !== 'true') {
                const modal = document.getElementById('path-warning-modal');
                const card = modal.querySelector('div');
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            }			
            const versionBadge = document.getElementById('panel-version');
            if (versionBadge) versionBadge.innerText = 'v' + CURRENT_VERSION;
            renderPortCheckboxes();
            loadUsers();
            loadLocations();
            
            window.usersRefreshIntervalId = null;
            
            window.startRefreshInterval = function(intervalMs) {
                if (window.usersRefreshIntervalId) {
                    clearInterval(window.usersRefreshIntervalId);
                }
                window.usersRefreshIntervalId = setInterval(() => loadUsers(true), intervalMs);
            };

            window.changeRefreshRate = function(val) {
                const ms = parseInt(val, 10);
                localStorage.setItem('zeus_refresh_rate', ms);
                window.startRefreshInterval(ms);
                showToast('نرخ رفرش پنل تغییر کرد');
            };

            const savedRate = localStorage.getItem('zeus_refresh_rate');
            const initialRate = savedRate ? parseInt(savedRate, 10) : 2000;
            const selectEl = document.getElementById('refresh-rate-select');
            if (selectEl) {
                selectEl.value = String(initialRate);
            }
            
            window.startRefreshInterval(initialRate);

            setTimeout(() => checkForUpdates(false), 2000);
            setInterval(() => checkForUpdates(false), 60000);

            window.addEventListener('click', (e) => {
                if (e.target.id === 'user-modal') toggleModal(false);
                if (e.target.id === 'ip-selector-modal') toggleIpSelectorModal(false);
                if (e.target.id === 'settings-modal') toggleSettingsModal(false);
                if (e.target.id === 'update-modal') toggleUpdateModal(false);
                if (e.target.id === 'token-modal') toggleTokenModal(false);
                if (e.target.id === 'qr-modal') toggleQrModal(false);
                if (e.target.id === 'bulk-edit-modal') toggleBulkEditModal(false);
                if (e.target.id === 'path-warning-modal') closePathWarning();
                if (e.target.id === 'usage-warning-modal') closeUsageWarning();
                if (e.target.id === 'free-panel-warning-modal') closeFreePanelWarning();
                if (e.target.id === 'custom-confirm-modal') {
                    const cancelBtn = document.getElementById('custom-confirm-cancel');
                    if (cancelBtn) cancelBtn.click();
                }
            });
        });
		
let cachedProxyCountries = null;

function toggleProxySelectorModal(show) {
    const modal = document.getElementById('proxy-selector-modal');
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

async function openProxySelectorModal() {
    toggleProxySelectorModal(true);
    const select = document.getElementById('proxy-country-select');
    const fetchBtn = document.getElementById('proxy-fetch-btn');
    
    const countriesList = [
  "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR",
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
    countriesList.forEach(country => {
        const option = document.createElement('option');
        option.value = country;
        const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(country) : '🌐';
        option.textContent = flag + ' ' + country;
        select.appendChild(option);
    });
    
    fetchBtn.disabled = false;
}

function populateProxyCountries(countries) {
    const select = document.getElementById('proxy-country-select');
    const fetchBtn = document.getElementById('proxy-fetch-btn');
    select.innerHTML = '';
    countries.forEach(country => {
        const option = document.createElement('option');
        option.value = country;
        const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(country) : '🌐';
        option.textContent = flag + ' ' + country;
        select.appendChild(option);
    });
    fetchBtn.disabled = false;
}

async function fetchAndLoadProxy() {
    const select = document.getElementById('proxy-country-select');
    const country = select.value;
    if (!country) return;

    const loadingState = document.getElementById('proxy-loading-state');
    const formState = document.getElementById('proxy-selection-form');
    const fetchBtn = document.getElementById('proxy-fetch-btn');

    loadingState.classList.remove('hidden');
    loadingState.innerText = 'در حال دریافت لیست پروکسی‌ها...';
    formState.classList.add('hidden');
    fetchBtn.disabled = true;

    try {
		const sources = [
			{ url: 'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/' + country.toUpperCase() + '/data.txt', prefix: '' },
			{ url: 'https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/proxy/' + country.toUpperCase() + '.txt', prefix: '' },
    
			{ url: 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=' + country, prefix: 'socks5://' },
			{ url: 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&country=' + country, prefix: 'socks4://' },
			{ url: 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=' + country, prefix: 'http://' },
			{ url: 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=' + country, prefix: 'https://' },
    
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&country=' + country, prefix: 'socks5://' },
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&country=' + country, prefix: 'socks4://' },
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol==http&country=' + country, prefix: 'http://' },
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&country=' + country, prefix: 'https://' },
    
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&country=' + country + '&format=text', prefix: 'socks5://' },
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&country=' + country + '&format=text', prefix: 'socks4://' },
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&country=' + country + '&format=text', prefix: 'http://' },
			{ url: 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=https&country=' + country + '&format=text', prefix: 'https://' },
			
			{ url: 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=getproxies&protocol=socks5&country=' + country + '&format=text', prefix: 'socks5://' },
			{ url: 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=getproxies&protocol=socks4&country=' + country + '&format=text', prefix: 'socks4://' },
			{ url: 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=getproxies&protocol=http&country=' + country + '&format=text', prefix: 'http://' },
			{ url: 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=getproxies&protocol=https&country=' + country + '&format=text', prefix: 'https://' }
		];

        const responses = await Promise.allSettled(sources.map(src => 
            fetch(src.url).then(async res => {
                if (!res.ok) throw new Error();
                const text = await res.text();
                return { text: text, prefix: src.prefix };
            })
        ));

        let combinedProxies = [];

        for (const res of responses) {
            if (res.status === 'fulfilled' && res.value && res.value.text) {
                const rawLines = res.value.text.split('\\n');
                for (let line of rawLines) {
                    line = line.trim();
                    if (line.length > 5) {
                        if (res.value.prefix && !line.includes('://')) {
                            combinedProxies.push(res.value.prefix + line);
                        } else {
                            combinedProxies.push(line);
                        }
                    }
                }
            }
        }

        let lines = [...new Set(combinedProxies.filter(l => l.match(/^(socks4|socks5|socks|http|https):\\/\\//i)))];

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
                loadingState.innerText = 'تعداد ' + lines.length + ' پروکسی پیدا شد درحال اسکن\\nاسکن گروه ' + (Math.floor(i / BATCH_SIZE) + 1) + ' (۵ تست برای هر کدام)...';

                const testResults = await Promise.allSettled(batch.map(async (candidate) => {
                    let successCount = 0;
                    let totalPing = 0;
                    let failCount = 0;
                    
                    for(let t = 0; t < 5; t++) {
                        const controller = new AbortController();
                        const timeoutId = setTimeout(() => controller.abort(), 3500);
                        try {
                            const testRes = await fetch('/api/test-proxy', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
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
                    .filter(r => r.status === 'fulfilled')
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
                document.getElementById('user-socks5-input').value = bestProxy;
                document.getElementById('test-user-proxy-result').innerText = '';
                toggleProxySelectorModal(false);
                showToast('پروکسی با بهترین امتیاز لود شد.');
            } else {
                alert('هیچ پروکسی سالمی (حتی با یک پینگ موفق) یافت نشد.');
            }
        } else {
            alert('پروکسی برای این کشور یافت نشد.');
        }
    } catch (e) {
        alert('خطا در دریافت لیست پروکسی‌ها از سرور.');
    } finally {
        loadingState.classList.add('hidden');
        formState.classList.remove('hidden');
        fetchBtn.disabled = false;
    }
}

window.addEventListener('click', (e) => {
    if (e.target.id === 'proxy-selector-modal') toggleProxySelectorModal(false);
});
    </script>
</body>
</html>`,
	status: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>وضعیت اشتراک کاربر</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Vazirmatn', sans-serif; }
        .glass {
            background: rgba(10, 10, 10, 0.6);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
    </style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center py-12 px-4">
    <div class="w-full max-w-xl glass rounded-3xl shadow-2xl p-6 md:p-8 relative overflow-hidden">
        <div class="absolute -left-12 -top-12 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="absolute -right-12 -bottom-12 w-40 h-40 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="text-center mb-8 relative z-10">
            <div class="inline-block p-3.5 bg-blue-600/10 text-blue-500 rounded-3xl mb-3 border border-blue-500/20 shadow-lg shadow-blue-500/5">
                <svg class="w-9 h-9" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
            </div>
            <h1 class="text-xl font-bold tracking-tight text-gray-900 dark:text-white mb-1">پنل کاسپین - وضعیت اشتراک</h1>
            <p id="display-username" class="text-sm font-bold text-blue-500 tracking-wide font-mono mb-2"></p>
            <div id="live-connections-badge" class="hidden inline-flex items-center gap-1.5 px-3 py-1 bg-green-600/10 border border-green-600/20 text-green-600 rounded-full text-xs font-bold shadow-sm">
                <span class="w-2 h-2 rounded-full bg-green-600 animate-pulse"></span>
                <span id="live-connections-text" dir="rtl">۰ دستگاه متصل</span>
            </div>
        </div>
        <!-- Connection Status -->
        <div id="status-card" class="mb-6 rounded-2xl p-4 text-center border font-bold relative z-10 transition duration-300">
            <span id="status-text" class="text-sm">در حال بارگذاری وضعیت...</span>
        </div>
        <div class="space-y-5 mb-8 relative z-10">
            <div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm">
                <div class="flex justify-between items-center mb-3">
                    <span class="text-xs font-semibold text-gray-500 dark:text-zinc-400 flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                        میزان حجم مصرفی
                    </span>
                    <span id="volume-pct" class="text-xs font-bold text-blue-500">۰٪</span>
                </div>
                <div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-2.5 overflow-hidden mb-3">
                    <div id="volume-progress" class="bg-blue-600 h-2.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-gray-500 dark:text-zinc-400 font-medium">
                    <span>مصرف شده: <span id="used-vol" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                    <span>حجم کل: <span id="limit-vol" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                </div>
            </div>
            <div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm">
                <div class="flex justify-between items-center mb-3">
                    <span class="text-xs font-semibold text-gray-500 dark:text-zinc-400 flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        زمان باقی‌مانده اشتراک
                    </span>
                    <span id="expiry-pct" class="text-xs font-bold text-purple-500">۰٪</span>
                </div>
                <div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-2.5 overflow-hidden mb-3 flex justify-end">
                    <div id="expiry-progress" class="bg-purple-600 h-2.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-gray-500 dark:text-zinc-400 font-medium">
                    <span>باقی‌مانده: <span id="days-remaining" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                    <span>کل اعتبار: <span id="total-days" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                </div>
            </div>
            <div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm">
                <div class="flex justify-between items-center mb-3">
                    <span class="text-xs font-semibold text-gray-500 dark:text-zinc-400 flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        وضعیت ریکوئست‌ها
                    </span>
                    <span id="req-pct" class="text-xs font-bold text-green-600">۰٪</span>
                </div>
                <div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-2.5 overflow-hidden mb-3">
                    <div id="req-progress" class="bg-green-700 h-2.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-gray-500 dark:text-zinc-400 font-medium">
                    <span>مصرف شده: <span id="used-req" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                    <span>سقف کل: <span id="limit-req" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                </div>
            </div>
            <div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-2xl p-5 shadow-sm">
                <div class="flex justify-between items-center mb-3">
                    <span class="text-xs font-semibold text-gray-500 dark:text-zinc-400 flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                        دستگاه‌های متصل
                    </span>
                    <span id="online-pct" class="text-xs font-bold text-sky-500">۰٪</span>
                </div>
                <div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-2.5 overflow-hidden mb-3">
                    <div id="online-progress" class="bg-sky-600 h-2.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-gray-500 dark:text-zinc-400 font-medium">
                    <span>متصل در لحظه: <span id="online-count" class="font-bold text-gray-800 dark:text-zinc-200">۰</span></span>
                    <span>سقف همزمان: <span id="limit-online" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
                </div>
            </div>
        </div>
        <div class="border-t border-gray-100 dark:border-zinc-800 pt-6 relative z-10">
            <h2 class="text-sm font-bold mb-4 flex items-center gap-2">
                <svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                دریافت کانفیگ و اشتراک‌ها
            </h2>
            <div class="space-y-3">
                <button onclick="copyTextSub()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-indigo-500 dark:hover:border-indigo-500 rounded-xl text-xs font-medium transition shadow-sm">
                    <span class="flex items-center gap-2">⛓️ کپی لینک ساب‌اسکریپشن متنی</span>
                    <span class="text-indigo-500">کپی</span>
                </button>
				<button onclick="showSubQr()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-amber-500 dark:hover:border-amber-500 rounded-xl text-xs font-medium transition shadow-sm">
                    <span class="flex items-center gap-2">📱 دریافت کیوآر کد ساب</span>
                    <span class="text-amber-500">نمایش</span>
                </button>
                <button onclick="copyVlessConfig()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-blue-500 dark:hover:border-blue-500 rounded-xl text-xs font-medium transition shadow-sm">
                    <span class="flex items-center gap-2">🚀 کپی کانفیگ VLESS (مستقیم)</span>
                    <span class="text-blue-500">کپی</span>
                </button>
            </div>
        </div>
    </div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
    <div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-3xl shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
        <div class="flex justify-between items-center mb-4">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
            <button onclick="toggleQrModal(false)" class="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
        <div class="flex justify-center bg-white p-4 rounded-xl mb-4">
            <div id="qrcode-container"></div>
        </div>
    </div>
</div>
<div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>
    <script>
        /* {{USER_DATA_PLACEHOLDER}} */
        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            const colors = type === 'error' 
                ? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
                : 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
            
            toast.className = 'px-4 py-3 border rounded-xl shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
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
            const msgStr = message ? message.toString() : '';
            if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
                showToast(msgStr, 'error');
            } else {
                showToast(msgStr, 'success');
            }
        };
        function getHost() {
            return window.location.host;
        }
        function getVlessLink() {
            const u = window.statusUser;
            const host = getHost();
            var ips = [host];
            if (u.ips) {
                ips = u.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
                if (ips.length === 0) ips = [host];
            }
            var ports = String(u.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
            var fp = u.fingerprint || 'chrome';
            const userFrag = (u.frag_len && u.frag_int) ? '&fragment=' + u.frag_len + ',' + u.frag_int : '';
            var links = [];
            ips.forEach(function(ip, ipIndex) {
                ports.forEach(function(portStr) {
                    var isTlsPort = ['443', '2053', '2083', '2087', '2096', '8443'].includes(portStr);
                    var tlsVal = isTlsPort ? 'tls' : 'none';
                    var remark = u.username;
                    links.push('vle' + 'ss://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=/&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + userFrag + '#' + encodeURIComponent(remark));
                });
            });
            return links.join('\\n');
        }
        function copyVlessConfig() {
            navigator.clipboard.writeText(getVlessLink()).then(() => alert('✅ کانفیگ VLESS با موفقیت کپی شد!'));
        }
        function copyTextSub() {
            const link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
            navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب متنی کپی شد!'));
        }
		function toggleQrModal(show, text) {
            const modal = document.getElementById('qr-modal');
            const card = document.getElementById('qr-modal-card');
            const container = document.getElementById('qrcode-container');
            if (show) {
                container.innerHTML = '';
                new QRCode(container, {
                    text: text,
                    width: 200,
                    height: 200,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
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

        function showSubQr() {
            const link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
            toggleQrModal(true, link);
        }
        document.addEventListener('DOMContentLoaded', () => {
            const u = window.statusUser;
            if (!u) return;
            const limit = u.ip_limit !== undefined ? u.ip_limit : u.max_connections;
            document.getElementById('display-username').innerText = u.username;
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
                document.getElementById('volume-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
                if (usedGb >= limitGb) isVolumeExpired = true;
            } else {
                document.getElementById('limit-vol').innerText = 'نامحدود';
                document.getElementById('volume-pct').innerText = '۰٪';
                document.getElementById('volume-progress').style.width = '100%';
                document.getElementById('volume-progress').style.backgroundColor = '#2dd4bf';
            }
            let daysRemaining = 'نامحدود';
            let totalDays = 'نامحدود';
            let isTimeExpired = false;
            if (u.expiry_days) {
                totalDays = u.expiry_days + ' روز';
                if (u.created_at) {
                    const created = new Date(u.created_at);
                    const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                    const diffDays = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
                    daysRemaining = diffDays > 0 ? diffDays : 0;
                    const pct = Math.max(0, Math.min(100, (daysRemaining / u.expiry_days) * 100));
                    document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
                    document.getElementById('expiry-progress').style.width = pct + '%';
                    const hue = pct * 1.2;
                    document.getElementById('expiry-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
                    if (new Date() > expiryDate) isTimeExpired = true;
                }
            } else {
                document.getElementById('expiry-pct').innerText = '۰٪';
                document.getElementById('expiry-progress').style.width = '100%';
                document.getElementById('expiry-progress').style.backgroundColor = '#14b8a6';
            }
            document.getElementById('days-remaining').innerText = daysRemaining === 'نامحدود' ? 'نامحدود' : daysRemaining + ' روز';
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
                document.getElementById('req-progress').style.backgroundColor = 'hsl(' + rHue + ', 80%, 45%)';
                if (usedReq >= limitReq) isReqExpired = true;
            } else {
                document.getElementById('limit-req').innerText = 'نامحدود';
                document.getElementById('req-pct').innerText = '۰٪';
                document.getElementById('req-progress').style.width = '100%';
                document.getElementById('req-progress').style.backgroundColor = '#10b981';
            }
            const onlineCount = u.online_count || 0;
            document.getElementById('online-count').innerText = onlineCount;
            if (limit) {
                document.getElementById('limit-online').innerText = limit;
                const oPct = Math.min((onlineCount / limit) * 100, 100);
                document.getElementById('online-pct').innerText = oPct.toFixed(0) + '٪';
                document.getElementById('online-progress').style.width = oPct + '%';
                const oHue = 120 - (oPct * 1.2);
                document.getElementById('online-progress').style.backgroundColor = 'hsl(' + oHue + ', 80%, 45%)';
            } else {
                document.getElementById('limit-online').innerText = 'نامحدود';
                document.getElementById('online-pct').innerText = '۰٪';
                document.getElementById('online-progress').style.width = '100%';
                document.getElementById('online-progress').style.backgroundColor = onlineCount > 0 ? '#0ea5e9' : '#9ca3af'; 
            }
            const statusCard = document.getElementById('status-card');
            const statusText = document.getElementById('status-text');
            if (u.is_active === 0) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-bold relative z-10 bg-red-500/10 border-red-500/30 text-red-500 shadow-md shadow-red-500/5';
                statusCard.style.boxShadow = 'inset 0 0 12px rgba(239, 68, 68, 0.1)';
                statusText.innerText = '❌ وضعیت اشتراک: غیرفعال / مسدود دستی';
            } else if (isVolumeExpired) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
                statusText.innerText = '⚠️ وضعیت اشتراک: تمام شدن حجم مجاز';
            } else if (isReqExpired) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
                statusText.innerText = '📈 وضعیت اشتراک: تمام شدن ریکوئست مجاز';
            } else if (isTimeExpired) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
                statusText.innerText = '⏳ وضعیت اشتراک: منقضی شده (پایان زمان اعتبار)';
            } else {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-bold relative z-10 bg-green-600/10 border-green-600/30 text-green-600 shadow-md shadow-green-600/5';
                statusText.innerText = '✅ وضعیت اشتراک: فعال و متصل';
            }
        });

        window.addEventListener('click', (e) => {
            if (e.target.id === 'qr-modal') toggleQrModal(false);
        });
		

    </script>
</body>
</html>`,
};
