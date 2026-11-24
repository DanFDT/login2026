const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { promisify } = require("node:util");
const express = require("express");

const scrypt = promisify(crypto.scrypt);
const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_COOKIE = "login_session";
const SESSION_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const dataDirectory = path.join(__dirname, "data");
const dataFile = path.join(dataDirectory, "store.json");
const reservedEmails = new Set();
let store;
let pendingWrite = Promise.resolve();

async function saveStore() {
  const write = pendingWrite.then(async () => {
    await fs.mkdir(dataDirectory, { recursive: true });
    const temporaryFile = `${dataFile}.tmp`;
    await fs.writeFile(temporaryFile, JSON.stringify(store, null, 2), { mode: 0o600 });
    await fs.rename(temporaryFile, dataFile);
  });
  pendingWrite = write.catch(() => {});
  return write;
}

async function loadStore() {
  await fs.mkdir(dataDirectory, { recursive: true });
  try {
    const contents = await fs.readFile(dataFile, "utf8");
    const parsed = JSON.parse(contents);
    if (!Array.isArray(parsed.users) || !Array.isArray(parsed.sessions)) {
      throw new Error("저장된 데이터 형식이 올바르지 않습니다.");
    }
    store = parsed;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    store = { users: [], sessions: [] };
    await saveStore();
  }

  const now = Date.now();
  store.sessions = store.sessions.filter((session) => session.expiresAt > now);
  await saveStore();
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function readCookie(request, name) {
  const cookies = request.headers.cookie || "";
  const entry = cookies.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return entry ? entry.slice(name.length + 1) : null;
}

function setSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_LIFETIME / 1000}${secure}`
  );
}

async function createSession(user, response) {
  const token = crypto.randomBytes(32).toString("base64url");
  store.sessions.push({
    tokenHash: hashToken(token),
    userId: user.id,
    expiresAt: Date.now() + SESSION_LIFETIME,
  });
  await saveStore();
  setSessionCookie(response, token);
}

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use((request, response, next) => {
  const token = readCookie(request, SESSION_COOKIE);
  const tokenHash = token ? hashToken(token) : null;
  const session = tokenHash && store.sessions.find((item) => item.tokenHash === tokenHash);
  if (!session || session.expiresAt <= Date.now()) {
    request.user = null;
    if (session) {
      store.sessions = store.sessions.filter((item) => item !== session);
      saveStore().catch(next);
    }
    return next();
  }
  request.user = store.users.find((user) => user.id === session.userId) || null;
  next();
});

app.post("/api/register", async (request, response, next) => {
  try {
    const body = request.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";

    if (name.length < 1 || name.length > 50) {
      return response.status(400).json({ error: "이름은 1자 이상 50자 이하로 입력해 주세요." });
    }
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return response.status(400).json({ error: "올바른 이메일 주소를 입력해 주세요." });
    }
    if (password.length < 8 || password.length > 128) {
      return response.status(400).json({ error: "비밀번호는 8자 이상 128자 이하로 입력해 주세요." });
    }
    if (store.users.some((user) => user.email === email) || reservedEmails.has(email)) {
      return response.status(409).json({ error: "이미 가입된 이메일입니다." });
    }

    reservedEmails.add(email);
    try {
      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = await scrypt(password, salt, 64);
      const user = {
        id: crypto.randomUUID(),
        name,
        email,
        passwordSalt: salt,
        passwordHash: passwordHash.toString("hex"),
        createdAt: new Date().toISOString(),
      };
      store.users.push(user);
      await createSession(user, response);
      response.status(201).json({ user: { name: user.name, email: user.email } });
    } finally {
      reservedEmails.delete(email);
    }
  } catch (error) {
    next(error);
  }
});

app.post("/api/login", async (request, response, next) => {
  try {
    const body = request.body || {};
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (password.length > 128) {
      return response.status(401).json({ error: "이메일 또는 비밀번호를 확인해 주세요." });
    }
    const user = store.users.find((item) => item.email === email);
    const salt = user ? user.passwordSalt : "login-server-placeholder-salt";
    const storedHash = user ? user.passwordHash : "0".repeat(128);
    const passwordHash = await scrypt(password, salt, 64);
    const expectedHash = Buffer.from(storedHash, "hex");
    const passwordMatches =
      expectedHash.length === passwordHash.length && crypto.timingSafeEqual(passwordHash, expectedHash);

    if (!user || !passwordMatches) {
      return response.status(401).json({ error: "이메일 또는 비밀번호를 확인해 주세요." });
    }

    await createSession(user, response);
    response.json({ user: { name: user.name, email: user.email } });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", (request, response) => {
  if (!request.user) return response.status(401).json({ error: "로그인이 필요합니다." });
  response.json({ user: { name: request.user.name, email: request.user.email } });
});

app.post("/api/logout", async (request, response, next) => {
  try {
    const token = readCookie(request, SESSION_COOKIE);
    if (token) {
      const tokenHash = hashToken(token);
      store.sessions = store.sessions.filter((session) => session.tokenHash !== tokenHash);
      await saveStore();
    }
    response.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    response.json({ message: "로그아웃되었습니다." });
  } catch (error) {
    next(error);
  }
});

app.use((error, request, response, next) => {
  console.error(error);
  if (response.headersSent) return next(error);
  response.status(500).json({ error: "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요." });
});

loadStore()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`로그인 서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
    });
  })
  .catch((error) => {
    console.error("저장 데이터를 불러오지 못했습니다.", error);
    process.exitCode = 1;
  });
