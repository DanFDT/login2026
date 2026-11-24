const authView = document.querySelector("#auth-view");
const accountView = document.querySelector("#account-view");
const form = document.querySelector("#auth-form");
const nameField = document.querySelector("#name-field");
const message = document.querySelector("#form-message");
const submitButton = document.querySelector("#submit-button");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
let mode = "login";

function setMode(nextMode) {
  mode = nextMode;
  const registering = mode === "register";
  nameField.classList.toggle("hidden", !registering);
  nameField.querySelector("input").required = registering;
  form.elements.password.autocomplete = registering ? "new-password" : "current-password";
  submitButton.textContent = registering ? "계정 만들기" : "로그인";
  document.querySelector("#page-title").textContent = registering ? "새 계정을 만들어 보세요" : "다시 만나서 반가워요";
  document.querySelector("#page-subtitle").textContent = registering
    ? "간단한 정보를 입력하고 시작해 보세요."
    : "로그인하고 서비스를 계속 이용해 보세요.";
  loginTab.classList.toggle("active", !registering);
  registerTab.classList.toggle("active", registering);
  loginTab.setAttribute("aria-selected", String(!registering));
  registerTab.setAttribute("aria-selected", String(registering));
  message.textContent = "";
}

function showAccount(user) {
  authView.classList.add("hidden");
  accountView.classList.remove("hidden");
  document.querySelector("#page-title").textContent = "로그인되었습니다";
  document.querySelector("#page-subtitle").textContent = "계정 정보는 서버에서 불러왔습니다.";
  document.querySelector("#welcome-name").textContent = `${user.name}님, 환영합니다!`;
  document.querySelector("#account-email").textContent = user.email;
  document.querySelector("#avatar").textContent = [...user.name][0] || "L";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "요청을 처리하지 못했습니다.");
  return result;
}

loginTab.addEventListener("click", () => setMode("login"));
registerTab.addEventListener("click", () => setMode("register"));

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";
  submitButton.disabled = true;
  const formData = new FormData(form);
  const payload = {
    email: formData.get("email"),
    password: formData.get("password"),
  };
  if (mode === "register") payload.name = formData.get("name");

  try {
    const result = await requestJson(`/api/${mode}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showAccount(result.user);
  } catch (error) {
    message.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  const logoutButton = document.querySelector("#logout-button");
  const accountMessage = document.querySelector("#account-message");
  logoutButton.disabled = true;
  accountMessage.textContent = "";
  try {
    await requestJson("/api/logout", { method: "POST" });
    accountView.classList.add("hidden");
    authView.classList.remove("hidden");
    form.reset();
    setMode("login");
  } catch (error) {
    accountMessage.textContent = error.message;
  } finally {
    logoutButton.disabled = false;
  }
});

requestJson("/api/me")
  .then(({ user }) => showAccount(user))
  .catch((error) => {
    if (error.message !== "로그인이 필요합니다.") {
      message.textContent = "서버에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.";
    }
  });
