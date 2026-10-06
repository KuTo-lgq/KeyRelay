const unlockForm = document.querySelector("#unlockForm");
const adminTokenInput = document.querySelector("#adminToken");
const authMessage = document.querySelector("#authMessage");
const lockState = document.querySelector("#lockState");
const siteList = document.querySelector("#siteList");
const openDialog = document.querySelector("#openDialog");
const dialog = document.querySelector("#siteDialog");
const siteForm = document.querySelector("#siteForm");
const formMessage = document.querySelector("#formMessage");
let token = sessionStorage.getItem("keyrelayAdmin") || "";

const escapeHtml = (value) =>
  value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-KeyRelay-Admin": token, ...options.headers },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || "请求失败");
  return body;
}

async function loadSites() {
  const sites = await api("/api/v1/sites");
  lockState.textContent = "已连接";
  lockState.classList.add("connected");
  openDialog.disabled = false;
  authMessage.textContent = "";
  if (!sites.length) {
    siteList.innerHTML = `<div class="empty"><span>+</span><h3>还没有授权网站</h3><p>添加第一个登录配方，密码将立即加密。</p></div>`;
    return;
  }
  siteList.innerHTML = sites.map((site) => `
    <article class="site">
      <div><h3>${escapeHtml(site.name)}</h3><p>${escapeHtml(site.login_url)}</p></div>
      <button class="delete" data-id="${escapeHtml(site.id)}" aria-label="删除 ${escapeHtml(site.name)}">删除</button>
    </article>`).join("");
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  token = adminTokenInput.value.trim();
  try {
    await loadSites();
    sessionStorage.setItem("keyrelayAdmin", token);
    adminTokenInput.value = "";
  } catch (error) {
    token = "";
    sessionStorage.removeItem("keyrelayAdmin");
    authMessage.textContent = error.message;
  }
});

openDialog.addEventListener("click", () => dialog.showModal());
document.querySelector("#closeDialog").addEventListener("click", () => dialog.close());
document.querySelector("#cancelDialog").addEventListener("click", () => dialog.close());

siteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  formMessage.textContent = "正在加密保存…";
  const data = Object.fromEntries(new FormData(siteForm).entries());
  data.allowed_hosts = data.allowed_hosts.split(",").map((host) => host.trim()).filter(Boolean);
  try {
    await api("/api/v1/sites", { method: "POST", body: JSON.stringify(data) });
    siteForm.reset();
    formMessage.textContent = "";
    dialog.close();
    await loadSites();
  } catch (error) {
    formMessage.textContent = error.message;
  }
});

siteList.addEventListener("click", async (event) => {
  const button = event.target.closest(".delete");
  if (!button || !confirm("确定删除这条登录授权？")) return;
  try {
    await api(`/api/v1/sites/${button.dataset.id}`, { method: "DELETE" });
    await loadSites();
  } catch (error) {
    authMessage.textContent = error.message;
  }
});

if (token) loadSites().catch(() => sessionStorage.removeItem("keyrelayAdmin"));
