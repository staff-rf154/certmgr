const STATUS_LABELS = {
  creating: "Создание запроса",
  pending_dns: "Ждёт TXT",
  issuing: "Выпуск",
  issued: "Выпущен",
  error: "Ошибка",
  expired: "Истёк",
};

const state = {
  certificates: [],
  default_email: "",
  cron: { enabled: false, time: "" },
  renew_days: 30,
  smtp: null,
  busy: false,
};

const certsEl = document.getElementById("certs");
const toastEl = document.getElementById("toast");
const formEl = document.getElementById("issue-form");
const cronEl = document.getElementById("cron-status");
const renewNoteEl = document.getElementById("renew-note");
const smtpFormEl = document.getElementById("smtp-form");
const smtpTestEl = document.getElementById("smtp-test");
const smtpPasswordStateEl = document.getElementById("smtp-password-state");

let toastTimer = null;
let smtpInitialized = false;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function toast(message, kind = "") {
  toastEl.textContent = message;
  toastEl.className = "toast show" + (kind ? " " + kind : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastEl.className = "toast";
  }, 5200);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    const error = new Error((data && data.detail) || "Ошибка запроса");
    error.payload = data;
    error.status = response.status;
    throw error;
  }
  return data;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function statusBadge(status) {
  const label = STATUS_LABELS[status] || status || "—";
  return `<span class="badge ${escapeHtml(status)}">${escapeHtml(label)}</span>`;
}

function challengesHtml(certificate) {
  const list = certificate.challenges || [];
  if (!list.length) return "";
  const rows = list
    .map(
      (item) => `
      <div class="dns-row">
        <div class="name">${escapeHtml(item.record)}</div>
        <div class="value">${escapeHtml(item.value)}</div>
        <button class="btn small ghost" data-action="copy" data-value="${escapeHtml(item.value)}">Копировать</button>
        <span class="chip">TXT</span>
      </div>`
    )
    .join("");
  return `
    <div class="dns">
      <div class="dns-head">Добавьте в DNS TXT-записи (TTL 300). Для домена и wildcard имя записи одинаковое — нужны оба значения.</div>
      ${rows}
    </div>`;
}

function downloadsHtml(certificate) {
  if (!certificate.has_files) return "";
  const domain = encodeURIComponent(certificate.domain);
  return `
    <a class="btn small" href="/api/certs/${domain}/download/fullchain">fullchain.pem</a>
    <a class="btn small" href="/api/certs/${domain}/download/privkey">privkey.pem</a>`;
}

function validityMeta(certificate) {
  if (!certificate.has_files || !certificate.expires_at) return "";
  const days = certificate.days_left;
  const daysText = days === null ? "—" : `${days} дн.`;
  return `
    <div class="meta">
      <span>Выпущен: <b>${formatDate(certificate.issued_at)}</b></span>
      <span>Действует до: <b>${formatDate(certificate.expires_at)}</b></span>
      <span>Осталось: <b>${escapeHtml(daysText)}</b></span>
    </div>`;
}

function actionsHtml(certificate) {
  const domain = escapeHtml(certificate.domain);
  const status = certificate.status;
  if (status === "pending_dns") {
    return `
      ${validityMeta(certificate)}
      <div class="row-actions">
        <button class="btn primary" data-action="verify" data-domain="${domain}">Проверить и выпустить</button>
        <button class="btn ghost" data-action="check" data-domain="${domain}">Проверить DNS</button>
        <button class="btn ghost" data-action="renew" data-domain="${domain}">Пересоздать запрос</button>
        ${downloadsHtml(certificate)}
        <button class="btn danger" data-action="delete" data-domain="${domain}">Удалить</button>
      </div>`;
  }
  if (status === "error") {
    return `
      ${validityMeta(certificate)}
      <div class="row-actions">
        <button class="btn primary" data-action="verify" data-domain="${domain}">Проверить и выпустить</button>
        <button class="btn ghost" data-action="renew" data-domain="${domain}">Создать запрос заново</button>
        ${downloadsHtml(certificate)}
        <button class="btn danger" data-action="delete" data-domain="${domain}">Удалить</button>
      </div>`;
  }
  if (status === "issuing" || status === "creating") {
    return `<div class="row-actions"><span class="muted"><span class="spinner"></span>Операция выполняется…</span></div>`;
  }
  if (status === "issued" || status === "expired") {
    return `
      ${validityMeta(certificate)}
      <div class="row-actions">
        ${downloadsHtml(certificate)}
        <button class="btn ghost small" data-action="renew" data-domain="${domain}">Продлить сейчас</button>
        <button class="btn danger small" data-action="delete" data-domain="${domain}">Удалить</button>
      </div>`;
  }
  return "";
}

function certificateHtml(certificate) {
  const chips = [
    certificate.include_wildcard ? '<span class="chip wild">wildcard</span>' : "",
    certificate.staging ? '<span class="chip staging">staging</span>' : "",
    certificate.renewal ? '<span class="chip">плановое продление</span>' : "",
    certificate.email ? `<span class="chip">${escapeHtml(certificate.email)}</span>` : "",
  ]
    .filter(Boolean)
    .join("");
  const error = certificate.last_error
    ? `<div class="error-box">${escapeHtml(certificate.last_error)}</div>`
    : "";
  return `
    <article class="card cert ${escapeHtml(certificate.status)}">
      <div class="cert-head">
        <div>
          <h3>${escapeHtml(certificate.domain)}</h3>
          <div class="chips">${chips}</div>
        </div>
        ${statusBadge(certificate.status)}
      </div>
      ${certificate.status_message ? `<p class="status-line">${escapeHtml(certificate.status_message)}</p>` : ""}
      ${error}
      ${challengesHtml(certificate)}
      ${actionsHtml(certificate)}
    </article>`;
}

function fillSmtpForm(smtp) {
  if (!smtp || !smtpFormEl) return;
  const fields = smtpFormEl.elements;
  fields.host.value = smtp.host || "";
  fields.port.value = smtp.port ?? 465;
  fields.username.value = smtp.username || "";
  fields.sender.value = smtp.sender || "";
  fields.notify_to.value = smtp.notify_to || "";
  fields.public_url.value = smtp.public_url || "";
  fields.enabled.checked = Boolean(smtp.enabled);
  fields.use_ssl.checked = smtp.use_ssl !== false;
  fields.password.value = "";
  fields.password.placeholder = smtp.password_set
    ? "задан (оставьте пустым, чтобы не менять)"
    : "не задан";
  smtpPasswordStateEl.textContent = smtp.password_set ? "Пароль задан" : "Пароль не задан";
  smtpPasswordStateEl.className = "chip" + (smtp.password_set ? " wild" : "");
}

function smtpPayload() {
  const fields = smtpFormEl.elements;
  const port = Number(fields.port.value || 465);
  return {
    enabled: fields.enabled.checked,
    host: fields.host.value.trim(),
    port: Number.isFinite(port) ? port : 465,
    username: fields.username.value.trim(),
    password: fields.password.value || null,
    sender: fields.sender.value.trim(),
    use_ssl: fields.use_ssl.checked,
    notify_to: fields.notify_to.value.trim(),
    public_url: fields.public_url.value.trim(),
  };
}

async function saveSmtp(showToast = true) {
  const data = await api("/api/smtp", {
    method: "PUT",
    body: JSON.stringify(smtpPayload()),
  });
  state.smtp = data;
  fillSmtpForm(data);
  if (showToast) toast("Настройки SMTP сохранены", "ok");
  return data;
}

function render() {
  cronEl.textContent = state.cron.enabled
    ? `Cron продления: ежедневно ${state.cron.time}`
    : "Cron продления: не создан";
  cronEl.className = "cron" + (state.cron.enabled ? " enabled" : "");
  renewNoteEl.textContent = `Плановое продление начинается за ${state.renew_days} дн. до истечения.`;

  if (!state.certificates.length) {
    certsEl.innerHTML = '<div class="empty">Сертификатов пока нет. Создайте первый запрос выше.</div>';
    return;
  }
  certsEl.innerHTML = state.certificates.map(certificateHtml).join("");
}

async function load() {
  try {
    const data = await api("/api/state");
    state.certificates = data.certificates || [];
    state.default_email = data.default_email || "";
    state.cron = data.cron || state.cron;
    state.renew_days = data.renew_days ?? state.renew_days;
    state.smtp = data.smtp || state.smtp;
    if (!smtpInitialized && state.smtp) {
      fillSmtpForm(state.smtp);
      smtpInitialized = true;
    }
    const emailInput = formEl.querySelector('input[name="email"]');
    if (emailInput && !emailInput.value && state.default_email) {
      emailInput.value = state.default_email;
    }
    render();
  } catch (error) {
    if (error.status === 401) return;
    toast(error.message, "error");
  }
}

async function runAction(button) {
  const action = button.dataset.action;
  const domain = button.dataset.domain;

  if (action === "copy") {
    try {
      await navigator.clipboard.writeText(button.dataset.value || "");
      toast("Значение скопировано", "ok");
    } catch (_) {
      toast("Не удалось скопировать", "error");
    }
    return;
  }

  if (state.busy) return;

  if (action === "delete") {
    if (!confirm(`Удалить сертификат и файлы для ${domain}?`)) return;
  }
  if (action === "renew") {
    if (!confirm(`Создать новый запрос для ${domain}? Текущий сертификат останется, пока новый не будет выпущен.`)) return;
  }

  state.busy = true;
  button.disabled = true;
  try {
    if (action === "verify") {
      toast("Проверяем DNS и запускаем выпуск…");
      await api(`/api/certs/${encodeURIComponent(domain)}/verify`, { method: "POST" });
      toast("Выпуск запущен. Сертификат появится после проверки Let's Encrypt.", "ok");
    } else if (action === "check") {
      const report = await api(`/api/certs/${encodeURIComponent(domain)}/check`, { method: "POST" });
      if (report.ok) {
        toast("Все TXT-записи найдены в DNS", "ok");
      } else {
        const missing = (report.records || [])
          .filter((item) => (item.missing || []).length)
          .map((item) => item.record)
          .join(", ");
        toast("Не найдены значения для: " + missing, "error");
      }
    } else if (action === "renew") {
      await api(`/api/certs/${encodeURIComponent(domain)}/renew`, { method: "POST" });
      toast("Запрос создан. Добавьте новые TXT-записи в DNS.", "ok");
    } else if (action === "delete") {
      await api(`/api/certs/${encodeURIComponent(domain)}`, { method: "DELETE" });
      toast("Сертификат удалён", "ok");
    }
  } catch (error) {
    if (error.status === 401) return;
    toast(error.message || "Ошибка", "error");
  } finally {
    state.busy = false;
    button.disabled = false;
    load();
  }
}

formEl.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.busy) return;
  const formData = new FormData(formEl);
  const payload = {
    domain: String(formData.get("domain") || "").trim(),
    email: String(formData.get("email") || "").trim(),
    include_wildcard: formData.get("wildcard") === "on",
    staging: formData.get("staging") === "on",
  };
  if (!payload.domain) {
    toast("Укажите домен", "error");
    return;
  }
  state.busy = true;
  const submit = formEl.querySelector('button[type="submit"]');
  submit.disabled = true;
  const original = submit.textContent;
  submit.innerHTML = '<span class="spinner"></span>Создаём запрос…';
  try {
    await api("/api/issue", { method: "POST", body: JSON.stringify(payload) });
    toast("Запрос создан. Добавьте TXT-записи в DNS.", "ok");
    formEl.querySelector('input[name="domain"]').value = "";
    await load();
  } catch (error) {
    if (error.status !== 401) toast(error.message || "Ошибка", "error");
  } finally {
    state.busy = false;
    submit.disabled = false;
    submit.textContent = original;
  }
});

certsEl.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (button) runAction(button);
});

smtpFormEl.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = smtpFormEl.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    await saveSmtp();
  } catch (error) {
    if (error.status !== 401) toast(error.message || "Ошибка сохранения SMTP", "error");
  } finally {
    submit.disabled = false;
  }
});

smtpTestEl.addEventListener("click", async () => {
  const fields = smtpFormEl.elements;
  const to =
    fields.test_to.value.trim() ||
    fields.notify_to.value.trim() ||
    fields.username.value.trim();
  if (!to) {
    toast("Укажите email для тестового письма", "error");
    return;
  }
  smtpTestEl.disabled = true;
  try {
    await saveSmtp(false);
    await api("/api/smtp/test", {
      method: "POST",
      body: JSON.stringify({ to }),
    });
    toast(`Тестовое письмо отправлено на ${to}`, "ok");
  } catch (error) {
    if (error.status !== 401) toast(error.message || "Ошибка отправки", "error");
  } finally {
    smtpTestEl.disabled = false;
  }
});

load();
setInterval(() => {
  if (!document.hidden && !state.busy) load();
}, 5000);
