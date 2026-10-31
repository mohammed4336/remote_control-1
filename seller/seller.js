
"use strict";

const body = document.getElementById("licensesBody");
const notice = document.getElementById("notice");

let licenses = [];

function showMessage(message, error = false) {
  notice.textContent = message;
  notice.style.color = error ? "#ff8585" : "#8ee5ad";
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function getStatus(row) {
  if (row.status === "pending") return ["بانتظار التفعيل", "pending"];

  if (row.status === "active") {
    if (row.expires_at && Number(row.expires_at) * 1000 < Date.now())
      return ["منتهي", "inactive"];

    return ["فعّال", "active"];
  }

  return ["موقوف", "inactive"];
}

function updateStats() {
  let active = 0;
  let pending = 0;

  licenses.forEach(row => {
    const [label] = getStatus(row);

    if (label === "فعّال") active++;
    else if (label === "بانتظار التفعيل") pending++;
  });

  document.getElementById("totalCount").textContent = licenses.length;
  document.getElementById("activeCount").textContent = active;
  document.getElementById("pendingCount").textContent = pending;
  document.getElementById("inactiveCount").textContent =
    licenses.length - active - pending;
}

function renderLicenses() {
  const search = document.getElementById("searchInput").value.toLowerCase();

  const filtered = licenses.filter(row =>
    [row.code, row.username, row.contact]
      .some(value => String(value || "").toLowerCase().includes(search))
  );

  if (!filtered.length) {
    body.innerHTML = '<tr><td colspan="6">لا توجد حسابات.</td></tr>';
    return;
  }

  body.innerHTML = filtered.map(row => {
    const [status, type] = getStatus(row);

    const expiry = row.expires_at
      ? new Date(Number(row.expires_at) * 1000).toLocaleDateString("ar-SA")
      : "غير محدد";

    const code = escapeHTML(row.code);

    return `
      <tr>
        <td>${code}</td>
        <td>${escapeHTML(row.username || "—")}</td>
        <td>${escapeHTML(row.masked_contact || row.contact || "—")}</td>
        <td>${status}</td>
        <td>${expiry}</td>
        <td>
          <input type="number" min="1" max="3650"
                 value="30" style="width:75px">

          <button data-action="activate" data-code="${code}">
            تفعيل
          </button>

          <button data-action="extend" data-code="${code}">
            تمديد
          </button>

          <button data-action="revoke" data-code="${code}">
            إيقاف
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  if (response.status === 401 || response.status === 403) {
    throw new Error("ليس لديك صلاحية الدخول.");
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.ok === false) {
    throw new Error(data.error || "حدث خطأ أثناء تنفيذ العملية.");
  }

  return data;
}

async function loadLicenses() {
  body.innerHTML = '<tr><td colspan="6">جارٍ تحميل الحسابات...</td></tr>';

  try {
    const data = await api("/seller/api/licenses");

    licenses = Array.isArray(data)
      ? data
      : (data.licenses || data.items || []);

    updateStats();
    renderLicenses();

    showMessage("تم تحديث الحسابات.");
  } catch (error) {
    body.innerHTML = `<tr><td colspan="6">${escapeHTML(error.message)}</td></tr>`;
    showMessage(error.message, true);
  }
}

body.addEventListener("click", async event => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;

  const code = button.dataset.code;
  const action = button.dataset.action;
  const days = Number(button.closest("tr").querySelector('input[type="number"]').value);

  if (action !== "revoke" && (!Number.isInteger(days) || days < 1 || days > 3650)) {
    showMessage("أدخل عدد أيام صحيحًا من 1 إلى 3650.", true);
    return;
  }

  const names = {
    activate: "تفعيل الاشتراك",
    extend: "تمديد الاشتراك",
    revoke: "إيقاف الاشتراك"
  };

  if (!confirm(`${names[action]} للحساب ${code}؟`)) return;

  button.disabled = true;

  try {
    const options = {
      method: "POST",
      body: JSON.stringify(action === "revoke" ? {} : { days })
    };

    await api(
      `/seller/api/licenses/${encodeURIComponent(code)}/${action}`,
      options
    );

    showMessage("تم تنفيذ العملية بنجاح.");
    await loadLicenses();
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("refreshBtn").addEventListener("click", loadLicenses);
document.getElementById("searchInput").addEventListener("input", renderLicenses);

loadLicenses();
