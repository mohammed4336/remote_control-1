const body = document.getElementById("licensesBody");
const notice = document.getElementById("notice");
const searchInput = document.getElementById("searchInput");

let licenses = [];

function showNotice(message, error = false) {
  notice.hidden = false;
  notice.textContent = message;
  notice.classList.toggle("error", error);
  setTimeout(() => notice.hidden = true, 4500);
}

function dateText(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString("ar-SA");
}

function statusInfo(status) {
  const map = {
    active: ["نشط", "active"],
    pending: ["بانتظار التفعيل", "pending"],
    expired: ["منتهي", "expired"],
    revoked: ["موقوف", "revoked"],
    inactive: ["غير نشط", "inactive"]
  };
  return map[status] || [status || "غير معروف", "inactive"];
}

function updateStats(items) {
  document.getElementById("totalCount").textContent = items.length;
  document.getElementById("activeCount").textContent =
    items.filter(x => x.status === "active").length;
  document.getElementById("pendingCount").textContent =
    items.filter(x => x.status === "pending").length;
  document.getElementById("inactiveCount").textContent =
    items.filter(x => ["expired", "revoked", "inactive"].includes(x.status)).length;
}

function render(items) {
  body.innerHTML = "";

  if (!items.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">لا توجد حسابات مطابقة.</td></tr>`;
    document.getElementById("resultCount").textContent = "0 حساب";
    return;
  }

  items.forEach(row => {
    const [statusLabel, statusClass] = statusInfo(row.status);
    const tr = document.createElement("tr");

    const values = [
      row.username || "بدون اسم",
      row.code || "—",
      null,
      dateText(row.expires_at),
      row.contact || row.masked_contact || "—"
    ];

    values.forEach((value, index) => {
      const td = document.createElement("td");
      if (index === 2) {
        const badge = document.createElement("span");
        badge.className = `status ${statusClass}`;
        badge.textContent = statusLabel;
        td.appendChild(badge);
      } else {
        td.textContent = value;
      }
      tr.appendChild(td);
    });

    const actions = document.createElement("td");
    actions.innerHTML = `
      <div class="actions">
        <button class="action-btn" data-action="activate">تفعيل</button>
        <button class="action-btn" data-action="extend">تمديد</button>
        <button class="action-btn danger" data-action="revoke">إيقاف</button>
      </div>
    `;

    actions.querySelectorAll("button").forEach(button => {
      button.addEventListener("click", () => {
        handleAction(button.dataset.action, row.code);
      });
    });

    tr.appendChild(actions);
    body.appendChild(tr);
  });

  document.getElementById("resultCount").textContent =
    `${items.length} حساب`;
}

async function loadLicenses() {
  body.innerHTML = `<tr><td colspan="6" class="empty">جارٍ تحميل الحسابات...</td></tr>`;

  try {
    const response = await fetch("/seller/api/licenses", {
      credentials: "same-origin",
      cache: "no-store"
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    licenses = Array.isArray(data)
      ? data
      : (data.licenses || data.items || data.accounts || []);

    updateStats(licenses);
    filterLicenses();
  } catch (error) {
    body.innerHTML = `<tr><td colspan="6" class="empty">تعذر تحميل الحسابات. تحقق من الاتصال ثم حدّث الصفحة.</td></tr>`;
    showNotice("حدث خطأ أثناء تحميل الحسابات.", true);
    console.error(error);
  }
}

function filterLicenses() {
  const query = searchInput.value.trim().toLowerCase();

  const filtered = licenses.filter(row =>
    [row.username, row.code, row.contact, row.status]
      .some(value => String(value || "").toLowerCase().includes(query))
  );

  render(filtered);
}

async function handleAction(action, code) {
  let days = 0;

  if (action === "activate" || action === "extend") {
    const answer = prompt("أدخل مدة الاشتراك بالأيام:", "30");
    if (answer === null) return;

    days = Number(answer);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      showNotice("أدخل عدد أيام صحيحًا من 1 إلى 3650.", true);
      return;
    }
  }

  const labels = {
    activate: "تفعيل الاشتراك",
    extend: "تمديد الاشتراك",
    revoke: "إيقاف الاشتراك"
  };

  if (!confirm(`هل تريد ${labels[action]}؟`)) return;

  const routes = {
    activate: `/seller/api/licenses/${encodeURIComponent(code)}/activate`,
    extend: `/seller/api/licenses/${encodeURIComponent(code)}/extend`,
    revoke: `/seller/api/licenses/${encodeURIComponent(code)}/revoke`
  };

  try {
    const response = await fetch(routes[action], {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(action === "revoke" ? {} : { days })
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok || result.ok === false) {
      throw new Error(result.error || `HTTP ${response.status}`);
    }

    showNotice("تم تنفيذ العملية بنجاح.");
    await loadLicenses();
  } catch (error) {
    console.error(error);
    showNotice("تعذر تنفيذ العملية: " + error.message, true);
  }
}

document.getElementById("refreshBtn").addEventListener("click", loadLicenses);
searchInput.addEventListener("input", filterLicenses);

loadLicenses();
