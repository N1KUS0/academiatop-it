// Подтверждение для опасных действий
document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (e) {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});

// Быстрый фильтр строк таблицы
document.querySelectorAll("[data-filter-table]").forEach(function (input) {
  var table = document.getElementById(input.dataset.filterTable);
  if (!table) return;
  input.addEventListener("input", function () {
    var q = input.value.trim().toLowerCase();
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      tr.style.display = tr.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
    });
  });
});

// Предпросмотр hostname в форме компьютера
(function () {
  var aud = document.getElementById("pc-aud");
  var num = document.getElementById("pc-num");
  var out = document.getElementById("hostname-preview");
  if (!aud || !num || !out) return;
  function pad(n) { n = String(n); return n.length < 2 ? "0" + n : n; }
  function update() {
    var opt = aud.options[aud.selectedIndex];
    var a = opt && opt.dataset.num ? pad(opt.dataset.num) : "??";
    var n = num.value ? pad(num.value) : "??";
    out.textContent = "PC-" + a + "-" + n;
  }
  aud.addEventListener("change", update);
  num.addEventListener("input", update);
  update();
})();

// Форма заявки: поле «программа» нужно только для запроса на установку
(function () {
  var form = document.getElementById("ticket-form");
  if (!form) return;
  function update() {
    var kind = form.querySelector('input[name="kind"]:checked');
    var install = kind && kind.value === "install";
    form.querySelectorAll('[data-kind="install"]').forEach(function (el) { el.hidden = !install; });
  }
  form.addEventListener("change", function (e) { if (e.target.name === "kind") update(); });
  update();

  // Аудитория и компьютеры: видны галочки только выбранной аудитории.
  // Ничего не отмечено — заявка на всю аудиторию, отмечено несколько — на эти ПК.
  var aud = document.getElementById("ticket-aud");
  var picker = document.getElementById("pc-picker");
  if (aud && picker) {
    var hint = document.getElementById("pc-picker-hint");
    var empty = picker.querySelector(".pc-picker-empty");
    var groups = picker.querySelectorAll(".pc-group");
    var countPcs = function (n) {
      var m10 = n % 10, m100 = n % 100;
      return n + (m10 === 1 && m100 !== 11 ? " компьютер" : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? " компьютера" : " компьютеров");
    };
    var refreshPcs = function () {
      var n = picker.querySelectorAll('input[name="pc"]:checked').length;
      hint.textContent = !aud.value ? "" : n === 0 ? "не отмечено ни одного — заявка на всю аудиторию"
        : "отмечено: " + countPcs(n);
    };
    var showGroup = function () {
      groups.forEach(function (g) {
        var on = g.dataset.aud === aud.value;
        g.hidden = !on;
        if (!on) g.querySelectorAll('input[name="pc"]').forEach(function (b) { b.checked = false; });
      });
      empty.hidden = !!aud.value;
      refreshPcs();
    };
    aud.addEventListener("change", showGroup);
    picker.addEventListener("change", refreshPcs);
    picker.addEventListener("click", function (e) {
      if (!e.target.matches("[data-pc-all]")) return;
      var boxes = e.target.closest(".pc-group").querySelectorAll('input[name="pc"]');
      var all = Array.prototype.every.call(boxes, function (b) { return b.checked; });
      boxes.forEach(function (b) { b.checked = !all; });
      picker.dispatchEvent(new Event("change", { bubbles: true }));  // счётчик и похожие заявки
    });
    showGroup();
  }

  // Похожие открытые заявки — чтобы не создавать дубли
  var box = document.getElementById("similar-box");
  if (!box || !window.fetch) return;
  var list = box.querySelector("ul");
  var timer = null, lastQuery = "";
  function field(name) { var el = form.elements[name]; return el ? el.value.trim() : ""; }
  function check() {
    var install = (form.querySelector('input[name="kind"]:checked') || {}).value === "install";
    var params = new URLSearchParams({
      pcs: Array.prototype.map.call(form.querySelectorAll('input[name="pc"]:checked'),
                                    function (b) { return b.value; }).join(","),
      auditorium: field("auditorium"), title: field("title"),
      software: install ? field("software") : ""
    });
    var query = params.toString();
    if (query === lastQuery) return;
    lastQuery = query;
    fetch(box.dataset.url + "?" + query, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : { tickets: [] }; })
      .then(function (data) {
        list.textContent = "";
        data.tickets.forEach(function (t) {
          var li = document.createElement("li");
          var a = document.createElement("a");
          a.href = t.url;
          a.target = "_blank";
          a.textContent = "№" + t.id + " " + t.title;
          var info = document.createElement("span");
          info.className = "muted small";
          info.textContent = " " + [t.pc, t.status, "касается: " + t.watchers].filter(Boolean).join(" · ")
            + (t.watching ? " · вы уже отслеживаете" : "");
          li.appendChild(a);
          li.appendChild(info);
          list.appendChild(li);
        });
        box.hidden = data.tickets.length === 0;
      })
      .catch(function () {});
  }
  function schedule() { clearTimeout(timer); timer = setTimeout(check, 400); }
  form.addEventListener("input", schedule);
  form.addEventListener("change", schedule);
  check();
})();

// Справочник ПО: мгновенный фильтр и сортировка по столбцам. Состояние хранится в адресе страницы.
(function () {
  var form = document.getElementById("sw-filters");
  var table = document.getElementById("sw-table");
  if (!form || !table) return;
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);  // исходный порядок (по названию) — для равных значений
  var headers = Array.prototype.slice.call(table.querySelectorAll("th[data-sort-key]"));
  var collator = new Intl.Collator("en", { numeric: true, sensitivity: "base" });  // en: латиница раньше кириллицы
  var count = document.getElementById("sw-count");
  var reset = document.getElementById("sw-reset");
  var wrap = document.getElementById("sw-wrap");
  var empty = document.getElementById("sw-empty");
  var params = new URLSearchParams(location.search);
  var sort = { key: "name", dir: "asc" };
  if (headers.some(function (th) { return th.dataset.sortKey === params.get("sort"); })) sort.key = params.get("sort");
  if (params.get("dir") === "desc") sort.dir = "desc";

  function value(tr, index) {
    var td = tr.cells[index];
    return "sort" in td.dataset ? td.dataset.sort : td.textContent.trim();
  }

  function applySort() {
    var index = 0, numeric = false;
    headers.forEach(function (th, i) {
      if (th.dataset.sortKey === sort.key) {
        index = i;
        numeric = th.dataset.sortType === "num";
        th.setAttribute("aria-sort", sort.dir === "asc" ? "ascending" : "descending");
      } else {
        th.removeAttribute("aria-sort");
      }
    });
    var sign = sort.dir === "asc" ? 1 : -1;
    rows.slice().sort(function (a, b) {
      var x = value(a, index), y = value(b, index);
      if (!x || !y) return x ? -1 : y ? 1 : 0;  // пустые значения всегда внизу
      return sign * (numeric ? Number(x) - Number(y) : collator.compare(x, y));
    }).forEach(function (tr) { tbody.appendChild(tr); });
  }

  function applyFilter() {
    var q = form.elements.q.value.trim().toLowerCase();
    var category = form.elements.category.value;
    var license = form.elements.license.value;
    var shown = 0;
    rows.forEach(function (tr) {
      var on = (!category || tr.dataset.category === category) && (!license || tr.dataset.license === license)
        && tr.dataset.search.toLowerCase().indexOf(q) !== -1;
      tr.hidden = !on;
      if (on) shown++;
    });
    count.textContent = shown === rows.length ? rows.length : shown + " из " + rows.length;
    wrap.hidden = shown === 0;
    empty.hidden = shown !== 0;
    reset.hidden = !(q || category || license);
  }

  function saveState() {
    var state = new URLSearchParams();
    ["q", "category", "license"].forEach(function (name) {
      var v = form.elements[name].value.trim();
      if (v) state.set(name, v);
    });
    if (sort.key !== "name" || sort.dir !== "asc") { state.set("sort", sort.key); state.set("dir", sort.dir); }
    var query = state.toString();
    history.replaceState(null, "", location.pathname + (query ? "?" + query : ""));
  }

  function onFilter() { applyFilter(); saveState(); }
  form.addEventListener("input", onFilter);
  form.addEventListener("change", onFilter);
  form.addEventListener("submit", function (e) { e.preventDefault(); });
  reset.addEventListener("click", function () {
    form.elements.q.value = "";
    form.elements.category.value = "";
    form.elements.license.value = "";
    onFilter();
    form.elements.q.focus();
  });
  headers.forEach(function (th) {
    th.querySelector(".th-sort").addEventListener("click", function () {
      var key = th.dataset.sortKey;
      sort.dir = sort.key === key ? (sort.dir === "asc" ? "desc" : "asc") : th.dataset.sortFirst;
      sort.key = key;
      applySort();
      saveState();
    });
  });

  applySort();
  applyFilter();
})();

// Массовая отметка: «выбрать всю аудиторию» и счётчик
(function () {
  var form = document.querySelector(".bulk-form");
  if (!form) return;
  var counter = document.getElementById("bulk-count");
  function boxes(group) {
    return form.querySelectorAll('input[name="pc"]' + (group ? '[data-group="' + group + '"]' : ""));
  }
  function refresh() {
    form.querySelectorAll("[data-check-all]").forEach(function (all) {
      var list = Array.prototype.slice.call(boxes(all.dataset.checkAll));
      var checked = list.filter(function (b) { return b.checked; }).length;
      all.checked = list.length > 0 && checked === list.length;
      all.indeterminate = checked > 0 && checked < list.length;
    });
    var total = Array.prototype.filter.call(boxes(), function (b) { return b.checked; }).length;
    counter.textContent = "Отмечено ПК: " + total;
  }
  form.querySelectorAll("[data-check-all]").forEach(function (all) {
    all.addEventListener("change", function () {
      boxes(all.dataset.checkAll).forEach(function (b) { b.checked = all.checked; });
      refresh();
    });
  });
  form.addEventListener("change", function (e) { if (e.target.name === "pc") refresh(); });
  refresh();
})();

// Просмотр картинок во всплывающем окне на этой же странице: ← → — соседние, Esc / клик мимо — закрыть.
// items: [{src: адрес картинки, href: ссылка «Открыть оригинал» (необязательно)}].
var openLightbox = (function () {
  var dlg, img, counter, original, items = [], index = 0;
  function build() {
    dlg = document.createElement("dialog");
    dlg.className = "lightbox";
    dlg.innerHTML =
      '<button type="button" class="lb-close" title="Закрыть (Esc)">×</button>' +
      '<button type="button" class="lb-nav lb-prev" title="Предыдущее (←)">‹</button>' +
      '<img alt="">' +
      '<button type="button" class="lb-nav lb-next" title="Следующее (→)">›</button>' +
      '<div class="lb-bar"><span class="lb-counter"></span><a class="lb-original" target="_blank" rel="noopener">Открыть оригинал</a></div>';
    document.body.appendChild(dlg);
    img = dlg.querySelector("img");
    counter = dlg.querySelector(".lb-counter");
    original = dlg.querySelector(".lb-original");
    dlg.querySelector(".lb-close").addEventListener("click", function () { dlg.close(); });
    dlg.querySelector(".lb-prev").addEventListener("click", function () { show(index - 1); });
    dlg.querySelector(".lb-next").addEventListener("click", function () { show(index + 1); });
    // Клик по тёмному фону (мимо картинки и кнопок) закрывает.
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener("keydown", function (e) {
      if (e.key === "ArrowLeft") { e.preventDefault(); show(index - 1); }
      if (e.key === "ArrowRight") { e.preventDefault(); show(index + 1); }
    });
    dlg.addEventListener("close", function () { img.removeAttribute("src"); });
  }
  function show(i) {
    if (!items.length) return;
    index = (i + items.length) % items.length;
    img.src = items[index].src;
    counter.textContent = items.length > 1 ? (index + 1) + " из " + items.length : "";
    original.hidden = !items[index].href;
    if (items[index].href) original.href = items[index].href;
    dlg.classList.toggle("lb-single", items.length < 2);
  }
  return function (list, start) {
    if (!dlg) build();
    items = list;
    show(start || 0);
    if (!dlg.open) dlg.showModal();
  };
})();

// Фото в переписке заявки — во всплывающем окне, по всем фото заявки подряд.
// Ctrl/Shift+клик — как раньше, в новой вкладке.
document.addEventListener("click", function (e) {
  var link = e.target.closest && e.target.closest(".msg-photos a");
  if (!link || e.ctrlKey || e.metaKey || e.shiftKey || !window.HTMLDialogElement) return;
  e.preventDefault();
  var links = Array.prototype.slice.call(document.querySelectorAll(".msg-photos a"));
  openLightbox(links.map(function (a) { return { src: a.href, href: a.href }; }), links.indexOf(link));
});

// Фото к заявке и ответу: выбрать файлом, вставить из буфера (Ctrl+V) или перетащить в форму.
// Выбранные фото видны миниатюрами, лишнее можно убрать. Слишком много или слишком большие — сразу
// предупредить (сервер всё равно проверит, но большой запрос nginx отклонит целиком, без понятного сообщения).
var TRASH_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
  'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/>' +
  '<path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="m19 6-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>' +
  '<path d="M10 11v6M14 11v6"/></svg>';

function initPhotoInput(input) {
  var MAX_FILE = 10 * 1024 * 1024, MAX_TOTAL = 18 * 1024 * 1024;
  // При правке сообщения число меняется: часть мест занята прежними фото.
  function maxFiles() { var n = parseInt(input.dataset.maxFiles, 10); return isNaN(n) ? 3 : n; }
  var form = input.form;
  var label = input.closest("label");
  var files = [];
  var canSet = true;  // можно ли подменять список файлов поля (во всех современных браузерах)
  try { new DataTransfer(); } catch (e) { canSet = false; }

  // Миниатюры — прямо под полем текста (туда вставляют Ctrl+V), а если его нет — под выбором файлов.
  var preview = document.createElement("div");
  preview.className = "photo-preview";
  var textarea = form && form.querySelector("textarea");
  var anchor = textarea ? (textarea.closest("label") || textarea) : (label || input);
  var inside = input.dataset.previewIn && form.querySelector(input.dataset.previewIn);  // рядом с прежними фото
  if (inside) inside.appendChild(preview); else anchor.insertAdjacentElement("afterend", preview);
  var urls = [];

  function check(list) {
    var total = list.reduce(function (s, f) { return s + f.size; }, 0);
    var big = list.filter(function (f) { return f.size > MAX_FILE; })[0];
    var max = maxFiles();
    return list.length > max ? (max > 0 ? "Можно приложить не больше " + max + " фото." : "Больше фото добавить нельзя — сначала уберите лишние.")
      : big ? "Фото «" + big.name + "» больше 10 МБ."
      : total > MAX_TOTAL ? "Фото вместе больше 18 МБ — выберите меньше или поменьше."
      : "";
  }
  function apply(list) {
    files = list;
    if (canSet) {
      var dt = new DataTransfer();
      files.forEach(function (f) { dt.items.add(f); });
      input.files = dt.files;
    }
    render();
  }
  function add(newFiles) {
    var list = files.concat(newFiles);
    var error = check(list);
    if (error) { alert(error); apply(files); return; }
    apply(list);
  }
  function render() {
    preview.textContent = "";
    urls.forEach(function (u) { URL.revokeObjectURL(u); });
    urls = files.map(function (f) { return URL.createObjectURL(f); });
    if (files.length) {
      var head = document.createElement("div");
      head.className = "photo-preview-head small muted";
      head.textContent = "Приложено фото: " + files.length + " из " + maxFiles() + " — нажмите, чтобы посмотреть";
      preview.appendChild(head);
    }
    files.forEach(function (f, i) {
      var item = document.createElement("span");
      item.className = "photo-thumb";
      var img = document.createElement("img");
      img.src = urls[i];
      img.alt = f.name;
      img.title = f.name;
      img.addEventListener("click", function () {
        if (!window.HTMLDialogElement) return;
        openLightbox(urls.map(function (u) { return { src: u }; }), i);
      });
      var del = document.createElement("button");
      del.type = "button";
      del.innerHTML = TRASH_ICON;
      del.title = "Убрать фото";
      del.setAttribute("aria-label", "Убрать фото");
      del.addEventListener("click", function () {
        apply(files.filter(function (_, j) { return j !== i; }));
      });
      item.appendChild(img);
      item.appendChild(del);
      preview.appendChild(item);
    });
  }
  // Картинки из буфера или перетаскивания; имя «Снимок экрана N», иначе все называются image.png.
  function images(list) {
    return Array.prototype.filter.call(list || [], function (f) { return /^image\//.test(f.type); })
      .map(function (f, i) {
        if (f.name && f.name !== "image.png") return f;
        var ext = (f.type.split("/")[1] || "png").replace("jpeg", "jpg");
        return new File([f], "Снимок экрана " + (files.length + i + 1) + "." + ext, { type: f.type });
      });
  }

  input.addEventListener("photos:reset", function () { apply([]); });
  input.addEventListener("change", function () {
    if (!canSet) {  // старый браузер: работает только обычный выбор файлов
      var error = check(Array.prototype.slice.call(input.files));
      if (error) { alert(error); input.value = ""; }
      return;
    }
    add(Array.prototype.slice.call(input.files).filter(function (f) { return files.indexOf(f) === -1; }));
  });
  if (!canSet || !form) return;

  form.addEventListener("paste", function (e) {
    var data = e.clipboardData;
    if (!data) return;
    // Если в буфере есть текст (например, ячейки из Excel — там ещё и картинка), вставляем текст как обычно.
    if ((data.getData("text/plain") || "").trim()) return;
    var pasted = images(data.files);
    if (!pasted.length) return;
    e.preventDefault();
    add(pasted);
  });
  form.addEventListener("dragover", function (e) {
    if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types, "Files") !== -1) {
      e.preventDefault();
      form.classList.add("drop-target");
    }
  });
  form.addEventListener("dragleave", function (e) {
    if (!form.contains(e.relatedTarget)) form.classList.remove("drop-target");
  });
  form.addEventListener("drop", function (e) {
    form.classList.remove("drop-target");
    var dropped = images(e.dataTransfer && e.dataTransfer.files);
    if (!dropped.length) return;
    e.preventDefault();
    add(dropped);
  });
}
document.querySelectorAll('input[type=file][name="photos"]').forEach(initPhotoInput);

// Отправка формы правки без перехода: ответ — JSON, ошибка показывается в самой форме.
function sendEdit(form, done) {
  var save = form.querySelector(".btn-primary"), error = form.querySelector(".form-error");
  save.disabled = true;
  error.hidden = true;
  fetch(form.action, { method: "POST", body: new FormData(form), credentials: "same-origin", headers: { Accept: "application/json" } })
    .then(function (r) { return r.json().catch(function () { return null; }); })
    .catch(function () { return null; })
    .then(function (data) {
      save.disabled = false;
      if (data && data.ok) { done(data); return; }
      error.textContent = (data && data.error) || "Не удалось сохранить. Обновите страницу и попробуйте ещё раз.";
      error.hidden = false;
    });
}

// Правка сообщения на месте: карандаш — редактор вместо текста, корзина на фото, Ctrl+Enter — сохранить, Esc — отмена.
(function () {
  var thread = document.querySelector(".thread");
  if (!thread) return;
  function updateLimit(form) {
    var input = form.querySelector('input[name="photos"]');
    input.dataset.maxFiles = input.dataset.total - form.querySelectorAll(".edit-photos [data-photo]:not([hidden])").length;
  }
  function closeEditor(msg) {
    var form = msg.querySelector(".msg-edit-form");
    form.reset();
    form.querySelectorAll('input[name="remove"]').forEach(function (i) { i.remove(); });
    form.querySelectorAll("[data-photo]").forEach(function (p) { p.hidden = false; });
    form.querySelector(".form-error").hidden = true;
    updateLimit(form);
    form.querySelector('input[name="photos"]').dispatchEvent(new Event("photos:reset"));
    msg.classList.remove("editing");
  }
  function openEditor(msg) {
    msg.classList.add("editing");
    var ta = msg.querySelector(".msg-edit-form textarea");
    ta.focus();
    ta.setSelectionRange(ta.value.length, ta.value.length);
  }
  thread.addEventListener("click", function (e) {
    var t = e.target, msg = t.closest && t.closest(".msg");
    if (!msg) return;
    if (t.closest("[data-msg-edit]")) { openEditor(msg); return; }
    if (t.closest("[data-msg-cancel]")) { closeEditor(msg); return; }
    var remove = t.closest("[data-photo-remove]");
    if (remove) {
      var item = remove.closest("[data-photo]"), form = msg.querySelector(".msg-edit-form");
      var field = document.createElement("input");
      field.type = "hidden"; field.name = "remove"; field.value = item.dataset.photo;
      form.appendChild(field);
      item.hidden = true;
      updateLimit(form);
      return;
    }
    if (t.matches("[data-photo] img") && window.HTMLDialogElement) {
      var imgs = Array.prototype.slice.call(msg.querySelectorAll(".edit-photos [data-photo]:not([hidden]) img"));
      openLightbox(imgs.map(function (i) { return { src: i.dataset.full, href: i.dataset.full }; }), imgs.indexOf(t));
    }
  });
  thread.addEventListener("keydown", function (e) {
    if (!e.target.matches(".msg-edit-form textarea")) return;
    var msg = e.target.closest(".msg");
    if (e.key === "Escape") closeEditor(msg);
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); msg.querySelector(".msg-edit-form").requestSubmit(); }
  });
  thread.addEventListener("submit", function (e) {
    if (!e.target.matches(".msg-edit-form")) return;
    e.preventDefault();
    var form = e.target, msg = form.closest(".msg");
    sendEdit(form, function (data) {
      var box = document.createElement("div");
      box.innerHTML = data.html;
      var fresh = box.firstElementChild;
      msg.replaceWith(fresh);
      fresh.querySelectorAll('input[type=file][name="photos"]').forEach(initPhotoInput);
    });
  });
})();

// Правка заявки на её странице: форма раскрывается вместо карточки с данными.
(function () {
  var btn = document.querySelector("[data-ticket-edit]"), form = document.getElementById("ticket-form");
  if (!btn || !form) return;
  var specs = document.querySelector(".ticket-specs");
  function toggle(open) { form.hidden = !open; specs.hidden = open; btn.hidden = open; }
  btn.addEventListener("click", function () { toggle(true); });
  form.querySelector("[data-ticket-cancel]").addEventListener("click", function () {
    form.reset();
    form.querySelector(".form-error").hidden = true;
    document.getElementById("ticket-aud").dispatchEvent(new Event("change"));
    toggle(false);
  });
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    sendEdit(form, function (data) { if (data.changed) location.reload(); else toggle(false); });
  });
})();

// Кнопка «глазик» у полей пароля: показать введённое, чтобы не ошибиться
document.querySelectorAll('input[type="password"]').forEach(function (input) {
  var EYE = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/>' +
            '<circle cx="12" cy="12" r="3"/>';
  var ICON_SHOW = EYE + '</svg>';
  var ICON_HIDE = EYE + '<path d="M3 3l18 18"/></svg>';
  var wrap = document.createElement("span");
  wrap.className = "pw-wrap";
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);
  var btn = document.createElement("button");
  btn.type = "button";
  btn.className = "pw-toggle";
  function render() {
    var shown = input.type === "text";
    btn.innerHTML = shown ? ICON_HIDE : ICON_SHOW;
    btn.title = shown ? "Скрыть пароль" : "Показать пароль";
    btn.setAttribute("aria-label", btn.title);
    btn.setAttribute("aria-pressed", shown ? "true" : "false");
  }
  btn.addEventListener("click", function (e) {
    e.preventDefault();
    input.type = input.type === "password" ? "text" : "password";
    render();
    input.focus();
  });
  // Перед отправкой — снова скрыть, чтобы браузер сохранял пароль как пароль.
  if (input.form) input.form.addEventListener("submit", function () { input.type = "password"; });
  wrap.appendChild(btn);
  render();
});

// Карта ПК в сети на главной: статусы по ping, обновляются раз в минуту, пока вкладка открыта
(function () {
  var map = document.getElementById("netmap");
  if (!map) return;
  var summary = document.getElementById("netmap-summary");
  var button = document.getElementById("netmap-refresh");
  var tiles = map.querySelectorAll(".net-pc[data-host]");
  var TEXT = { up: "в сети", down: "не отвечает", noip: "адрес неизвестен: нет в DNS и нет «IP: …» в примечании", off: "списан",
              wait: "не проверен" };
  var busy = false, timer = null;

  function apply(data) {
    var up = 0, total = 0, perAud = {};
    tiles.forEach(function (el) {
      var info = data.pcs[el.dataset.host] || { state: "noip" };
      el.className = el.className.replace(/\bstate-\w+/, "state-" + info.state);
      el.title = el.dataset.host + (info.ip ? " · " + info.ip : el.dataset.label.slice(el.dataset.host.length)) +
        " — " + TEXT[info.state] + (info.ms != null ? " (" + info.ms + " мс)" : "");
      var a = perAud[el.dataset.aud] || (perAud[el.dataset.aud] = { up: 0, total: 0 });
      if (info.state !== "off" && info.state !== "wait") { total++; a.total++; }
      if (info.state === "up") { up++; a.up++; }
    });
    Object.keys(perAud).forEach(function (num) {
      var span = map.querySelector('[data-aud-count="' + num + '"]');
      if (span && !data.error) span.textContent = perAud[num].up + " из " + perAud[num].total + " в сети";
    });
    summary.textContent = data.error
      ? data.error
      : "В сети " + up + " из " + total + " ПК · проверено в " + data.checked_at;
    summary.classList.toggle("netmap-error", !!data.error);
  }

  function refresh() {
    if (busy) return;
    busy = true;
    button.disabled = true;
    map.classList.add("is-loading");
    fetch(map.dataset.url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(apply)
      .catch(function () { summary.textContent = "Не удалось проверить сеть. Попробуйте обновить."; })
      .then(function () { busy = false; button.disabled = false; map.classList.remove("is-loading"); });
  }

  function schedule() {
    clearInterval(timer);
    timer = document.hidden ? null : setInterval(refresh, 60000);
  }

  button.addEventListener("click", refresh);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); schedule(); });
  refresh();
  schedule();
})();

// Светлая / тёмная тема. Пока не выбрана — как в системе; выбор запоминается в браузере.
document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var root = document.documentElement;
    var current = root.dataset.theme ||
      (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    var next = current === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch (e) {}
  });
});

// Меню на телефоне: закрыть по Esc и при переходе по пункту.
(function () {
  var toggle = document.getElementById("nav-toggle");
  if (!toggle) return;
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") toggle.checked = false; });
  document.querySelectorAll(".sidebar a").forEach(function (a) {
    a.addEventListener("click", function () { toggle.checked = false; });
  });
})();

// Страница ПК: «в сети / не в сети».
(function () {
  var badge = document.querySelector("[data-online-url]");
  if (!badge || !window.fetch) return;
  var TEXT = { up: "в сети", down: "не в сети", noip: "сеть: адрес неизвестен", wait: "сеть: не проверить" };
  function show(data) {
    badge.className = "badge online-badge online-" + data.state;
    badge.textContent = TEXT[data.state] || "";
    badge.hidden = data.state === "off";
    var title = data.state === "up" ? "Отвечает на ping" + (data.ms != null ? " за " + Math.round(data.ms) + " мс" : "")
      : data.state === "down" ? "Не отвечает на ping"
      : data.state === "noip" ? "Нет адреса: ПК не найден в DNS и нет «IP: …» в примечании"
      : (data.error || "Сервер не смог проверить");
    if (data.ip) title += " · " + data.ip;
    if (data.checked_at) title += " · проверено в " + data.checked_at;
    badge.title = title;
  }
  function load() {
    fetch(badge.dataset.onlineUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { if (data) show(data); })
      .catch(function () {});
  }
  load();
  setInterval(function () { if (!document.hidden) load(); }, 30000);
})();

// Плашка «Включение ПК»: после «Включить» сервер 3 минуты ждёт ответа на ping; здесь — ход и итог.
(function () {
  var box = document.getElementById("wake-box");
  if (!box) return;
  var watch = parseInt(box.dataset.watch, 10) || 180;
  var chips = box.querySelector(".wake-chips"), summary = box.querySelector(".wake-summary");
  var failedNote = box.querySelector(".wake-failed");
  var hidden = 0, jobs = [], fetchedAt = Date.now(), timer = null;
  try { hidden = parseInt(localStorage.getItem("wake-hidden"), 10) || 0; } catch (e) {}
  function dur(s) { s = Math.max(0, Math.round(s)); return s >= 60 ? Math.floor(s / 60) + " мин " + (s % 60) + " с" : s + " с"; }
  function clock(s) { s = Math.max(0, Math.round(s)); var m = Math.floor(s / 60), r = s % 60; return m + ":" + (r < 10 ? "0" : "") + r; }
  function render() {
    var maxId = jobs.reduce(function (m, j) { return Math.max(m, j.id); }, 0);
    box.hidden = !jobs.length || maxId <= hidden;
    if (box.hidden) return;
    var count = { up: 0, waiting: 0, failed: 0, already: 0, lost: 0 }, failed = [];
    var passed = (Date.now() - fetchedAt) / 1000;
    chips.textContent = "";
    jobs.forEach(function (j) {
      count[j.state] = (count[j.state] || 0) + 1;
      var el = document.createElement(j.url ? "a" : "span");
      if (j.url) el.href = j.url;
      el.className = "wake-chip wake-" + j.state;
      var note = { up: "за " + dur(j.seconds), failed: "не включился", already: "уже в сети", lost: "не проверено" }[j.state]
        || clock(j.seconds + passed) + " из " + clock(watch);
      el.title = {
        waiting: "Ждём ответа на ping — до " + Math.round(watch / 60) + " мин",
        up: "Ответил на ping через " + dur(j.seconds) + " после «Включить»",
        failed: "Не ответил на ping за " + Math.round(watch / 60) + " мин",
        already: "Был в сети уже в момент «Включить»",
        lost: "Проверка прервалась (перезапуск сервера) — смотрите «ПК в сети»"
      }[j.state] + (j.who ? " · включал: " + j.who : "");
      el.textContent = j.hostname + " ";
      var small = document.createElement("small");
      small.textContent = note;
      el.appendChild(small);
      chips.appendChild(el);
      if (j.state === "failed") failed.push(j.hostname);
    });
    var parts = [];
    if (count.up) parts.push("включились: " + count.up);
    if (count.waiting) parts.push("ждём ответа: " + count.waiting);
    if (count.failed) parts.push("не включились: " + count.failed);
    if (count.already) parts.push("уже были в сети: " + count.already);
    if (count.lost) parts.push("не проверено: " + count.lost);
    summary.textContent = parts.join(" · ");
    failedNote.hidden = !failed.length;
    failedNote.textContent = failed.length
      ? "Не удалось включить " + failed.join(", ") + ": нет ответа на ping за " + Math.round(watch / 60) +
        " мин. Проверьте питание и сетевой кабель, включён ли Wake-on-LAN в BIOS и в настройках сетевой карты."
      : "";
  }
  function poll() {
    fetch(box.dataset.url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;
        jobs = data.jobs; fetchedAt = Date.now(); render(); schedule();
      })
      .catch(schedule);
  }
  function schedule() {
    clearTimeout(timer);
    if (jobs.some(function (j) { return j.state === "waiting"; })) timer = setTimeout(poll, 5000);
  }
  box.querySelector("[data-wake-hide]").addEventListener("click", function () {
    hidden = jobs.reduce(function (m, j) { return Math.max(m, j.id); }, 0);
    try { localStorage.setItem("wake-hidden", String(hidden)); } catch (e) {}
    render();
  });
  try { jobs = JSON.parse(box.dataset.jobs); } catch (e) { jobs = []; }
  render();
  schedule();
  setInterval(function () { if (jobs.some(function (j) { return j.state === "waiting"; })) render(); }, 1000);
})();
