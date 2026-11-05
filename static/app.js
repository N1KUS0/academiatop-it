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

// Фото к заявке и ответу: выбрать файлом, вставить из буфера (Ctrl+V) или перетащить в форму.
// Выбранные фото видны миниатюрами, лишнее можно убрать. Слишком много или слишком большие — сразу
// предупредить (сервер всё равно проверит, но большой запрос nginx отклонит целиком, без понятного сообщения).
document.querySelectorAll('input[type=file][name="photos"]').forEach(function (input) {
  var MAX_FILE = 10 * 1024 * 1024, MAX_TOTAL = 18 * 1024 * 1024;
  var max = parseInt(input.dataset.maxFiles, 10) || 3;
  var form = input.form;
  var label = input.closest("label");
  var files = [];
  var canSet = true;  // можно ли подменять список файлов поля (во всех современных браузерах)
  try { new DataTransfer(); } catch (e) { canSet = false; }

  var preview = document.createElement("div");
  preview.className = "photo-preview";
  (label || input).insertAdjacentElement("afterend", preview);

  function check(list) {
    var total = list.reduce(function (s, f) { return s + f.size; }, 0);
    var big = list.filter(function (f) { return f.size > MAX_FILE; })[0];
    return list.length > max ? "Можно приложить не больше " + max + " фото."
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
    files.forEach(function (f, i) {
      var item = document.createElement("span");
      item.className = "photo-thumb";
      var img = document.createElement("img");
      img.src = URL.createObjectURL(f);
      img.alt = f.name;
      img.onload = function () { URL.revokeObjectURL(img.src); };
      var del = document.createElement("button");
      del.type = "button";
      del.textContent = "×";
      del.title = "Убрать фото";
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
});

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
  var TEXT = { up: "в сети", down: "не отвечает", noip: "IP неизвестен — впишите «IP: …» в примечание", off: "списан",
              wait: "не проверен" };
  var busy = false, timer = null;

  function apply(data) {
    var up = 0, total = 0, perAud = {};
    tiles.forEach(function (el) {
      var info = data.pcs[el.dataset.host] || { state: "noip" };
      el.className = el.className.replace(/\bstate-\w+/, "state-" + info.state);
      el.title = el.dataset.label + " — " + TEXT[info.state] + (info.ms != null ? " (" + info.ms + " мс)" : "");
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
