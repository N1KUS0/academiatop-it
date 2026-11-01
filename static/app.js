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
