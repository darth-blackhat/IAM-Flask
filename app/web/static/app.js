// backend-iam web UI. Same-origin only (CSP script-src 'self'); no inline script.
// Progressive enhancement: every page also works with JavaScript off.
(function () {
  "use strict";

  // ---- DataTables: <table data-dt> gets search, sort and paging ----------------
  // Our tables are plain <tr> rows with a <th> header row; DataTables needs a <thead>.
  function initTables() {
    if (typeof window.DataTable !== "function") { return; }
    document.querySelectorAll("table[data-dt]").forEach(function (table) {
      var rows = table.querySelectorAll("tr");
      // An empty table has one "nothing here" row with a colspan: leave it plain.
      if (rows.length < 2 || table.querySelector("td[colspan]")) { return; }
      if (!table.tHead) {
        var head = table.createTHead();
        head.appendChild(rows[0]);
      }
      var opts = {
        pageLength: parseInt(table.getAttribute("data-dt-page") || "25", 10),
        lengthMenu: [10, 25, 50, 100, 250],
        order: [],                     // keep the server's order until a header is clicked
        autoWidth: false,
        language: { search: "Filter:", emptyTable: "Nothing here." }
      };
      if (table.hasAttribute("data-dt-nopage")) { opts.paging = false; }
      try { new window.DataTable(table, opts); } catch (e) { /* stay a plain table */ }
    });
  }

  // ---- confirm dangerous buttons: <button data-confirm="..."> ------------------
  document.addEventListener("submit", function (e) {
    var b = e.submitter;
    var msg = b && b.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { e.preventDefault(); }
  });

  // ---- new user: suggest a login until one is typed ----------------------------
  function suggestLogin() {
    var first = document.querySelector("input[name=first_name][data-suggest]");
    var last = document.querySelector("input[name=last_name][data-suggest]");
    var login = document.querySelector("input[name=login][data-suggest]");
    if (!first || !last || !login) { return; }
    var typed = false;
    login.addEventListener("input", function () { typed = login.value !== ""; });
    var suggest = function () {
      if (typed) { return; }
      login.value = (first.value.charAt(0) + last.value).toLowerCase()
        .replace(/[^a-z0-9._-]/g, "").slice(0, 20);
    };
    first.addEventListener("input", suggest);
    last.addEventListener("input", suggest);
  }

  // ---- member forms: placeholder follows the chosen member kind ----------------
  function memberHints() {
    document.querySelectorAll("select[name=member_kind]").forEach(function (sel) {
      var input = sel.form && sel.form.querySelector("input[name=member]");
      if (!input) { return; }
      var update = function () {
        input.placeholder = sel.value === "group"
          ? "group name (it becomes memberOf this group)" : "employee id";
      };
      sel.addEventListener("change", update);
      update();
    });
  }

  // ---- "Via" choice: show what it means next to the select ---------------------
  function viaHints() {
    document.querySelectorAll("select[name=via]").forEach(function (sel) {
      var hint = document.createElement("span");
      hint.className = "muted hint";
      var update = function () {
        hint.textContent = sel.value === "ad"
          ? "OpenIAM is not changed (drift will show it)"
          : "OpenIAM first, then AD instructions";
      };
      sel.addEventListener("change", update);
      sel.insertAdjacentElement("afterend", hint);
      update();
    });
  }

  // ---- theme: apply at once (the form still saves the cookie) -------------------
  document.querySelectorAll("form.theme button[name=theme]").forEach(function (b) {
    b.addEventListener("click", function () {
      document.documentElement.setAttribute("data-theme", b.value);
    });
  });

  // ---- pages that wait on the service: refresh while something is running -------
  function autoRefresh() {
    var el = document.querySelector("[data-refresh-while]");
    if (!el) { return; }
    if (!document.querySelector(el.getAttribute("data-refresh-while"))) { return; }
    var tick = function () {
      // Never throw away something being typed.
      var typing = Array.prototype.some.call(document.querySelectorAll("input:not([type=hidden]),textarea"),
        function (i) { return i.value !== "" || i === document.activeElement; });
      if (typing) { window.setTimeout(tick, 5000); } else { window.location.reload(); }
    };
    window.setTimeout(tick, 5000);
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTables();
    suggestLogin();
    memberHints();
    viaHints();
    autoRefresh();
  });
})();
