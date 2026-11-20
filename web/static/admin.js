(function () {
  "use strict";

  function slugify(name) {
    name = name.replace(/\.[^.]+$/, "").toLowerCase();
    var out = "";
    var dash = false;
    for (var i = 0; i < name.length; i++) {
      var c = name[i];
      if ((c >= "a" && c <= "z") || (c >= "0" && c <= "9")) {
        out += c;
        dash = false;
      } else if (!dash && out.length) {
        out += "-";
        dash = true;
      }
    }
    return out.replace(/^-+|-+$/g, "").slice(0, 63) || "seite";
  }

  // Segmented input switcher
  document.querySelectorAll(".segmented").forEach(function (group) {
    var buttons = Array.prototype.slice.call(group.querySelectorAll(".seg"));
    var form = group.closest("form") || document;

    function select(btn, focus) {
      buttons.forEach(function (b) {
        var on = b === btn;
        b.classList.toggle("active", on);
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.tabIndex = on ? 0 : -1;
      });
      var name = btn.getAttribute("data-tab");
      form.querySelectorAll("[role=tabpanel]").forEach(function (panel) {
        panel.hidden = panel.id !== "panel-" + name;
      });
      if (focus) btn.focus();
    }

    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () { select(btn, false); });
      btn.addEventListener("keydown", function (e) {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        e.preventDefault();
        var i = buttons.indexOf(btn);
        var next = buttons[(i + (e.key === "ArrowRight" ? 1 : buttons.length - 1)) % buttons.length];
        select(next, true);
      });
    });
  });

  // Access mode fields
  function syncMode(select) {
    var form = select.closest("form");
    if (!form) return;
    form.querySelectorAll(".mode-field").forEach(function (field) {
      var on = field.getAttribute("data-mode") === select.value;
      field.hidden = !on;
      field.querySelectorAll("input").forEach(function (input) {
        input.disabled = !on;
        if (form.id === "deploy-form") input.required = on;
      });
    });
  }
  document.querySelectorAll("select#mode-select").forEach(function (select) {
    syncMode(select);
    select.addEventListener("change", function () { syncMode(select); });
  });

  // File input
  var fileInput = document.getElementById("file-input");
  var pathInput = document.getElementById("path-input");
  var dropzoneSub = document.getElementById("dropzone-sub");
  if (fileInput) {
    fileInput.addEventListener("change", function () {
      var f = fileInput.files && fileInput.files[0];
      if (!f) return;
      if (dropzoneSub) dropzoneSub.textContent = f.name;
      if (pathInput && !pathInput.value.trim()) {
        pathInput.value = slugify(f.name);
        pathInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
      if (/\.zip$/i.test(f.name)) {
        var multi = document.querySelector('input[name="multi"]');
        if (multi) multi.checked = true;
      }
    });
  }

  document.querySelectorAll("[data-focus-file]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (fileInput) fileInput.click();
    });
  });

  // Drag & drop visual state
  var dropzone = document.getElementById("dropzone");
  if (dropzone) {
    ["dragenter", "dragover"].forEach(function (ev) {
      dropzone.addEventListener(ev, function (e) {
        e.preventDefault();
        dropzone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      dropzone.addEventListener(ev, function (e) {
        e.preventDefault();
        dropzone.classList.remove("dragover");
      });
    });
  }

  // Live deploy summary: what the current path will actually write.
  var summary = document.getElementById("deploy-summary");
  var summaryTag = document.getElementById("deploy-tag");
  var summaryTarget = document.getElementById("deploy-target");
  var submitLabel = document.querySelector("#deploy-submit .btn-label");
  var prefixEl = document.querySelector("#deploy-form .input-prefix .prefix");
  var knownPaths = {};
  document.querySelectorAll("#known-paths option").forEach(function (opt) {
    knownPaths[opt.value] = true;
  });

  var PATH_RE = /^[a-z0-9-]+(\/[a-z0-9-]+){0,3}$/;

  function setSummary(state, tag, text) {
    if (!summary) return;
    summary.setAttribute("data-state", state);
    if (summaryTag) summaryTag.textContent = tag;
    if (summaryTarget) summaryTarget.textContent = text;
  }

  function syncSummary() {
    if (!summary || !pathInput) return;
    var raw = pathInput.value.trim().replace(/^\/+|\/+$/g, "");
    var base = prefixEl ? prefixEl.textContent.replace(/\/+$/, "") : "";

    if (!raw) {
      setSummary("idle", "Neu", "Pfad wählen — z. B. meine-seite");
      if (submitLabel) submitLabel.textContent = "Deployen";
      return;
    }
    var field = pathInput.closest(".field");
    if (!PATH_RE.test(raw) || raw.length > 200) {
      setSummary("invalid", "Ungültig", "Pfad nicht verwendbar");
      if (field) field.setAttribute("data-invalid", "true");
      if (submitLabel) submitLabel.textContent = "Deployen";
      return;
    }
    if (field) field.removeAttribute("data-invalid");
    var url = base + "/" + raw + "/";
    if (knownPaths[raw]) {
      setSummary("existing", "Neue Version", url);
      if (submitLabel) submitLabel.textContent = "Neue Version deployen";
    } else {
      setSummary("new", "Neu", url);
      if (submitLabel) submitLabel.textContent = "Deployen";
    }
  }

  if (pathInput) {
    pathInput.addEventListener("input", syncSummary);
    syncSummary();
  }

  // Submit state
  var deployForm = document.getElementById("deploy-form");
  if (deployForm) {
    deployForm.addEventListener("submit", function () {
      var btn = document.getElementById("deploy-submit");
      if (!btn) return;
      btn.disabled = true;
      var spinner = btn.querySelector(".spinner");
      if (submitLabel) submitLabel.textContent = "Wird deployed…";
      if (spinner) spinner.hidden = false;
    });
  }

  // Copy buttons
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy") || "";
      var iconOnly = !!btn.querySelector("svg");
      var done = function () {
        if (iconOnly) {
          btn.classList.add("copied");
          btn.setAttribute("title", "Kopiert");
          setTimeout(function () {
            btn.classList.remove("copied");
            btn.setAttribute("title", "Link kopieren");
          }, 1400);
          return;
        }
        var old = btn.textContent;
        btn.textContent = "Kopiert";
        setTimeout(function () { btn.textContent = old; }, 1400);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
      } else {
        fallbackCopy(text, done);
      }
    });
  });

  function fallbackCopy(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  // Confirmation
  document.querySelectorAll("[data-confirm]").forEach(function (el) {
    el.addEventListener("click", function (e) {
      if (!window.confirm(el.getAttribute("data-confirm"))) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    });
  });

  // Page filter
  var search = document.getElementById("site-search");
  if (search) {
    var rows = Array.prototype.slice.call(document.querySelectorAll("#site-list tr"));
    var empty = document.getElementById("site-empty");
    var count = document.getElementById("site-count");
    search.addEventListener("input", function () {
      var q = search.value.trim().toLowerCase();
      var visible = 0;
      rows.forEach(function (row) {
        var hay = (row.getAttribute("data-search") || "").toLowerCase();
        var show = !q || hay.indexOf(q) !== -1;
        row.hidden = !show;
        if (show) visible++;
      });
      if (empty) empty.hidden = visible !== 0;
      var wrap = document.querySelector(".register .table-wrap");
      if (wrap) wrap.hidden = visible === 0;
      if (count) count.textContent = q ? visible + " / " + rows.length : rows.length;
    });
  }
})();
