// DVMA docs: client-side enhancements.
//
// Manual Testing checklist: Goldmark renders task-list checkboxes as
// `disabled`, so by default they can't be ticked. Here we enable them ONLY on
// the manual-testing page and persist their state to localStorage (keyed by a
// stable hash of each item's text) so progress survives reloads and revisits
// within the same browser. State is per-browser and not synced anywhere.
(function () {
  "use strict";

  // Scope strictly to the Manual Testing section (the platform sub-pages
  // /manual-testing/android/ and /manual-testing/ios/, plus the /manual-testing/
  // landing page) so we never touch checkboxes that belong to the theme's own
  // UI. The landing page has no task-list boxes, so init() bails there anyway.
  if (!/\/manual-testing\//.test(window.location.pathname)) return;

  var STORAGE_PREFIX = "dvma-checklist:";

  // The Manual Testing section has one page per platform (…/android/, …/ios/).
  // Namespace stored state by that page slug so each platform's checklist is
  // fully independent: checking or resetting Android never affects iOS, even
  // for the modules that appear on both pages.
  var PAGE_SCOPE = (window.location.pathname.match(
    /\/manual-testing\/([^/]+)\/?$/
  ) || [, "index"])[1];

  // Stable, order-independent key for a checklist item, derived from its label
  // text (djb2) and scoped to the current platform page. Survives page rebuilds
  // as long as the wording is unchanged.
  function keyFor(text) {
    var hash = 5381;
    for (var i = 0; i < text.length; i++) {
      hash = ((hash << 5) + hash + text.charCodeAt(i)) >>> 0;
    }
    return STORAGE_PREFIX + PAGE_SCOPE + ":" + hash;
  }

  function itemLabel(checkbox) {
    var li = checkbox.closest("li");
    return (li ? li.textContent : checkbox.value || "").trim();
  }

  function init() {
    var boxes = Array.prototype.slice.call(
      document.querySelectorAll('.book-page input[type="checkbox"], #R-body input[type="checkbox"], main input[type="checkbox"]')
    ).filter(function (b) {
      return b.closest("li"); // only markdown task-list items live inside <li>
    });
    if (!boxes.length) return;

    boxes.forEach(function (box) {
      box.removeAttribute("disabled");
      box.style.cursor = "pointer";
      var li = box.closest("li");
      if (li) li.classList.add("dvma-check-item"); // CSS spacing hook
      var key = keyFor(itemLabel(box));
      if (localStorage.getItem(key) === "1") box.checked = true;
      box.addEventListener("change", function () {
        try {
          if (box.checked) localStorage.setItem(key, "1");
          else localStorage.removeItem(key);
        } catch (e) {
          /* storage disabled (private mode) — checkbox still toggles in-session */
        }
        updateProgress(boxes);
      });
    });

    addToolbar(boxes);
    updateProgress(boxes);
  }

  var progressEl;

  function addToolbar(boxes) {
    var heading = document.querySelector("#R-body h1, main h1, .book-page h1");
    if (!heading) return;
    var bar = document.createElement("div");
    bar.className = "dvma-checklist-toolbar";
    progressEl = document.createElement("span");
    progressEl.className = "dvma-checklist-progress";
    var reset = document.createElement("button");
    reset.type = "button";
    reset.className = "dvma-checklist-reset";
    reset.textContent = "Reset checklist";
    reset.addEventListener("click", function () {
      boxes.forEach(function (box) {
        box.checked = false;
        try {
          localStorage.removeItem(keyFor(itemLabel(box)));
        } catch (e) {}
      });
      updateProgress(boxes);
    });
    bar.appendChild(progressEl);
    bar.appendChild(reset);
    heading.insertAdjacentElement("afterend", bar);
  }

  function updateProgress(boxes) {
    if (!progressEl) return;
    var done = boxes.filter(function (b) {
      return b.checked;
    }).length;
    progressEl.textContent = done + " / " + boxes.length + " checked";
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
