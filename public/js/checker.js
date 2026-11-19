// The URL form, the scan request and the result flow.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});

  var FOCUS_HIDE = ["sideHelp", "sideAbout", "statsTicker", "analyticsSection", "waitlistSection", "faqSection", "eduSection"];

  function setFocusMode(on) {
    S.$("mainGrid").classList.toggle("mode-focus", on);
    FOCUS_HIDE.forEach(function (id) {
      var el = S.$(id);
      if (el) el.classList.toggle("hidden", on);
    });
  }

  function scanOne(url) {
    return S.postJSON("/api/scan", { url: url }).then(function (res) {
      if (!res.ok && !(res.body && res.body.error)) return { error: "The check failed. Please try again." };
      return res.body;
    });
  }

  function bindResultActions(view, data, input, apiInput) {
    var badge = S.$("badgeCode");
    if (badge) badge.textContent = view.badge;
    var on = function (id, fn) { var el = S.$(id); if (el) el.addEventListener("click", fn); };
    on("copyBadgeBtn", function () { S.copy(S.state.lastBadgeHtml).then(function () { S.toast("Badge HTML copied"); }); });
    on("copyResultBtn", function () { S.copy(S.state.lastResultText).then(function () { S.toast("Result copied"); }); });
    on("emailReportBtn", function () {
      var email = (S.$("emailReport") || {}).value || "";
      window.location.href = "mailto:" + encodeURIComponent(email).replace(/%40/g, "@") +
        "?subject=" + encodeURIComponent("Sentinel site report") + "&body=" + encodeURIComponent(S.state.lastResultText);
    });
    on("checkAnotherBtn", function () {
      S.$("result").classList.add("hidden");
      S.$("ctaSection").classList.add("hidden");
      setFocusMode(false);
      input.value = "";
      apiInput.value = "";
      input.focus();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    var share = S.$("shareXBtn");
    if (share) share.href = "https://x.com/intent/post?text=" + encodeURIComponent(S.state.lastResultText);
    on("useApiSuggestion", function () { apiInput.value = data.api_suggestion; apiInput.focus(); });
  }

  function showResult(data, secondary, input, apiInput) {
    var view = S.resultView.build(data, secondary);
    var result = S.$("result");
    result.innerHTML = view.html;
    result.classList.remove("hidden");
    if (!view.ok) return;

    S.state.lastResultText = view.text;
    S.state.lastBadgeHtml = view.badge;
    bindResultActions(view, data, input, apiInput);
    S.remediation.mount(S.$("fixMount"), data);
    S.resultCta.render(S.$("ctaSection"), data, data.url || input.value || "");
    S.track("scan_completed", { status: data.status });
    if (data.status !== "error") S.stats.refresh();
  }

  function init() {
    var input = S.$("urlInput"), apiInput = S.$("apiInput"), btn = S.$("checkBtn"), btnText = S.$("btnText");
    var loading = S.$("loading"), result = S.$("result"), cta = S.$("ctaSection");
    if (!input || !btn) return;

    function run() {
      var url = input.value.trim();
      if (!url) { input.focus(); return; }
      setFocusMode(true);
      btn.disabled = true;
      btnText.textContent = "Scanning…";
      loading.classList.remove("hidden");
      result.classList.add("hidden");
      cta.classList.add("hidden");

      scanOne(url).then(function (primary) {
        var apiUrl = apiInput.value.trim();
        if (!apiUrl || (primary && primary.error && !primary.status)) return { primary: primary, secondary: null };
        return scanOne(apiUrl).then(function (secondary) { return { primary: primary, secondary: secondary }; });
      }).then(function (pair) {
        loading.classList.add("hidden");
        showResult(pair.primary, pair.secondary, input, apiInput);
      }).catch(function () {
        loading.classList.add("hidden");
        result.innerHTML = S.resultView.errorCard("Something went wrong. Check your connection and try again.");
        result.classList.remove("hidden");
      }).then(function () {
        btn.disabled = false;
        btnText.textContent = "Check Now";
      });
    }

    btn.addEventListener("click", run);
    input.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
  }

  S.checker = { init: init, showResult: showResult };
})();