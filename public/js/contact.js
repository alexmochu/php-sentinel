// Message modal. One form handler for every page (previously duplicated three times).
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var modal = S.$("msgModal");
  var lastFocus = null;

  function open(prefillSite) {
    if (!modal) return;
    if (S.closeNavMenus) S.closeNavMenus();
    lastFocus = document.activeElement;
    var site = S.$("gMsgSite");
    var urlInput = S.$("urlInput");
    if (site && !site.value) site.value = prefillSite || (urlInput && urlInput.value) || "";
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    var em = S.$("gMsgEmail");
    if (em) setTimeout(function () { em.focus(); }, 50);
  }

  function close() {
    if (!modal) return;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  /** Send a message. Resolves with the response body or rejects with an Error that has a readable message. */
  function send(payload) {
    return S.postJSON("/api/message", payload).then(function (res) {
      if (!res.ok || !res.body || !res.body.ok) {
        throw new Error((res.body && res.body.error) || "Could not send. Try again or book a call.");
      }
      S.track("message_sent", { source: payload.source, wants_call: !!payload.wants_call });
      return res.body;
    });
  }

  S.contact = { open: open, close: close, send: send };

  document.addEventListener("click", function (e) {
    var trigger = e.target.closest && e.target.closest("[data-open-message]");
    if (trigger) open();
  });
  if (modal) {
    S.$("msgModalClose").addEventListener("click", close);
    modal.addEventListener("click", function (e) { if (e.target === modal) close(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") close(); });
  }

  var form = S.$("globalMsgForm");
  if (!form) return;
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var email = (S.$("gMsgEmail").value || "").trim();
    var message = (S.$("gMsgBody").value || "").trim();
    var status = S.$("gMsgStatus");
    var btn = S.$("gMsgSubmit");
    if (!email || email.indexOf("@") < 1) { status.textContent = "Enter a valid email."; return; }
    if (message.length < 5) { status.textContent = "Write a short message first."; return; }
    var wants = !!S.$("gMsgWantsCall").checked;
    btn.disabled = true;
    btn.textContent = "Sending…";
    status.textContent = "";
    send({
      email: email,
      message: message,
      site_url: (S.$("gMsgSite").value || "").trim(),
      phone: S.$("gMsgPhone").value || "",
      wants_call: wants,
      source: (document.body.getAttribute("data-page") || "page") + "_modal",
      website: S.$("gMsgHp").value || ""
    }).then(function () {
      form.classList.add("hidden");
      S.$("gMsgSuccess").classList.remove("hidden");
      if (wants) S.$("gMsgSuccessCall").classList.remove("hidden");
    }).catch(function (err) {
      status.textContent = err.message;
      btn.disabled = false;
      btn.textContent = "Send message";
    });
  });
})();
