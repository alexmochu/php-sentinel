// Abuse, removal and security report form (abuse.html).
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var form = S.$("reportForm");
  if (!form) return;
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var status = S.$("reportStatus"), btn = S.$("reportSubmit");
    var email = (S.$("reportEmail").value || "").trim();
    var details = (S.$("reportDetails").value || "").trim();
    if (!email || email.indexOf("@") < 1) { status.textContent = "Enter a valid email so we can reply."; return; }
    if (details.length < 5) { status.textContent = "Add a few details."; return; }
    btn.disabled = true; btn.textContent = "Sending…"; status.textContent = "";
    S.postJSON("/api/report", {
      kind: S.$("reportKind").value, email: email, domain: (S.$("reportDomain").value || "").trim(),
      details: details, website: S.$("reportHp").value || ""
    }).then(function (res) {
      if (!res.ok || !res.body || !res.body.ok) throw new Error((res.body && res.body.error) || "Could not send. Please email us instead.");
      form.classList.add("hidden");
      S.$("reportDone").classList.remove("hidden");
    }).catch(function (err) {
      status.textContent = err.message; btn.disabled = false; btn.textContent = "Send report";
    });
  });
})();
