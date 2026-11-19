// Sentinel Pro waitlist: full form on the home page and a compact form in the result card.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});

  function submit(payload) {
    return S.postJSON("/api/waitlist", payload).then(function (res) {
      if (!res.ok || !res.body || !res.body.ok) throw new Error((res.body && res.body.error) || "Could not join the waitlist. Try again.");
      S.track("waitlist_joined", { source: payload.source, role: payload.role });
    });
  }

  /** Full form (home page section). */
  function bindFull(form) {
    if (!form) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = form.querySelector("[data-status]");
      var btn = form.querySelector("button[type=submit]");
      var email = (form.querySelector("[name=email]").value || "").trim();
      if (!email || email.indexOf("@") < 1) { status.textContent = "Enter a valid email."; return; }
      if (!form.querySelector("[name=consent]").checked) { status.textContent = "Tick the box to agree to be emailed."; return; }
      var interests = Array.prototype.map.call(form.querySelectorAll("[name=interests]:checked"), function (i) { return i.value; });
      btn.disabled = true;
      btn.textContent = "Joining…";
      status.textContent = "";
      submit({
        email: email,
        role: form.querySelector("[name=role]").value,
        interests: interests,
        site_url: (form.querySelector("[name=site_url]").value || "").trim(),
        consent: true,
        source: "waitlist_page",
        website: form.querySelector("[name=website]").value || ""
      }).then(function () {
        form.classList.add("hidden");
        var ok = S.$("waitlistDone");
        if (ok) ok.classList.remove("hidden");
      }).catch(function (err) {
        status.textContent = err.message;
        btn.disabled = false;
        btn.textContent = "Join the waitlist";
      });
    });
  }

  /** Compact form markup for the result card. */
  function compactHtml() {
    return '<form id="waitlistMini" class="mt-4 p-4 rounded-2xl bg-white/5 border border-white/10 text-sm" novalidate>' +
      '<p class="text-white font-medium mb-1">Want fixes and alerts done for you?</p>' +
      '<p class="text-slate-400 mb-3">Sentinel Pro is in design: scheduled checks, change alerts, client-ready reports and unlimited AI fix plans.</p>' +
      '<input type="text" name="website" tabindex="-1" autocomplete="off" class="hidden" aria-hidden="true" />' +
      '<div class="flex flex-col sm:flex-row gap-2"><label class="sr-only" for="wlMiniEmail">Your email</label>' +
      '<input id="wlMiniEmail" name="email" type="email" placeholder="you@company.com" class="flex-1 px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm" />' +
      '<button type="submit" class="px-4 py-2 rounded-xl bg-white text-ink font-bold text-sm">Join the waitlist</button></div>' +
      '<label class="flex items-start gap-2 mt-3 text-xs text-slate-400 cursor-pointer"><input type="checkbox" name="consent" class="mt-0.5 rounded border-white/20 bg-white/5 text-teal" />' +
      '<span>I agree to be emailed about Sentinel Pro. Unsubscribe any time. <a class="underline" href="/privacy">Privacy</a></span></label>' +
      '<p data-status class="text-xs text-slate-400 mt-2" role="status"></p></form>';
  }

  function bindCompact(form, ctx) {
    if (!form) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = form.querySelector("[data-status]");
      var email = (form.querySelector("[name=email]").value || "").trim();
      if (!email || email.indexOf("@") < 1) { status.textContent = "Enter a valid email."; return; }
      if (!form.querySelector("[name=consent]").checked) { status.textContent = "Tick the box to agree to be emailed."; return; }
      var btn = form.querySelector("button[type=submit]");
      btn.disabled = true;
      submit({
        email: email, role: "other", interests: ["ai_fixes", "monitoring"], site_url: (ctx && ctx.site) || "",
        consent: true, source: "result_card", website: form.querySelector("[name=website]").value || ""
      }).then(function () {
        form.innerHTML = '<p class="text-emerald-200">You’re on the list. Thanks!</p>';
      }).catch(function (err) {
        status.textContent = err.message;
        btn.disabled = false;
      });
    });
  }

  S.waitlist = { submit: submit, bindFull: bindFull, compactHtml: compactHtml, bindCompact: bindCompact };
})();
