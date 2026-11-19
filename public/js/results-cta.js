// "Need a hand?" card under the result: book a call, send a message, join the waitlist.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var e = S.esc;

  var COPY = {
    vulnerable: ["Your site needs attention", "I help teams upgrade PHP and harden apps after critical issues.", "Book free emergency review", "Prefer writing first? Describe what you run and I will reply with next steps."],
    hidden: ["Verify it is patched", "I can help confirm the real version and upgrade safely.", "Book a free verification call", "Send the hosting type (cPanel, VPS, managed) and I will point you to where the version lives."],
    safe: ["You look patched", "Want hardening or a second opinion?", "Book a free strategy call", "Ask about headers, TLS, or upgrade paths — no call required."],
    other: ["Still want a review?", "Happy to look at hardening even when PHP is not public.", "Book a free strategy call", "Tell me what stack you use and what you are worried about."]
  };

  function render(section, data, siteForForm) {
    var cfg = S.cfg();
    var c = COPY[data.status] || COPY.other;
    var notes = encodeURIComponent("Sentinel result for " + siteForForm + "\nStatus: " + data.status + "\n" + (data.message || ""));
    var cal = cfg.calUrl + "?notes=" + notes;
    var wa = String(cfg.whatsapp || "").replace(/\D/g, "");
    var waLink = wa.length >= 10
      ? "https://wa.me/" + wa + "?text=" + encodeURIComponent("Hi Alex — Sentinel check for " + siteForForm + " (" + data.status + "). ")
      : "";
    var linkedin = /^https:\/\/([a-z]+\.)?linkedin\.com\/in\/[^/]+/i.test(cfg.linkedin || "") ? cfg.linkedin : "";

    section.innerHTML =
      '<div class="glass-strong rounded-3xl p-6 space-y-5">' +
      '<div class="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3"><div>' +
      '<h3 class="font-semibold text-white text-lg">Alex Mochu</h3>' +
      '<p class="text-sm text-slate-400">Senior Fullstack Engineer · Nairobi · PHP &amp; frameworks</p>' +
      '<p class="text-sm text-slate-300 mt-2 max-w-md">Clear next steps for complex technical problems. Message first if you prefer — booking is optional.</p></div>' +
      '<div class="flex flex-wrap gap-2 shrink-0">' +
      (waLink ? '<a href="' + e(waLink) + '" target="_blank" rel="noopener" class="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 transition">WhatsApp</a>' : "") +
      (linkedin ? '<a href="' + e(linkedin) + '" target="_blank" rel="noopener" class="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium border border-white/10 text-slate-300 hover:text-white hover:bg-white/5 transition">LinkedIn</a>' : "") +
      "</div></div>" +
      '<div class="border-t border-white/10 pt-5"><h4 class="font-semibold text-white mb-1">' + e(c[0]) + '</h4><p class="text-sm text-slate-400 mb-4">' + e(c[1]) + "</p>" +
      '<div class="flex flex-col sm:flex-row gap-2 mb-5">' +
      '<a id="bookBtn" href="' + e(cal) + '" target="_blank" rel="noopener" class="inline-flex justify-center items-center gap-2 px-5 py-3 bg-teal text-ink font-bold rounded-xl hover:brightness-110 transition">' + e(c[2]) + "</a>" +
      '<button type="button" id="toggleMsgBtn" class="inline-flex justify-center items-center gap-2 px-5 py-3 rounded-xl border border-white/15 text-white font-medium hover:bg-white/5 transition">Send a message instead</button></div>' +
      '<div id="msgPanel" class="hidden"><p class="text-sm text-slate-400 mb-3">' + e(c[3]) + "</p>" +
      '<form id="msgForm" class="space-y-3" novalidate>' +
      '<input type="text" name="website" id="msgHp" tabindex="-1" autocomplete="off" class="hidden" aria-hidden="true" />' +
      '<div class="grid sm:grid-cols-2 gap-3">' +
      '<div><label class="block text-xs text-slate-500 mb-1" for="msgEmail">Email</label><input id="msgEmail" type="email" required placeholder="you@company.com" class="' + S.INPUT_CLASS + '" /></div>' +
      '<div><label class="block text-xs text-slate-500 mb-1" for="msgPhone">Phone / WhatsApp <span class="text-slate-600">(optional)</span></label><input id="msgPhone" type="tel" inputmode="tel" placeholder="+254 7…" class="' + S.INPUT_CLASS + '" /></div></div>' +
      '<div><label class="block text-xs text-slate-500 mb-1" for="msgSite">Site (optional)</label><input id="msgSite" type="url" value="' + e(siteForForm) + '" placeholder="https://…" class="' + S.INPUT_CLASS + '" /></div>' +
      '<div><label class="block text-xs text-slate-500 mb-1" for="msgBody">Message</label><textarea id="msgBody" required rows="3" placeholder="What are you running, and what do you need help with?" class="' + S.INPUT_CLASS + ' resize-y"></textarea></div>' +
      '<label class="flex items-start gap-2 text-sm text-slate-300 cursor-pointer select-none"><input id="msgWantsCall" type="checkbox" class="mt-1 rounded border-white/20 bg-white/5 text-teal focus:ring-teal" /><span>I would also like a free 15‑min call <span class="text-slate-500">(optional)</span></span></label>' +
      '<div class="flex flex-wrap items-center gap-3 pt-1"><button type="submit" id="msgSubmit" class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white text-ink font-bold text-sm hover:bg-slate-100 transition">Send message</button>' +
      '<span id="msgStatusLine" class="text-sm text-slate-500" role="status"></span></div></form>' +
      '<div id="msgSuccess" class="hidden mt-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-200"><p class="font-medium text-emerald-100 mb-1">Message sent</p><p>Thanks — I will reply by email. No account needed.</p>' +
      '<p id="msgSuccessCall" class="hidden mt-2">You asked for a call — you can still <a href="' + e(cal) + '" target="_blank" rel="noopener" class="underline text-teal">pick a slot here</a>.</p></div></div>' +
      S.waitlist.compactHtml() + "</div></div>";

    section.classList.remove("hidden");
    S.waitlist.bindCompact(section.querySelector("#waitlistMini"), { site: siteForForm });

    var toggle = S.$("toggleMsgBtn"), panel = S.$("msgPanel");
    toggle.addEventListener("click", function () {
      panel.classList.toggle("hidden");
      var open = !panel.classList.contains("hidden");
      toggle.textContent = open ? "Hide message form" : "Send a message instead";
      if (open) S.$("msgEmail").focus();
    });

    S.$("msgForm").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var email = (S.$("msgEmail").value || "").trim();
      var message = (S.$("msgBody").value || "").trim();
      var line = S.$("msgStatusLine"), btn = S.$("msgSubmit");
      if (!email || email.indexOf("@") < 1) { line.textContent = "Enter a valid email."; return; }
      if (message.length < 5) { line.textContent = "Write a short message first."; return; }
      var wants = !!S.$("msgWantsCall").checked;
      btn.disabled = true; btn.textContent = "Sending…"; line.textContent = "";
      S.contact.send({
        email: email, message: message, site_url: S.$("msgSite").value || siteForForm, phone: S.$("msgPhone").value || "",
        scan_status: data.status || "", wants_call: wants, source: "checker_result", website: S.$("msgHp").value || ""
      }).then(function () {
        S.$("msgForm").classList.add("hidden");
        S.$("msgSuccess").classList.remove("hidden");
        if (wants) S.$("msgSuccessCall").classList.remove("hidden");
      }).catch(function (err) {
        line.textContent = err.message; btn.disabled = false; btn.textContent = "Send message";
      });
    });
    S.track("cta_shown", { status: data.status });
  }

  S.resultCta = { render: render };
})();
