// Renders the header, footer and message modal once, so every page stays in sync.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var cfg = S.cfg();
  var page = document.body.getAttribute("data-page") || "";
  var footerNote = document.body.getAttribute("data-footer-note") || "Public signals only. No exploits.";

  var chevron = '<svg class="w-3.5 h-3.5 opacity-70" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>';

  function pill(href, label, key) {
    var active = page === key;
    return '<a href="' + href + '" class="nav-pill' + (active ? " is-active" : "") + '"' + (active ? ' aria-current="page"' : "") + ">" + label + "</a>";
  }

  var header =
    '<a class="skip-link" href="#main">Skip to content</a>' +
    '<header class="sticky top-0 z-50 border-b border-white/5 bg-[#05070f]/80 backdrop-blur-xl">' +
    '<div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between gap-3">' +
    '<a href="/" class="block shrink-0"><p class="font-display text-white leading-none text-xl tracking-tight">Sentinel</p>' +
    '<p class="text-[11px] text-slate-500 mt-1">by Kejani Garage</p></a>' +
    '<div class="flex items-center gap-2 sm:gap-3">' +
    '<nav class="nav-shell" aria-label="Primary">' + pill("/", "Checker", "checker") + pill("/threats", "Threats", "threats") + "</nav>" +
    '<div class="talk-wrap">' +
    '<button type="button" id="talkBtn" class="nav-cta" aria-expanded="false" aria-haspopup="true" aria-controls="talkMenu">Talk to us ' + chevron + "</button>" +
    '<div id="talkMenu" class="talk-menu" role="menu">' +
    '<a role="menuitem" class="talk-item" href="' + S.esc(cfg.calUrl) + '" target="_blank" rel="noopener"><span class="talk-icon">📅</span><span><span class="ti-title">Book a free call</span><span class="ti-sub block">15 min · Cal.com</span></span></a>' +
    '<button type="button" role="menuitem" class="talk-item" id="navOpenMsg" data-open-message><span class="talk-icon">✉️</span><span><span class="ti-title">Send a message</span><span class="ti-sub block">Email reply · no account</span></span></button>' +
    '<a role="menuitem" class="talk-item hidden" id="navWhatsApp" href="#" target="_blank" rel="noopener"><span class="talk-icon wa">💬</span><span><span class="ti-title">WhatsApp</span><span class="ti-sub block">Quick chat</span></span></a>' +
    "</div></div>" +
    '<button type="button" id="navToggle" class="nav-mobile-btn" aria-expanded="false" aria-controls="navDrawer" aria-label="Open menu">' +
    '<svg id="navIconOpen" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7h16M4 12h16M4 17h16"/></svg>' +
    '<svg id="navIconClose" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>' +
    "</button></div></div>" +
    '<div id="navDrawer" class="nav-drawer"><div class="max-w-6xl mx-auto px-4 py-3 space-y-1">' +
    '<a href="/"' + (page === "checker" ? ' class="is-active"' : "") + '>Checker <span class="text-xs text-teal">Live</span></a>' +
    '<a href="/threats"' + (page === "threats" ? ' class="is-active"' : "") + '>Threat Timeline <span class="text-xs text-slate-500">2026</span></a>' +
    '<a href="/#waitlist">Sentinel Pro waitlist <span class="text-xs text-slate-500">New</span></a>' +
    '<div class="my-2 border-t border-white/10"></div>' +
    '<a href="' + S.esc(cfg.calUrl) + '" target="_blank" rel="noopener">Book a free call <span class="text-xs text-slate-500">Cal.com</span></a>' +
    '<button type="button" id="navDrawerMsg" data-open-message class="w-full text-left talk-item !px-3 !py-3"><span class="talk-icon">✉️</span><span><span class="ti-title">Send a message</span><span class="ti-sub block">I’ll reply by email</span></span></button>' +
    "</div></div></header>";

  var modal =
    '<div id="msgModal" class="msg-modal-backdrop" aria-hidden="true">' +
    '<div class="msg-modal" role="dialog" aria-modal="true" aria-labelledby="msgModalTitle">' +
    '<div class="flex items-start justify-between gap-3 mb-3"><div>' +
    '<h2 id="msgModalTitle" class="font-display text-xl text-white">Send a message</h2>' +
    '<p class="text-sm text-slate-400 mt-1">Leave your email and a short note. Booking is optional.</p></div>' +
    '<button type="button" id="msgModalClose" class="w-9 h-9 rounded-xl border border-white/10 text-slate-400 hover:text-white hover:bg-white/5" aria-label="Close">×</button></div>' +
    '<form id="globalMsgForm" class="space-y-3" novalidate>' +
    '<input type="text" name="website" id="gMsgHp" tabindex="-1" autocomplete="off" class="hidden" aria-hidden="true" />' +
    '<div><label class="block text-xs text-slate-500 mb-1" for="gMsgEmail">Email</label><input id="gMsgEmail" type="email" required placeholder="you@company.com" class="' + S.INPUT_CLASS + '" /></div>' +
    '<div class="grid sm:grid-cols-2 gap-3">' +
    '<div><label class="block text-xs text-slate-500 mb-1" for="gMsgSite">Site (optional)</label><input id="gMsgSite" type="url" placeholder="https://…" class="' + S.INPUT_CLASS + '" /></div>' +
    '<div><label class="block text-xs text-slate-500 mb-1" for="gMsgPhone">Phone / WhatsApp <span class="text-slate-600">(optional)</span></label><input id="gMsgPhone" type="tel" inputmode="tel" placeholder="+254 7…" class="' + S.INPUT_CLASS + '" /></div></div>' +
    '<div><label class="block text-xs text-slate-500 mb-1" for="gMsgBody">Message</label><textarea id="gMsgBody" required rows="3" placeholder="What do you need help with?" class="' + S.INPUT_CLASS + ' resize-y"></textarea></div>' +
    '<label class="flex items-start gap-2 text-sm text-slate-300 cursor-pointer select-none"><input id="gMsgWantsCall" type="checkbox" class="mt-1 rounded border-white/20 bg-white/5 text-teal focus:ring-teal" /><span>I’d also like a free 15‑min call <span class="text-slate-500">(optional)</span></span></label>' +
    '<p class="text-[11px] text-slate-500">We use your details only to reply. <a class="underline text-slate-400" href="/privacy">Privacy</a></p>' +
    '<div class="flex flex-wrap items-center gap-3 pt-1"><button type="submit" id="gMsgSubmit" class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white text-ink font-bold text-sm hover:bg-slate-100 transition">Send message</button>' +
    '<a href="' + S.esc(cfg.calUrl) + '" target="_blank" rel="noopener" class="text-sm text-teal hover:underline">Or book a call</a></div>' +
    '<p id="gMsgStatus" class="text-sm text-slate-500" role="status"></p></form>' +
    '<div id="gMsgSuccess" class="hidden rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-200"><p class="font-medium text-emerald-100 mb-1">Message sent</p><p>Thanks — I’ll reply by email.</p>' +
    '<p id="gMsgSuccessCall" class="hidden mt-2">You asked for a call — <a href="' + S.esc(cfg.calUrl) + '" target="_blank" rel="noopener" class="underline text-teal">pick a slot here</a>.</p></div>' +
    "</div></div>";

  var footer =
    '<footer class="border-t border-white/5 py-10 text-center text-sm text-slate-500">' +
    '<p>Sentinel · Built by <a href="https://kejanigarage.com" class="text-teal hover:underline">Kejani Garage</a></p>' +
    '<p class="mt-1">' + S.esc(footerNote) + "</p>" +
    '<nav aria-label="Legal" class="mt-4 flex flex-wrap justify-center gap-x-5 gap-y-1">' +
    '<a class="hover:text-slate-300" href="/terms">Terms</a><a class="hover:text-slate-300" href="/privacy">Privacy</a>' +
    '<a class="hover:text-slate-300" href="/abuse">Abuse &amp; removal</a><a class="hover:text-slate-300" href="/#waitlist">Pro waitlist</a>' +
    '<button type="button" id="consentReopen" class="hover:text-slate-300">Cookie choices</button></nav></footer>';

  document.body.insertAdjacentHTML("afterbegin", header);
  document.body.insertAdjacentHTML("beforeend", modal + footer);

  // Mobile drawer
  var toggle = S.$("navToggle"), drawer = S.$("navDrawer"), iconOpen = S.$("navIconOpen"), iconClose = S.$("navIconClose");
  toggle.addEventListener("click", function () {
    var open = drawer.classList.toggle("open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    iconOpen.classList.toggle("hidden", open);
    iconClose.classList.toggle("hidden", !open);
  });

  // Talk menu
  var talkBtn = S.$("talkBtn"), talkMenu = S.$("talkMenu");
  function closeTalk() {
    talkMenu.classList.remove("open");
    talkBtn.setAttribute("aria-expanded", "false");
  }
  S.closeNavMenus = function () { closeTalk(); drawer.classList.remove("open"); };
  talkBtn.addEventListener("click", function (e) {
    e.stopPropagation();
    var open = talkMenu.classList.toggle("open");
    talkBtn.setAttribute("aria-expanded", open ? "true" : "false");
  });
  document.addEventListener("click", function (e) {
    if (!talkMenu.contains(e.target) && e.target !== talkBtn) closeTalk();
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeTalk(); });

  // WhatsApp (hidden until a plausible number is configured)
  var wa = String(cfg.whatsapp || "").replace(/\D/g, "");
  var navWa = S.$("navWhatsApp");
  if (wa.length >= 10) {
    navWa.href = "https://wa.me/" + wa + "?text=" + encodeURIComponent("Hi Alex — from Sentinel. ");
    navWa.classList.remove("hidden");
  }

  S.$("consentReopen").addEventListener("click", function () {
    if (S.analytics && !document.querySelector(".consent-banner")) S.analytics.reopen();
  });
})();
