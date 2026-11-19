// Home page boot. Scripts load with defer, in the order listed in index.html.
(function () {
  var S = window.Sentinel;
  S.checker.init();
  S.stats.init();
  S.waitlist.bindFull(S.$("waitlistForm"));
})();
