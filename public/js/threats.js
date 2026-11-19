(function () {
  var DATA = null;
  var activeCategory = "all";
  var activeSeverity = "all";
  var searchQ = "";
  var sortMode = "date-desc";

  var CATEGORY_LABELS = {
    all: "All",
    runtime_language: "Runtime / language",
    framework_cms: "Framework / CMS",
    enterprise_software: "Enterprise software",
    company_breach: "Company breach",
    supply_chain: "Supply chain",
    ai_agent_attacks: "AI agent attacks",
    ai_product_incident: "AI product incident",
    infrastructure_pki: "Infrastructure / PKI"
  };

  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, research: 3 };

  var categoryFilters = document.getElementById("categoryFilters");
  var severityFilters = document.getElementById("severityFilters");
  var eventList = document.getElementById("eventList");
  var emptyState = document.getElementById("emptyState");
  var searchInput = document.getElementById("searchInput");
  var sortSelect = document.getElementById("sortSelect");
  var filterPanel = document.getElementById("filterPanel");
  var filterToggle = document.getElementById("filterToggle");
  var filterChevron = document.getElementById("filterChevron");
  var filterBadge = document.getElementById("filterBadge");

  function setFilterOpen(open) {
    if (open) {
      filterPanel.classList.remove("hidden");
      filterToggle.setAttribute("aria-expanded", "true");
      filterChevron.style.transform = "rotate(180deg)";
    } else {
      filterPanel.classList.add("hidden");
      filterToggle.setAttribute("aria-expanded", "false");
      filterChevron.style.transform = "";
    }
  }

  filterToggle.addEventListener("click", function () {
    setFilterOpen(filterPanel.classList.contains("hidden"));
  });

  var scrollCollapseTimer = null;
  window.addEventListener(
    "scroll",
    function () {
      if (filterPanel.classList.contains("hidden")) return;
      if (scrollCollapseTimer) return;
      scrollCollapseTimer = setTimeout(function () {
        scrollCollapseTimer = null;
        if (window.scrollY > 120) setFilterOpen(false);
      }, 120);
    },
    { passive: true }
  );

  fetch("/data/threats-2026.json")
    .then(function (r) {
      if (!r.ok) throw new Error("Failed to load threats data");
      return r.json();
    })
    .then(function (json) {
      DATA = json;
      buildFilterButtons();
      updateStats();
      render();
    })
    .catch(function () {
      eventList.innerHTML =
        '<div class="glass rounded-3xl p-8 text-center text-rose-300">Could not load threat data. Ensure threats-2026.json is in the public folder.</div>';
    });

  function buildFilterButtons() {
    var cats = ["all"].concat(Object.keys(CATEGORY_LABELS).filter(function (k) { return k !== "all"; }));
    categoryFilters.innerHTML = cats.map(function (c) {
      return (
        '<button type="button" data-cat="' + c + '" class="filter-btn px-3 py-1.5 rounded-full text-xs border border-white/15 text-slate-300 hover:border-teal/40 transition' +
        (c === "all" ? " active" : "") + '">' +
        (CATEGORY_LABELS[c] || c) +
        "</button>"
      );
    }).join("");

    var sevs = ["all", "critical", "high", "medium", "research"];
    severityFilters.innerHTML = sevs.map(function (s) {
      return (
        '<button type="button" data-sev="' + s + '" class="filter-btn px-3 py-1.5 rounded-full text-xs border border-white/15 text-slate-300 hover:border-teal/40 transition' +
        (s === "all" ? " active" : "") + '">' +
        (s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)) +
        "</button>"
      );
    }).join("");

    categoryFilters.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-cat]");
      if (!btn) return;
      activeCategory = btn.getAttribute("data-cat");
      categoryFilters.querySelectorAll(".filter-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-cat") === activeCategory);
      });
      render();
    });

    severityFilters.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-sev]");
      if (!btn) return;
      activeSeverity = btn.getAttribute("data-sev");
      severityFilters.querySelectorAll(".filter-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-sev") === activeSeverity);
      });
      render();
    });
  }

  searchInput.addEventListener("input", function () {
    searchQ = (searchInput.value || "").trim().toLowerCase();
    render();
  });

  sortSelect.addEventListener("change", function () {
    sortMode = sortSelect.value;
    render();
  });

  function resetAllFilters() {
    activeCategory = "all";
    activeSeverity = "all";
    searchQ = "";
    searchInput.value = "";
    sortMode = "date-desc";
    sortSelect.value = "date-desc";
    categoryFilters.querySelectorAll(".filter-btn").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-cat") === "all");
    });
    severityFilters.querySelectorAll(".filter-btn").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-sev") === "all");
    });
    render();
  }

  document.getElementById("resetFilters").addEventListener("click", resetAllFilters);
  document.getElementById("resetFiltersInline").addEventListener("click", resetAllFilters);

  function updateFilterBadge() {
    var n = 0;
    if (activeCategory !== "all") n++;
    if (activeSeverity !== "all") n++;
    if (searchQ) n++;
    if (n > 0) {
      filterBadge.textContent = String(n);
      filterBadge.classList.remove("hidden");
      filterBadge.classList.add("inline-flex");
    } else {
      filterBadge.classList.add("hidden");
      filterBadge.classList.remove("inline-flex");
    }
  }

  function updateStats() {
    if (!DATA || !DATA.events) return;
    var events = DATA.events;
    var critical = events.filter(function (e) { return e.severity === "critical"; }).length;
    var withCve = events.filter(function (e) { return e.cves && e.cves.length; }).length;
    var wild = events.filter(function (e) { return e.exploitation && e.exploitation.in_the_wild; }).length;
    document.getElementById("statTotal").textContent = events.length;
    document.getElementById("statCritical").textContent = critical;
    document.getElementById("statCves").textContent = withCve;
    document.getElementById("statWild").textContent = wild;
  }

  function filteredEvents() {
    if (!DATA || !DATA.events) return [];
    var list = DATA.events.slice();

    if (activeCategory !== "all") {
      list = list.filter(function (e) { return e.category === activeCategory; });
    }
    if (activeSeverity !== "all") {
      list = list.filter(function (e) { return e.severity === activeSeverity; });
    }
    if (searchQ) {
      list = list.filter(function (e) {
        var blob = [
          e.title || "",
          e.subtitle || "",
          e.summary || "",
          (e.cves || []).join(" "),
          (e.tags || []).join(" "),
          JSON.stringify(e.affected || {})
        ].join(" ").toLowerCase();
        return blob.indexOf(searchQ) !== -1;
      });
    }

    if (sortMode === "date-asc") {
      list.sort(function (a, b) { return (a.date || "").localeCompare(b.date || ""); });
    } else if (sortMode === "severity") {
      list.sort(function (a, b) {
        var sa = SEVERITY_ORDER[a.severity] != null ? SEVERITY_ORDER[a.severity] : 9;
        var sb = SEVERITY_ORDER[b.severity] != null ? SEVERITY_ORDER[b.severity] : 9;
        if (sa !== sb) return sa - sb;
        return (b.date || "").localeCompare(a.date || "");
      });
    } else {
      list.sort(function (a, b) { return (b.date || "").localeCompare(a.date || ""); });
    }

    return list;
  }

  function sevClass(sev) {
    if (sev === "critical") return "sev-critical";
    if (sev === "high") return "sev-high";
    if (sev === "medium") return "sev-medium";
    return "sev-research";
  }

  function dotClass(sev) {
    if (sev === "critical") return "dot-critical";
    if (sev === "high") return "dot-high";
    return "";
  }

  function escapeHtml(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function render() {
    var list = filteredEvents();
    document.getElementById("visibleCount").textContent = list.length;
    updateFilterBadge();

    if (!list.length) {
      eventList.innerHTML = "";
      emptyState.classList.remove("hidden");
      return;
    }
    emptyState.classList.add("hidden");

    eventList.innerHTML = list.map(function (e) {
      var cves = (e.cves || []).map(function (c) {
        return '<span class="chip chip-cve">' + escapeHtml(c) + "</span>";
      }).join(" ");

      var tags = (e.tags || []).slice(0, 6).map(function (t) {
        return '<span class="chip">' + escapeHtml(t) + "</span>";
      }).join(" ");

      var fixed = "";
      if (e.fixed_versions && e.fixed_versions.length) {
        fixed =
          '<p class="text-xs text-slate-400 mt-2"><span class="text-emerald-300 font-medium">Fixed in:</span> ' +
          escapeHtml(e.fixed_versions.join(", ")) +
          "</p>";
      }

      var wild = e.exploitation && e.exploitation.in_the_wild
        ? '<span class="chip" style="color:#fda4af;border-color:rgba(244,63,94,0.35)">In the wild</span>'
        : "";

      var products = "";
      if (e.affected && e.affected.products && e.affected.products.length) {
        products =
          '<p class="text-xs text-slate-400 mt-1"><span class="text-slate-300">Affects:</span> ' +
          escapeHtml(e.affected.products.slice(0, 5).join(", ")) +
          (e.affected.products.length > 5 ? "…" : "") +
          "</p>";
      }

      var scale = "";
      if (e.affected && e.affected.scale) {
        scale =
          '<p class="text-xs text-slate-400"><span class="text-slate-300">Scale:</span> ' +
          escapeHtml(String(e.affected.scale)) +
          "</p>";
      }

      var relevance = e.sentinel_relevance
        ? '<div class="mt-3 p-3 rounded-xl bg-teal/5 border border-teal/20 text-xs text-slate-300"><span class="text-teal font-medium">Sentinel note:</span> ' +
          escapeHtml(e.sentinel_relevance) +
          "</div>"
        : "";

      var sources = "";
      if (e.sources && e.sources.length) {
        sources =
          '<div class="mt-3 flex flex-wrap gap-2">' +
          e.sources.slice(0, 3).map(function (u, i) {
            return (
              '<a href="' + escapeHtml(/^https:\/\//i.test(u) ? u : "#") + '" target="_blank" rel="noopener noreferrer" class="text-[11px] text-teal/80 hover:text-teal underline">' +
              "Source " + (i + 1) +
              "</a>"
            );
          }).join("") +
          "</div>";
      }

      return (
        '<article class="relative md:pl-12">' +
        '<div class="hidden md:flex absolute left-0 top-6 items-center justify-center w-8">' +
        '<span class="dot ' + dotClass(e.severity) + '"></span></div>' +
        '<div class="glass-strong rounded-3xl p-5 lift">' +
        '<div class="flex flex-wrap items-center gap-2 mb-2">' +
        '<span class="px-2 py-0.5 rounded-lg text-[11px] font-semibold border ' + sevClass(e.severity) + '">' +
        escapeHtml((e.severity || "info").toUpperCase()) +
        "</span>" +
        '<span class="chip">' + escapeHtml(CATEGORY_LABELS[e.category] || e.category) + "</span>" +
        wild +
        (e.cvss != null ? '<span class="chip">CVSS ' + escapeHtml(String(e.cvss)) + "</span>" : "") +
        "</div>" +
        '<p class="text-[11px] text-slate-500 mb-1">' + escapeHtml(e.date_label || e.date) + "</p>" +
        '<h2 class="font-display text-lg sm:text-xl text-white mb-1">' + escapeHtml(e.title) + "</h2>" +
        (e.subtitle ? '<p class="text-sm text-teal/90 mb-2">' + escapeHtml(e.subtitle) + "</p>" : "") +
        '<p class="text-sm text-slate-300 leading-relaxed">' + escapeHtml(e.summary) + "</p>" +
        (e.impact ? '<p class="text-sm text-slate-400 mt-2"><span class="text-slate-200 font-medium">Impact:</span> ' + escapeHtml(e.impact) + "</p>" : "") +
        products +
        scale +
        fixed +
        '<div class="mt-3 flex flex-wrap gap-1.5">' + cves + tags + "</div>" +
        relevance +
        sources +
        "</div></article>"
      );
    }).join("");
  }
})();
