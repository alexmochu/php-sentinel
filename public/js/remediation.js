// AI fix plan (beta). Sends only whitelisted scan findings. Falls back to built-in rules on the server.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var h = S.h;

  var STACKS = [
    ["unknown", "I’m not sure"],
    ["cpanel", "Shared hosting (cPanel)"],
    ["nginx", "Nginx server"],
    ["apache", "Apache server"],
    ["cloudflare", "Cloudflare in front"],
    ["wordpress", "WordPress"],
    ["laravel", "Laravel"]
  ];

  function findingsOf(data) {
    return {
      status: data.status,
      php_version: data.php_version || null,
      framework: data.framework || null,
      x_powered_by_exposed: !!data.x_powered_by_exposed,
      security_headers: data.security_headers || {},
      tls: data.tls || {}
    };
  }

  function codeBlock(snippet) {
    var pre = h("pre", {}, [h("code", { text: snippet.code })]);
    var btn = h("button", {
      type: "button",
      text: "Copy",
      onclick: function () { S.copy(snippet.code).then(function () { S.toast("Snippet copied"); }); }
    });
    return h("div", { class: "code-block" }, [
      snippet.label ? h("p", { class: "code-label", text: snippet.label }) : null,
      btn,
      pre
    ]);
  }

  var PRIORITY = { high: ["chip-bad", "High"], medium: ["chip-warn", "Medium"], low: ["chip-mute", "Low"] };

  function stepCard(step) {
    var p = PRIORITY[step.priority] || PRIORITY.medium;
    return h("li", { class: "fix-step" }, [
      h("div", { class: "flex flex-wrap items-center gap-2 mb-1" }, [
        h("span", { class: "px-2 py-0.5 rounded-md text-[11px] font-medium " + p[0], text: p[1] + " priority" }),
        h("h5", { class: "text-white font-medium", text: step.title })
      ]),
      h("p", { class: "text-sm text-slate-400 mb-2", text: step.why }),
      h("ol", { class: "list-decimal list-inside text-sm text-slate-300 space-y-1" }, (step.how || []).map(function (line) {
        return h("li", { text: line });
      })),
      step.snippet ? codeBlock(step.snippet) : null
    ]);
  }

  function renderPlan(out, plan) {
    out.textContent = "";
    var steps = h("ol", { class: "space-y-3 mt-3" }, (plan.steps || []).map(stepCard));
    out.appendChild(h("div", { class: "mt-3" }, [
      h("p", { class: "text-sm text-slate-200", text: plan.summary || "" }),
      steps,
      plan.verify && plan.verify.length
        ? h("div", { class: "mt-3 text-sm text-slate-300" }, [
            h("p", { class: "text-white font-medium mb-1", text: "How to check it worked" }),
            h("ul", { class: "list-disc list-inside" }, plan.verify.map(function (v) { return h("li", { text: v }); }))
          ])
        : null,
      plan.notes && plan.notes.length
        ? h("ul", { class: "list-disc list-inside text-xs text-slate-400 mt-3" }, plan.notes.map(function (n) { return h("li", { text: n }); }))
        : null,
      h("p", { class: "text-[11px] text-slate-500 mt-3", text:
        (plan.source === "ai" ? "Written by AI (beta) from your scan findings. " : "Built from Sentinel’s reviewed rules. ") +
        "Review each step and back up before you change anything. Sentinel sees public signals only." })
    ]));
  }

  function mount(container, data) {
    if (!container || data.status === "error" || data.status === undefined) return;
    var select = h("select", { id: "fixStack", class: "rounded-xl bg-black/40 border border-white/10 px-3 py-2 text-sm text-white", "aria-label": "Where is the site hosted?" },
      STACKS.map(function (s) { return h("option", { value: s[0], text: s[1] }); }));
    var out = h("div", { id: "fixOut", "aria-live": "polite" });
    var button = h("button", {
      type: "button", id: "fixBtn", text: "Get fix plan",
      class: "px-4 py-2 rounded-xl bg-teal text-ink font-bold text-sm hover:brightness-110 transition"
    });

    button.addEventListener("click", function () {
      button.disabled = true;
      button.textContent = "Writing your plan…";
      out.textContent = "";
      S.track("fix_plan_requested", { status: data.status, stack: select.value });
      S.postJSON("/api/remediate", { findings: findingsOf(data), stack: select.value }).then(function (res) {
        if (!res.ok || !res.body || !res.body.plan) throw new Error((res.body && res.body.error) || "Could not create a plan. Try again.");
        renderPlan(out, res.body.plan);
        button.textContent = "Update plan";
      }).catch(function (err) {
        out.appendChild(h("p", { class: "text-sm text-rose-300 mt-3", role: "alert", text: err.message }));
        button.textContent = "Try again";
      }).then(function () { button.disabled = false; });
    });

    container.appendChild(h("section", { class: "mt-4 p-4 rounded-2xl bg-indigo-500/10 border border-indigo-400/20", "aria-labelledby": "fixTitle" }, [
      h("div", { class: "flex flex-wrap items-center gap-2 mb-1" }, [
        h("p", { id: "fixTitle", class: "text-white font-medium", text: "Get a fix plan" }),
        h("span", { class: "chip-mute px-2 py-0.5 rounded-md text-[11px]", text: "AI beta" })
      ]),
      h("p", { class: "text-sm text-slate-400 mb-3", text: "Step-by-step changes for your setup. Only the scan findings are used, never your site’s content." }),
      h("div", { class: "flex flex-col sm:flex-row gap-2" }, [select, button]),
      out
    ]));
  }

  S.remediation = { mount: mount };
})();
