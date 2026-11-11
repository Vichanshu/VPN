(() => {
  const STORE = "vpn-presentation-annotations-v1";
  const slides = [...document.querySelectorAll(".slide")];
  const stage = document.getElementById("stage");
  const ink = document.getElementById("ink");
  const ctx = ink.getContext("2d");
  const toc = document.getElementById("toc");
  const notesPanel = document.getElementById("notes");
  const noteBox = document.getElementById("noteBox");
  const counter = document.getElementById("counter");
  const overview = document.getElementById("overview");
  let current = 0;
  let tool = null; // null | pen | highlight | text | erase
  let data = { notes: {}, strokes: {} };
  try { data = { notes: {}, strokes: {}, ...JSON.parse(localStorage.getItem(STORE) || "{}") }; } catch { /* storage unavailable */ }
  const save = () => { try { localStorage.setItem(STORE, JSON.stringify(data)); } catch { /* ignore */ } };

  // table of contents + overview built from the slides themselves
  let lastPart = "";
  slides.forEach((slide, index) => {
    const part = slide.dataset.part || "";
    const title = slide.dataset.title || `Slide ${index + 1}`;
    slide.insertAdjacentHTML("beforeend", `<span class="pageno">${index + 1} / ${slides.length}</span>`);
    if (part) slide.insertAdjacentHTML("afterbegin", `<span class="part-tag">${part}</span>`);
    if (part !== lastPart) { toc.insertAdjacentHTML("beforeend", `<div class="part">${part || "&nbsp;"}</div>`); lastPart = part; }
    toc.insertAdjacentHTML("beforeend", `<a href="#${index + 1}" data-i="${index}">${index + 1}. ${title}</a>`);
    overview.insertAdjacentHTML("beforeend", `<button data-i="${index}"><b>${index + 1} · ${part}</b>${title}</button>`);
  });

  function fit() {
    const box = document.getElementById("viewport").getBoundingClientRect();
    const left = toc.classList.contains("open") ? 250 : 0;
    const right = notesPanel.classList.contains("open") ? 300 : 0;
    const scale = Math.min((box.width - left - right - 24) / 1280, (box.height - 24) / 720);
    stage.style.transform = `translate(${(left - right) / 2}px, 0) scale(${scale})`;
  }

  function redraw() {
    ctx.clearRect(0, 0, 1280, 720);
    for (const item of data.strokes[current] || []) {
      if (item.type === "text") {
        ctx.globalAlpha = 1; ctx.fillStyle = "#1f3a8a"; ctx.font = "22px system-ui, sans-serif";
        ctx.fillText(item.text, item.x, item.y);
      } else {
        ctx.globalAlpha = item.type === "highlight" ? 0.3 : 1;
        ctx.strokeStyle = item.type === "highlight" ? "#f2c200" : "#1f3a8a";
        ctx.lineWidth = item.type === "highlight" ? 20 : 3;
        ctx.lineCap = "round"; ctx.lineJoin = "round";
        ctx.beginPath();
        item.points.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
        if (item.points.length === 1) ctx.lineTo(item.points[0][0] + 0.1, item.points[0][1]);
        ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;
  }

  function go(index) {
    current = Math.max(0, Math.min(slides.length - 1, index));
    slides.forEach((slide, i) => slide.classList.toggle("active", i === current));
    counter.textContent = `${current + 1} / ${slides.length}`;
    toc.querySelectorAll("a").forEach((a) => a.classList.toggle("cur", Number(a.dataset.i) === current));
    noteBox.value = data.notes[current] || "";
    history.replaceState(null, "", `#${current + 1}`);
    redraw();
  }

  noteBox.addEventListener("input", () => { data.notes[current] = noteBox.value; save(); });

  const point = (event) => {
    const rect = ink.getBoundingClientRect();
    return [Math.round(((event.clientX - rect.left) / rect.width) * 1280), Math.round(((event.clientY - rect.top) / rect.height) * 720)];
  };
  let active = null;
  ink.addEventListener("pointerdown", (event) => {
    if (!tool) return;
    const [x, y] = point(event);
    const list = (data.strokes[current] ||= []);
    if (tool === "text") {
      const text = window.prompt("Annotation text");
      if (text) { list.push({ type: "text", x, y, text }); save(); redraw(); }
      return;
    }
    if (tool === "erase") {
      const hit = list.findIndex((item) => item.type === "text" ? Math.abs(item.x - x) < 120 && Math.abs(item.y - y) < 20 : item.points.some(([px, py]) => Math.hypot(px - x, py - y) < 16));
      if (hit >= 0) { list.splice(hit, 1); save(); redraw(); }
      return;
    }
    active = { type: tool, points: [[x, y]] };
    list.push(active);
    ink.setPointerCapture(event.pointerId);
  });
  ink.addEventListener("pointermove", (event) => {
    if (!active) return;
    active.points.push(point(event));
    redraw();
  });
  const endStroke = () => { if (active) { active = null; save(); } };
  ink.addEventListener("pointerup", endStroke);
  ink.addEventListener("pointercancel", endStroke);

  function setTool(next) {
    tool = tool === next ? null : next;
    ink.classList.toggle("drawing", Boolean(tool));
    document.querySelectorAll("[data-tool]").forEach((button) => button.classList.toggle("on", button.dataset.tool === tool));
  }
  document.querySelectorAll("[data-tool]").forEach((button) => button.addEventListener("click", () => setTool(button.dataset.tool)));
  document.getElementById("undo").addEventListener("click", () => { (data.strokes[current] || []).pop(); save(); redraw(); });
  document.getElementById("clear").addEventListener("click", () => { if (confirm("Remove all drawings on this slide?")) { data.strokes[current] = []; save(); redraw(); } });
  document.getElementById("prev").addEventListener("click", () => go(current - 1));
  document.getElementById("next").addEventListener("click", () => go(current + 1));
  document.getElementById("btnToc").addEventListener("click", () => { toc.classList.toggle("open"); fit(); });
  document.getElementById("btnNotes").addEventListener("click", () => { notesPanel.classList.toggle("open"); fit(); });
  document.getElementById("btnOverview").addEventListener("click", () => overview.classList.toggle("open"));
  document.getElementById("btnPrint").addEventListener("click", () => window.print());
  toc.addEventListener("click", (event) => { const a = event.target.closest("a"); if (a) { event.preventDefault(); go(Number(a.dataset.i)); } });
  overview.addEventListener("click", (event) => { const b = event.target.closest("button"); if (b) { overview.classList.remove("open"); go(Number(b.dataset.i)); } });

  document.getElementById("export").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "presentation-annotations.json" });
    link.click(); URL.revokeObjectURL(link.href);
  });
  document.getElementById("import").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try { data = { notes: {}, strokes: {}, ...JSON.parse(await file.text()) }; save(); go(current); } catch { alert("That file is not valid annotations JSON."); }
    event.target.value = "";
  });

  document.addEventListener("keydown", (event) => {
    if (event.target.tagName === "TEXTAREA") return;
    if (event.key === "ArrowRight" || event.key === "PageDown" || event.key === " ") { event.preventDefault(); go(current + 1); }
    else if (event.key === "ArrowLeft" || event.key === "PageUp") { go(current - 1); }
    else if (event.key === "Home") go(0);
    else if (event.key === "End") go(slides.length - 1);
    else if (event.key === "n") { notesPanel.classList.toggle("open"); fit(); }
    else if (event.key === "o") overview.classList.toggle("open");
    else if (event.key === "d") setTool("pen");
    else if (event.key === "h") setTool("highlight");
    else if (event.key === "Escape") { setTool(tool); overview.classList.remove("open"); }
  });

  window.addEventListener("resize", fit);
  window.addEventListener("hashchange", () => { const n = Number(location.hash.slice(1)) - 1; if (Number.isFinite(n) && n !== current) go(n); });
  const start = Number((location.hash || "#1").slice(1)) - 1;
  fit();
  go(Number.isFinite(start) ? start : 0);
})();
