/* ---------- animated network background ---------- */
(function () {
  const canvas = document.getElementById('bg');
  const ctx = canvas.getContext('2d');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let w, h, dpr, nodes = [];
  const mouse = { x: -9999, y: -9999 };
  const LINK = 140;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = canvas.width = innerWidth * dpr;
    h = canvas.height = innerHeight * dpr;
    canvas.style.width = innerWidth + 'px';
    canvas.style.height = innerHeight + 'px';
    const count = Math.round(Math.min(110, (innerWidth * innerHeight) / 14000));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - .5) * .35 * dpr, vy: (Math.random() - .5) * .35 * dpr,
      r: (Math.random() * 1.4 + .6) * dpr, hue: Math.random() < .5 ? 190 : 255,
    }));
  }

  function frame() {
    ctx.clearRect(0, 0, w, h);
    const link = LINK * dpr;
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > w) n.vx *= -1;
      if (n.y < 0 || n.y > h) n.vy *= -1;
      const dx = mouse.x - n.x, dy = mouse.y - n.y, d = Math.hypot(dx, dy);
      if (d < 180 * dpr) { n.x -= dx * .0015; n.y -= dy * .0015; }  // gentle pull toward the cursor
    }
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < link) {
          ctx.strokeStyle = `hsla(${a.hue},90%,70%,${(1 - d / link) * .28})`;
          ctx.lineWidth = dpr * .8;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
      const dm = Math.hypot(a.x - mouse.x, a.y - mouse.y);
      if (dm < 190 * dpr) {
        ctx.strokeStyle = `rgba(77,240,255,${(1 - dm / (190 * dpr)) * .55})`;
        ctx.lineWidth = dpr;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
      }
      ctx.fillStyle = `hsla(${a.hue},95%,75%,.85)`;
      ctx.shadowColor = `hsla(${a.hue},95%,65%,.9)`; ctx.shadowBlur = 8 * dpr;
      ctx.beginPath(); ctx.arc(a.x, a.y, a.r, 0, 6.283); ctx.fill();
      ctx.shadowBlur = 0;
    }
    if (!reduce) requestAnimationFrame(frame);
  }

  addEventListener('resize', resize);
  addEventListener('pointermove', e => { mouse.x = e.clientX * dpr; mouse.y = e.clientY * dpr; });
  addEventListener('pointerleave', () => { mouse.x = mouse.y = -9999; });
  resize(); frame();
})();

/* ---------- scanner UI ---------- */
(function () {
  const $ = id => document.getElementById(id);
  const input = $('input'), scanBtn = $('scan'), errorEl = $('error'), result = $('result');
  const CIRC = 540.4;

  const COPY = {
    low:    ['LOW RISK',    'Nothing alarming found.',        'No strong phishing signs were detected. Stay careful with anything unexpected that asks for money, passwords or codes.'],
    medium: ['MEDIUM RISK', 'Some warning signs. Be careful.', 'A few things look off. Do not click links or open attachments until you have checked with the sender another way.'],
    high:   ['HIGH RISK',   'This looks like phishing.',      'Several strong warning signs were found. Do not click links, open attachments or reply with any personal details.'],
  };

  document.querySelectorAll('[data-sample]').forEach(btn => btn.addEventListener('click', () => {
    input.value = window.SAMPLES[btn.dataset.sample] || '';
    input.focus();
  }));
  $('clear').addEventListener('click', () => {
    input.value = ''; result.hidden = true; errorEl.hidden = true; document.body.removeAttribute('data-level'); input.focus();
  });
  input.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run(); });
  scanBtn.addEventListener('click', run);

  async function run() {
    const text = input.value;
    errorEl.hidden = true;
    if (!text.trim()) { showError('Please paste a message or link to check.'); return; }
    scanBtn.classList.add('busy'); scanBtn.disabled = true;
    try {
      const [res] = await Promise.all([
        fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) }),
        new Promise(r => setTimeout(r, 650)),   // brief pause so the scan feels deliberate
      ]);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Something went wrong.');
      render(data);
    } catch (err) {
      showError(err.message || 'Could not reach the server.');
    } finally {
      scanBtn.classList.remove('busy'); scanBtn.disabled = false;
    }
  }

  function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }

  function render(d) {
    const [badge, headline, summary] = COPY[d.level];
    document.body.dataset.level = d.level;
    $('badge').textContent = badge;
    $('headline').textContent = headline;
    $('summary').textContent = summary;

    result.hidden = false;
    result.style.animation = 'none'; void result.offsetWidth; result.style.animation = '';

    // gauge + counter
    const arc = $('arc');
    arc.style.strokeDashoffset = CIRC;
    requestAnimationFrame(() => requestAnimationFrame(() => { arc.style.strokeDashoffset = CIRC * (1 - d.score / 100); }));
    countTo($('score'), d.score);

    // meters
    $('ruleVal').textContent = d.rule_score + ' / 100';
    $('ruleBar').style.width = '0';
    const mlPct = d.ml_probability == null ? null : Math.round(d.ml_probability * 100);
    $('mlVal').textContent = mlPct == null ? 'unavailable' : mlPct + '%';
    $('mlBar').style.width = '0';
    setTimeout(() => { $('ruleBar').style.width = d.rule_score + '%'; $('mlBar').style.width = (mlPct || 0) + '%'; }, 80);

    // model signals
    const sigBox = $('signalsBox'), sigEl = $('signals');
    sigEl.replaceChildren();
    (d.ml_signals || []).forEach(s => { const el = document.createElement('span'); el.textContent = s; sigEl.appendChild(el); });
    sigBox.hidden = !(d.ml_signals && d.ml_signals.length);

    // findings
    const list = $('findings');
    list.replaceChildren();
    if (!d.findings.length) {
      const li = document.createElement('div'); li.className = 'clean';
      li.textContent = 'No warning signs were found by the rules engine.';
      list.appendChild(li);
    }
    d.findings.forEach((f, i) => {
      const li = document.createElement('li');
      li.style.animationDelay = (0.08 * i + 0.2) + 's';
      const pts = document.createElement('span');
      pts.className = 'pts ' + (f.points >= 25 ? 'hi' : f.points >= 12 ? 'mid' : 'lo');
      pts.textContent = '+' + f.points;
      const body = document.createElement('div');
      const h = document.createElement('h4'); h.textContent = f.title; body.appendChild(h);
      if (f.evidence) { const ev = document.createElement('span'); ev.className = 'ev'; ev.textContent = f.evidence; body.appendChild(ev); }
      const tip = document.createElement('span'); tip.className = 'tip'; tip.textContent = f.advice; body.appendChild(tip);
      li.append(pts, body); list.appendChild(li);
    });

    // urls
    const uBox = $('urlsBox'), uList = $('urls');
    uList.replaceChildren();
    (d.urls || []).forEach(u => { const li = document.createElement('li'); li.textContent = u; uList.appendChild(li); });
    uBox.hidden = !(d.urls && d.urls.length);

    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function countTo(el, target) {
    const t0 = performance.now(), dur = 1100;
    (function step(t) {
      const p = Math.min(1, (t - t0) / dur);
      el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(step);
    })(t0);
  }
})();
