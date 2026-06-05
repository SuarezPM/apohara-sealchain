// Offline receipt verifier UI. Loads the wasm module and drives it from two
// file inputs + a drop zone. No network calls: the only fetch is the local wasm
// binary, served from the same origin by a static server.

import init, { verify_receipt } from "./pkg/sealchain_wasm.js";

const els = {
  drop: document.getElementById("drop"),
  artifact: document.getElementById("artifact"),
  receipt: document.getElementById("receipt"),
  artifactName: document.getElementById("artifact-name"),
  receiptName: document.getElementById("receipt-name"),
  verify: document.getElementById("verify"),
  results: document.getElementById("results"),
};

let artifactFile = null;
let receiptFile = null;
let ready = false;

// Boot the wasm module (local fetch of the .wasm binary only).
init()
  .then(() => {
    ready = true;
    refreshButton();
  })
  .catch((e) => {
    els.results.innerHTML = `<div class="error">Failed to load the wasm verifier: ${escapeHtml(
      String(e)
    )}</div>`;
  });

function refreshButton() {
  els.verify.disabled = !(ready && artifactFile && receiptFile);
}

function setArtifact(file) {
  artifactFile = file;
  els.artifactName.textContent = file ? file.name : "";
  refreshButton();
}

function setReceipt(file) {
  receiptFile = file;
  els.receiptName.textContent = file ? file.name : "";
  refreshButton();
}

els.artifact.addEventListener("change", (e) => setArtifact(e.target.files[0] || null));
els.receipt.addEventListener("change", (e) => setReceipt(e.target.files[0] || null));

// Drag-and-drop: route a dropped .seal.json to the receipt slot and any other
// file to the artifact slot, so a user can drag both at once.
["dragenter", "dragover"].forEach((ev) =>
  els.drop.addEventListener(ev, (e) => {
    e.preventDefault();
    els.drop.classList.add("dragover");
  })
);
["dragleave", "drop"].forEach((ev) =>
  els.drop.addEventListener(ev, (e) => {
    e.preventDefault();
    els.drop.classList.remove("dragover");
  })
);
els.drop.addEventListener("drop", (e) => {
  const files = Array.from(e.dataTransfer.files || []);
  for (const f of files) {
    if (f.name.endsWith(".seal.json") || f.name.endsWith(".json")) {
      setReceipt(f);
    } else {
      setArtifact(f);
    }
  }
});

els.verify.addEventListener("click", async () => {
  els.results.innerHTML = "";
  els.verify.disabled = true;
  try {
    const fileBytes = new Uint8Array(await artifactFile.arrayBuffer());
    const receiptText = await receiptFile.text();
    const out = verify_receipt(fileBytes, receiptText);
    render(out);
  } catch (e) {
    els.results.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`;
  } finally {
    refreshButton();
  }
});

// HMAC is reported with ok:false but a benign reason; show it as "unknown"
// (amber) rather than a failure (red), since it is unverifiable, not invalid.
function classify(layer) {
  if (layer.name === "hmac") return "unknown";
  return layer.ok ? "ok" : "bad";
}

function icon(kind) {
  if (kind === "ok") return "✔"; // heavy check
  if (kind === "unknown") return "—"; // em dash (not applicable)
  return "✖"; // heavy multiplication x
}

function render(out) {
  if (out.error) {
    els.results.innerHTML = `<div class="error">${escapeHtml(out.error)}</div>`;
    return;
  }

  const verdictClass = out.ok ? "ok" : "bad";
  const verdictText = out.ok
    ? "VERIFIED — all browser-checkable layers passed"
    : "NOT VERIFIED — at least one layer failed";

  const layersHtml = out.layers
    .map((l) => {
      const kind = classify(l);
      return `<div class="layer ${kind}">
        <div class="icon">${icon(kind)}</div>
        <div class="body">
          <div class="name">${escapeHtml(l.name)}</div>
          <div class="reason">${escapeHtml(l.reason)}</div>
        </div>
      </div>`;
    })
    .join("");

  els.results.innerHTML = `
    <div class="verdict ${verdictClass}">${verdictText}</div>
    ${layersHtml}
  `;
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
