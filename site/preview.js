const scope = document.getElementById("scope");
const architecture = document.getElementById("architecture");
const rows = document.querySelectorAll(".app-list li");
const count = document.getElementById("preview-count");

function filterPreview() {
  let shown = 0;
  for (const row of rows) {
    const inScope = scope.value === "all" || row.dataset.scope === scope.value;
    const matchesArchitecture = architecture.value === "all" || row.dataset.type === architecture.value;
    row.hidden = !inScope || !matchesArchitecture;
    if (!row.hidden) shown++;
  }
  count.textContent = shown === 1 ? "1 example process shown." : `${shown} example processes shown.`;
}

scope.addEventListener("change", filterPreview);
architecture.addEventListener("change", filterPreview);
filterPreview();
