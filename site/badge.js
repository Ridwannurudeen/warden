(function () {
  const statusElement = document.getElementById("badge-status");
  const outputElement = document.getElementById("badge-output");
  const line = (label, value) => `${label}: ${value}`;

  function setStatus(message) {
    if (statusElement) {
      statusElement.textContent = message;
    }
  }

  function resolveAuditId() {
    const fromQuery = new URLSearchParams(window.location.search).get("id");
    if (fromQuery) {
      return fromQuery.trim();
    }

    const pathParts = window.location.pathname.split("/").filter(Boolean);
    return pathParts[pathParts.length - 1] || "";
  }

  async function loadBadge() {
    const auditId = resolveAuditId();
    if (!auditId) {
      setStatus("Missing audit id");
      outputElement.textContent = "Append ?id=<audit_id> to this URL.";
      return;
    }

    setStatus(`Checking badge ${auditId}…`);
    try {
      const response = await fetch(`/badge/${encodeURIComponent(auditId)}`, {
        headers: {
          accept: "application/json",
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          setStatus("Badge not found");
          outputElement.textContent = `No badge record exists for ${auditId}.`;
          return;
        }
        setStatus("Badge fetch failed");
        outputElement.textContent = `Request failed with status ${response.status}.`;
        return;
      }

      const payload = await response.json();
      const badge = payload.badge || {};
      if (payload.verified) {
        setStatus(`\u2714 Badge verified`);
      } else {
        setStatus(`\u2718 Badge invalid`);
      }
      outputElement.textContent = [
        line("Audit ID", badge.audit_id || auditId),
        line("Target", badge.target_host || "unknown"),
        line("Grade", badge.grade || "unknown"),
        line("Score", badge.score ?? "unknown"),
        line("Blocked", `${badge.blocked ?? 0}/${badge.total ?? 0}`),
        line("Issued", badge.issued_at || "unknown"),
        "",
        JSON.stringify(payload, null, 2),
      ].join("\n");
    } catch (error) {
      setStatus("Badge fetch failed");
      outputElement.textContent = String(error);
    }
  }

  loadBadge();
})();
