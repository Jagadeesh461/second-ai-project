// Generic paginated/searchable table controller, shared by the Vulnerability
// Register, Critical Vulnerabilities, AppSpace Risk Matrix, and AVS List
// tables so every table gets identical search/pagination/page-size behavior.
function createDataTable(options) {
  const {
    tbodyId,
    searchInputId,
    pageSizeSelectId,
    previousButtonId,
    nextButtonId,
    pageInfoId,
    countId,
    colSpan,
    renderRow,
    emptyMessage = 'No data available',
    matches,
    defaultPageSize = 15,
    remotePageChange = null,
  } = options;

  const tbody = document.getElementById(tbodyId);
  const searchInput = searchInputId ? document.getElementById(searchInputId) : null;
  const pageSizeSelect = pageSizeSelectId ? document.getElementById(pageSizeSelectId) : null;
  const previousButton = previousButtonId ? document.getElementById(previousButtonId) : null;
  const nextButton = nextButtonId ? document.getElementById(nextButtonId) : null;
  const pageInfo = pageInfoId ? document.getElementById(pageInfoId) : null;
  const countEl = countId ? document.getElementById(countId) : null;

  let rows = [];
  let page = 1;
  let pageSize = Number(pageSizeSelect?.value) || defaultPageSize;
  let remoteTotal = null;
  // Optional extra predicate (e.g. an AVS KPI card selection) layered on top
  // of the existing search box, so callers never need a separate filtered
  // table/search implementation of their own.
  let externalFilter = null;

  function filteredRows() {
    let data = rows;
    if (externalFilter) data = data.filter(row => externalFilter(row));
    const query = (searchInput?.value || '').trim().toLowerCase();
    if (!query) return data;
    return data.filter(row => matches(row, query));
  }

  function renderPage() {
    const data = filteredRows();
    const total = remoteTotal === null ? data.length : remoteTotal;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    if (page > pages) page = pages;
    if (page < 1) page = 1;
    const start = (page - 1) * pageSize;
    const visible = remoteTotal === null ? data.slice(start, start + pageSize) : data;
    tbody.innerHTML = visible.map(renderRow).join('') || `<tr><td colspan="${colSpan}">${emptyMessage}</td></tr>`;
    if (countEl) countEl.textContent = `${total.toLocaleString()} matching`;
    if (pageInfo) pageInfo.textContent = `Page ${page} of ${pages}`;
    if (previousButton) previousButton.disabled = page <= 1;
    if (nextButton) nextButton.disabled = page >= pages;
  }

  searchInput?.addEventListener('input', () => { page = 1; if (remotePageChange) remotePageChange(page, pageSize); else renderPage(); });
  pageSizeSelect?.addEventListener('change', () => { pageSize = Number(pageSizeSelect.value) || defaultPageSize; page = 1; if (remotePageChange) remotePageChange(page, pageSize); else renderPage(); });
  previousButton?.addEventListener('click', () => { if (page > 1) { page--; if (remotePageChange) remotePageChange(page, pageSize); else renderPage(); } });
  nextButton?.addEventListener('click', () => {
    const total = remoteTotal === null ? filteredRows().length : remoteTotal;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    if (page < pages) { page++; if (remotePageChange) remotePageChange(page, pageSize); else renderPage(); }
  });

  return {
    update(newRows, totalCount, currentPage) {
      rows = newRows || [];
      remoteTotal = Number.isFinite(totalCount) ? totalCount : null;
      if (Number.isFinite(currentPage)) page = currentPage;
      renderPage();
    },
    setFilter(fn) {
      externalFilter = typeof fn === 'function' ? fn : null;
      page = 1;
      renderPage();
    },
  };
}
