// TrustVault Frontend Utilities
document.addEventListener('DOMContentLoaded', function () {
    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Confirmation dialogs for dangerous actions
    document.querySelectorAll('[data-confirm]').forEach(function (element) {
        element.addEventListener('click', function (e) {
            var message = this.getAttribute('data-confirm') || "Are you sure you want to proceed?";
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });

    // Copy to clipboard helper for hashes
    document.querySelectorAll('.copy-hash-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var hash = this.getAttribute('data-hash');
            if (hash) {
                navigator.clipboard.writeText(hash).then(function () {
                    var originalText = btn.innerHTML;
                    btn.innerHTML = '<i class="bi bi-check2"></i> Copied!';
                    setTimeout(function () {
                        btn.innerHTML = originalText;
                    }, 2000);
                });
            }
        });
    });
});
