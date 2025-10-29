(() => {
    const applyPangu = () => {
        if (!window.pangu) return;
        window.pangu.spacingPage();
    };

    if (window.document$ && typeof window.document$.subscribe === 'function') {
        window.document$.subscribe(applyPangu);
    } else {
        document.addEventListener('DOMContentLoaded', applyPangu);
    }
})();
